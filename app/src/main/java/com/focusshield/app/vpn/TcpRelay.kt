package com.focusshield.app.vpn

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore
import kotlin.random.Random

class TcpRelay(
    private val protectSocket: (Socket) -> Boolean,
    private val writeToTun: (ByteArray) -> Unit
) {
    private data class SessionKey(val srcPort: Int, val dstIp: String, val dstPort: Int)
    private enum class State { SYN_RECEIVED, ESTABLISHED, CLOSING, CLOSED }

    // Caps how many real sockets can be mid-connect at once. Without this,
    // a burst of traffic (many apps at once) opens hundreds of raw threads
    // simultaneously, which can starve/race the VpnService.protect() call
    // and cause sockets to silently stay inside the tunnel instead of
    // being exempted from it - producing exactly the "everything times
    // out" symptom.
    private val connectionLimiter = Semaphore(150)

    private inner class Session(
        val deviceIp: ByteArray, val destIp: ByteArray,
        val srcPort: Int, val dstPort: Int,
        val clientIsn: Long
    ) {
        val ourIsn: Long = Random.nextLong(0, 0xFFFFFFFFL)
        var bytesFromClient: Long = 0
        var bytesToClient: Long = 0
        @Volatile var state: State = State.SYN_RECEIVED
        var socket: Socket? = null
        var output: OutputStream? = null
        @Volatile var lastActive: Long = System.currentTimeMillis()

        fun ackToSend() = clientIsn + 1 + bytesFromClient
        fun seqToSend() = ourIsn + 1 + bytesToClient
    }

    private val sessions = ConcurrentHashMap<SessionKey, Session>()

    fun handle(packet: ByteArray, length: Int) {
        if (length < 40) return
        val ihl = (packet[0].toInt() and 0x0F) * 4
        val tcpStart = ihl
        if (tcpStart + 20 > length) return

        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)
        val srcPort = u16(packet, tcpStart)
        val dstPort = u16(packet, tcpStart + 2)
        val seq = u32(packet, tcpStart + 4)
        val dataOffset = ((packet[tcpStart + 12].toInt() and 0xFF) shr 4) * 4
        val flags = packet[tcpStart + 13].toInt() and 0xFF
        val payloadStart = tcpStart + dataOffset
        val payload = if (payloadStart < length) packet.copyOfRange(payloadStart, length) else ByteArray(0)

        val dstIpStr = ipToString(dstIp)
        val key = SessionKey(srcPort, dstIpStr, dstPort)

        when {
            flags and TcpFlags.SYN != 0 && flags and TcpFlags.ACK == 0 -> {
                if (sessions.containsKey(key)) {
                    // Duplicate/retransmitted SYN for an already-pending session - ignore it
                    // instead of tearing down and reopening, which was likely amplifying the
                    // connection storm under load.
                    return
                }
                DebugLog.log("SYN new connection -> $dstIpStr:$dstPort (srcPort=$srcPort)")
                val session = Session(srcIp, dstIp, srcPort, dstPort, seq)
                sessions[key] = session
                openRealSocket(key, session, dstIpStr, dstPort)
            }
            flags and TcpFlags.RST != 0 -> {
                sessions.remove(key)?.let { it.socket?.close() }
            }
            else -> {
                val session = sessions[key] ?: return
                session.lastActive = System.currentTimeMillis()

                if (flags and TcpFlags.FIN != 0) {
                    session.bytesFromClient += 1
                    try { session.output?.flush(); session.socket?.shutdownOutput() } catch (e: Exception) {}
                    sendSegment(session, TcpFlags.ACK, ByteArray(0))
                    session.state = State.CLOSING
                } else if (payload.isNotEmpty() && session.state != State.CLOSED) {
                    try {
                        session.output?.write(payload)
                        session.bytesFromClient += payload.size
                        sendSegment(session, TcpFlags.ACK, ByteArray(0))
                    } catch (e: Exception) {
                        sendSegment(session, TcpFlags.RST or TcpFlags.ACK, ByteArray(0))
                        sessions.remove(key)?.socket?.close()
                    }
                }
            }
        }
    }

    private fun openRealSocket(key: SessionKey, session: Session, dstIpStr: String, dstPort: Int) {
        Thread {
            val gotPermit = connectionLimiter.tryAcquire(8, java.util.concurrent.TimeUnit.SECONDS)
            if (!gotPermit) {
                DebugLog.log("REJECTED $dstIpStr:$dstPort - too many concurrent connections")
                sendSegment(session, TcpFlags.RST or TcpFlags.ACK, ByteArray(0))
                sessions.remove(key)
                return@Thread
            }
            try {
                val socket = Socket()
                // Force the underlying native fd to exist before protect() -
                // an unbound Socket may not have one yet on some Android
                // versions, which makes protect() silently no-op.
                socket.bind(InetSocketAddress(0))
                val protected = protectSocket(socket)
                DebugLog.log("protect() returned $protected for $dstIpStr:$dstPort")
                if (!protected) {
                    DebugLog.log("PROTECT FAILED for $dstIpStr:$dstPort - aborting connection")
                    sendSegment(session, TcpFlags.RST or TcpFlags.ACK, ByteArray(0))
                    sessions.remove(key)
                    socket.close()
                    return@Thread
                }

                DebugLog.log("opening real socket to $dstIpStr:$dstPort")
                socket.connect(InetSocketAddress(dstIpStr, dstPort), 8_000)
                DebugLog.log("connected to $dstIpStr:$dstPort, local=${socket.localAddress}")
                session.socket = socket
                session.output = socket.outputStream

                sendSegment(session, TcpFlags.SYN or TcpFlags.ACK, ByteArray(0))
                session.state = State.ESTABLISHED

                startUpstreamReader(key, session, socket.inputStream)
            } catch (e: Exception) {
                DebugLog.log("FAILED to connect to $dstIpStr:$dstPort - ${e.message}")
                sendSegment(session, TcpFlags.RST or TcpFlags.ACK, ByteArray(0))
                sessions.remove(key)
            } finally {
                connectionLimiter.release()
            }
        }.apply { isDaemon = true }.start()
    }

    private fun startUpstreamReader(key: SessionKey, session: Session, input: InputStream) {
        Thread {
            val buf = ByteArray(4096)
            try {
                while (session.state != State.CLOSED) {
                    val n = input.read(buf)
                    if (n < 0) {
                        sendSegment(session, TcpFlags.FIN or TcpFlags.ACK, ByteArray(0))
                        session.bytesToClient += 1
                        break
                    }
                    if (n > 0) {
                        val chunk = buf.copyOf(n)
                        sendSegment(session, TcpFlags.ACK or TcpFlags.PSH, chunk)
                        session.bytesToClient += n
                    }
                    session.lastActive = System.currentTimeMillis()
                }
            } catch (e: Exception) {
            } finally {
                sessions.remove(key)
                try { session.socket?.close() } catch (e: Exception) {}
            }
        }.apply { isDaemon = true }.start()
    }

    private fun sendSegment(session: Session, flags: Int, payload: ByteArray) {
        val packet = PacketBuilder.buildTcpIpv4Packet(
            srcIp = session.destIp, srcPort = session.dstPort,
            dstIp = session.deviceIp, dstPort = session.srcPort,
            seq = session.seqToSend(), ack = session.ackToSend(),
            flags = flags, window = 65535,
            payload = payload
        )
        writeToTun(packet)
    }

    fun closeAll() {
        sessions.values.forEach { it.socket?.close() }
        sessions.clear()
    }

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun u32(data: ByteArray, offset: Int): Long {
        return ((data[offset].toLong() and 0xFF) shl 24) or
               ((data[offset + 1].toLong() and 0xFF) shl 16) or
               ((data[offset + 2].toLong() and 0xFF) shl 8) or
               (data[offset + 3].toLong() and 0xFF)
    }

    private fun ipToString(ip: ByteArray): String =
        "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}.${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
}
