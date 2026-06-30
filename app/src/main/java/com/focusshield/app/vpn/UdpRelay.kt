package com.focusshield.app.vpn

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Generic UDP NAT relay for everything that isn't a DNS query (port 53,
 * which DnsPacketProcessor already handles). Each unique 4-tuple
 * (srcIp:srcPort -> dstIp:dstPort) gets its own real, protected
 * DatagramSocket. Replies are read on a background thread per session and
 * written back into the tun as new packets addressed back to the
 * original device source.
 *
 * Sessions are evicted after IDLE_TIMEOUT_MS of inactivity so this doesn't
 * leak sockets/threads over a long-running VPN session.
 */
class UdpRelay(
    private val protectSocket: (DatagramSocket) -> Boolean,
    private val writeToTun: (ByteArray) -> Unit
) {
    private data class SessionKey(val srcIp: String, val srcPort: Int, val dstIp: String, val dstPort: Int)

    private class Session(val socket: DatagramSocket) {
        @Volatile var lastActive: Long = System.currentTimeMillis()
    }

    private val sessions = ConcurrentHashMap<SessionKey, Session>()

    fun handle(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, payload: ByteArray) {
        val srcIpStr = ipToString(srcIp)
        val dstIpStr = ipToString(dstIp)
        val key = SessionKey(srcIpStr, srcPort, dstIpStr, dstPort)

        val session = sessions.getOrPut(key) {
            val socket = DatagramSocket()
            protectSocket(socket)
            val newSession = Session(socket)
            startReaderThread(key, newSession, srcIp, dstIp)
            newSession
        }

        session.lastActive = System.currentTimeMillis()
        try {
            val dest = InetSocketAddress(InetAddress.getByName(dstIpStr), dstPort)
            session.socket.send(DatagramPacket(payload, payload.size, dest))
        } catch (e: Exception) {
            sessions.remove(key)
            session.socket.close()
        }
    }

    private fun startReaderThread(key: SessionKey, session: Session, deviceIp: ByteArray, destIp: ByteArray) {
        Thread {
            val buf = ByteArray(32767)
            try {
                while (!session.socket.isClosed) {
                    session.socket.soTimeout = IDLE_TIMEOUT_MS.toInt()
                    val packet = DatagramPacket(buf, buf.size)
                    try {
                        session.socket.receive(packet)
                    } catch (timeout: java.net.SocketTimeoutException) {
                        if (System.currentTimeMillis() - session.lastActive > IDLE_TIMEOUT_MS) break
                        continue
                    }
                    session.lastActive = System.currentTimeMillis()
                    val reply = packet.data.copyOf(packet.length)
                    val ipPacket = PacketBuilder.buildUdpIpv4Packet(
                        srcIp = destIp, srcPort = key.dstPort,
                        dstIp = deviceIp, dstPort = key.srcPort,
                        payload = reply
                    )
                    writeToTun(ipPacket)
                }
            } catch (e: Exception) {
                // session ended
            } finally {
                sessions.remove(key)
                session.socket.close()
            }
        }.apply { isDaemon = true }.start()
    }

    fun closeAll() {
        sessions.values.forEach { it.socket.close() }
        sessions.clear()
    }

    private fun ipToString(ip: ByteArray): String =
        "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}.${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"

    companion object {
        private const val IDLE_TIMEOUT_MS = 60_000L
    }
}
