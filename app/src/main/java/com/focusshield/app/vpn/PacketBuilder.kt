package com.focusshield.app.vpn

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Builds raw IPv4 packets (UDP or TCP payloads) to write back into the tun interface. */
object PacketBuilder {

    fun buildUdpIpv4Packet(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLength = 8 + payload.size
        val totalLength = 20 + udpLength
        val packet = ByteArray(totalLength)
        val buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)

        writeIpv4Header(buf, totalLength, protocol = 17, srcIp = srcIp, dstIp = dstIp)

        val udpStart = 20
        buf.putShort(udpStart, srcPort.toShort())
        buf.putShort(udpStart + 2, dstPort.toShort())
        buf.putShort(udpStart + 4, udpLength.toShort())
        buf.putShort(udpStart + 6, 0)
        System.arraycopy(payload, 0, packet, udpStart + 8, payload.size)

        val udpChecksum = l4Checksum(srcIp, dstIp, protocol = 17, packet = packet, l4Start = udpStart, l4Length = udpLength)
        buf.putShort(udpStart + 6, udpChecksum.toShort())

        finalizeIpChecksum(packet)
        return packet
    }

    /**
     * Builds a TCP segment. `flags` is the raw 6-bit TCP flags byte
     * (use the SYN/ACK/FIN/RST/PSH constants in TcpFlags).
     */
    fun buildTcpIpv4Packet(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        seq: Long, ack: Long,
        flags: Int, window: Int,
        payload: ByteArray
    ): ByteArray {
        val tcpHeaderLength = 20
        val tcpLength = tcpHeaderLength + payload.size
        val totalLength = 20 + tcpLength
        val packet = ByteArray(totalLength)
        val buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)

        writeIpv4Header(buf, totalLength, protocol = 6, srcIp = srcIp, dstIp = dstIp)

        val tcpStart = 20
        buf.putShort(tcpStart, srcPort.toShort())
        buf.putShort(tcpStart + 2, dstPort.toShort())
        buf.putInt(tcpStart + 4, seq.toInt())
        buf.putInt(tcpStart + 8, ack.toInt())
        packet[tcpStart + 12] = ((tcpHeaderLength / 4) shl 4).toByte() // data offset, no options
        packet[tcpStart + 13] = flags.toByte()
        buf.putShort(tcpStart + 14, window.toShort())
        buf.putShort(tcpStart + 16, 0) // checksum placeholder
        buf.putShort(tcpStart + 18, 0) // urgent pointer
        System.arraycopy(payload, 0, packet, tcpStart + tcpHeaderLength, payload.size)

        val tcpChecksum = l4Checksum(srcIp, dstIp, protocol = 6, packet = packet, l4Start = tcpStart, l4Length = tcpLength)
        buf.putShort(tcpStart + 16, tcpChecksum.toShort())

        finalizeIpChecksum(packet)
        return packet
    }

    private fun writeIpv4Header(buf: ByteBuffer, totalLength: Int, protocol: Int, srcIp: ByteArray, dstIp: ByteArray) {
        buf.put(0, 0x45.toByte())
        buf.put(1, 0)
        buf.putShort(2, totalLength.toShort())
        buf.putShort(4, 0)
        buf.putShort(6, 0x4000.toShort()) // DF flag set, no fragmentation
        buf.put(8, 64.toByte())
        buf.put(9, protocol.toByte())
        buf.putShort(10, 0) // checksum placeholder, filled in by finalizeIpChecksum
        System.arraycopy(srcIp, 0, buf.array(), 12, 4)
        System.arraycopy(dstIp, 0, buf.array(), 16, 4)
    }

    private fun finalizeIpChecksum(packet: ByteArray) {
        val checksum = checksum16(packet, 0, 20)
        packet[10] = (checksum shr 8).toByte()
        packet[11] = (checksum and 0xFF).toByte()
    }

    /** RFC 793/768 pseudo-header checksum, shared by UDP and TCP. */
    private fun l4Checksum(srcIp: ByteArray, dstIp: ByteArray, protocol: Int, packet: ByteArray, l4Start: Int, l4Length: Int): Int {
        var sum = 0
        sum += word(srcIp, 0); sum += word(srcIp, 2)
        sum += word(dstIp, 0); sum += word(dstIp, 2)
        sum += protocol
        sum += l4Length

        var i = l4Start
        val end = l4Start + l4Length
        while (i < end - 1) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }
        if ((l4Length % 2) == 1) {
            sum += (packet[end - 1].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val result = sum.inv() and 0xFFFF
        return if (result == 0) 0xFFFF else result
    }

    private fun checksum16(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (length % 2 == 1) sum += (data[offset + length - 1].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    private fun word(ip: ByteArray, offset: Int): Int =
        ((ip[offset].toInt() and 0xFF) shl 8) or (ip[offset + 1].toInt() and 0xFF)
}

object TcpFlags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}
