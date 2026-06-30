package com.focusshield.app.vpn

import com.focusshield.app.data.BlocklistRepository
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Parses raw IPv4 packets coming out of the tun interface, looks for UDP
 * port-53 DNS queries, checks the queried hostname against the blocklist,
 * and either:
 *   - forwards allowed queries to a real upstream resolver and relays the
 *     response back into the tun interface, or
 *   - synthesizes an NXDOMAIN response directly for blocked queries
 *     (no network round-trip needed for those).
 *
 * Scope / honest limitations:
 *   - Handles IPv4 + UDP DNS only. IPv6 and DNS-over-TCP (used as a
 *     fallback for responses >512 bytes) are not implemented here.
 *   - DNS-over-HTTPS/TLS (DoH/DoT) bypasses this entirely since it's not
 *     plain port-53 UDP traffic — that's a structural limitation of any
 *     DNS-based blocker, not something fixable by better parsing. Closing
 *     that gap requires SNI/IP-based filtering of known DoH provider
 *     endpoints, which is a separate, more invasive layer.
 *   - This only ever sees traffic because FilterVpnService routes ONLY
 *     the virtual DNS server address through the tun (not all traffic),
 *     so it never has to relay general app traffic — much simpler and
 *     more reliable than building a full NAT layer.
 */
class DnsPacketProcessor(
    private val blocklist: BlocklistRepository,
    private val protectSocket: (DatagramSocket) -> Boolean,
    private val upstreamDns: InetAddress
) {

    /**
     * Processes one raw IP packet read from the tun fd.
     * Returns the response packet bytes to write back into the tun, or
     * null if there's nothing to write back (non-UDP/53 traffic, parse
     * failure, etc).
     */
    fun process(packet: ByteArray, length: Int): ByteArray? {
        if (length < 20) return null // smaller than a minimal IPv4 header

        val buf = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN)

        val versionAndIhl = buf.get(0).toInt() and 0xFF
        val version = versionAndIhl shr 4
        if (version != 4) return null // IPv6 not handled

        val ihl = (versionAndIhl and 0x0F) * 4
        val protocol = buf.get(9).toInt() and 0xFF
        if (protocol != 17) return null // not UDP

        val srcIp = ByteArray(4).also { System.arraycopy(packet, 12, it, 0, 4) }
        val dstIp = ByteArray(4).also { System.arraycopy(packet, 16, it, 0, 4) }

        val udpStart = ihl
        if (length < udpStart + 8) return null

        val srcPort = ((packet[udpStart].toInt() and 0xFF) shl 8) or (packet[udpStart + 1].toInt() and 0xFF)
        val dstPort = ((packet[udpStart + 2].toInt() and 0xFF) shl 8) or (packet[udpStart + 3].toInt() and 0xFF)
        if (dstPort != 53) return null // only interested in DNS queries

        val udpLength = ((packet[udpStart + 4].toInt() and 0xFF) shl 8) or (packet[udpStart + 5].toInt() and 0xFF)
        val dnsStart = udpStart + 8
        val dnsLength = udpLength - 8
        if (dnsLength <= 0 || dnsStart + dnsLength > length) return null

        val dnsPayload = ByteArray(dnsLength)
        System.arraycopy(packet, dnsStart, dnsPayload, 0, dnsLength)

        val queryName = DnsMessage.extractQuestionName(dnsPayload) ?: return null

        val responseDnsPayload: ByteArray = if (blocklist.isBlocked(queryName)) {
            DnsMessage.buildNxDomainResponse(dnsPayload)
        } else {
            forwardToUpstream(dnsPayload) ?: return null
        }

        return buildIpv4UdpPacket(
            srcIp = dstIp, srcPort = dstPort,       // swapped: response comes "from" the DNS server
            dstIp = srcIp, dstPort = srcPort,       // back "to" the original requesting app
            payload = responseDnsPayload
        )
    }

    private fun forwardToUpstream(query: ByteArray): ByteArray? {
        return try {
            DatagramSocket().use { socket ->
                protectSocket(socket) // VpnService.protect() — keeps this socket OUTSIDE the tun
                socket.soTimeout = 4000
                val request = java.net.DatagramPacket(query, query.size, InetSocketAddress(upstreamDns, 53))
                socket.send(request)

                val responseBuf = ByteArray(1500)
                val responsePacket = java.net.DatagramPacket(responseBuf, responseBuf.size)
                socket.receive(responsePacket)

                responseBuf.copyOf(responsePacket.length)
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun buildIpv4UdpPacket(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLength = 8 + payload.size
        val totalLength = 20 + udpLength
        val packet = ByteArray(totalLength)
        val buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)

        // --- IPv4 header ---
        buf.put(0, (0x45).toByte())       // version 4, IHL 5 (no options)
        buf.put(1, 0)                      // DSCP/ECN
        buf.putShort(2, totalLength.toShort())
        buf.putShort(4, 0)                 // identification
        buf.putShort(6, 0)                 // flags/fragment offset
        buf.put(8, 64.toByte())            // TTL
        buf.put(9, 17.toByte())            // protocol = UDP
        buf.putShort(10, 0)                // checksum placeholder
        System.arraycopy(srcIp, 0, packet, 12, 4)
        System.arraycopy(dstIp, 0, packet, 16, 4)

        val ipChecksum = checksum(packet, 0, 20)
        buf.putShort(10, ipChecksum.toShort())

        // --- UDP header ---
        val udpStart = 20
        buf.putShort(udpStart, srcPort.toShort())
        buf.putShort(udpStart + 2, dstPort.toShort())
        buf.putShort(udpStart + 4, udpLength.toShort())
        buf.putShort(udpStart + 6, 0) // checksum optional for IPv4 UDP; left as 0 (valid)

        System.arraycopy(payload, 0, packet, udpStart + 8, payload.size)

        return packet
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (length % 2 == 1) {
            sum += (data[offset + length - 1].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }
}
