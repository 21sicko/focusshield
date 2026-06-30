package com.focusshield.app.vpn

/**
 * Minimal DNS wire-format helpers — just enough to read the queried
 * hostname out of a question section and synthesize a same-question
 * NXDOMAIN response. Not a general-purpose DNS library.
 *
 * Wire format reference (RFC 1035 section 4.1):
 *   Header: 12 bytes (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
 *   Question: sequence of length-prefixed labels ending in a 0 byte,
 *             followed by QTYPE (2 bytes) and QCLASS (2 bytes)
 */
object DnsMessage {

    fun extractQuestionName(message: ByteArray): String? {
        if (message.size < 12) return null
        val qdCount = ((message[4].toInt() and 0xFF) shl 8) or (message[5].toInt() and 0xFF)
        if (qdCount < 1) return null

        var pos = 12
        val labels = mutableListOf<String>()

        while (pos < message.size) {
            val len = message[pos].toInt() and 0xFF
            if (len == 0) {
                pos += 1
                break
            }
            // Compression pointers shouldn't appear in the question section
            // of a query, but bail out safely if one shows up.
            if (len and 0xC0 == 0xC0) return null
            if (pos + 1 + len > message.size) return null

            val label = String(message, pos + 1, len, Charsets.US_ASCII)
            labels.add(label)
            pos += 1 + len
        }

        if (labels.isEmpty()) return null
        return labels.joinToString(".")
    }

    /**
     * Builds a response with the same ID/question section as the original
     * query, RCODE = 3 (NXDOMAIN), QR=1 (response), ANCOUNT=0. This is
     * the standard way DNS-level blockers signal "this domain doesn't
     * resolve" without needing a fake IP / block page.
     */
    fun buildNxDomainResponse(query: ByteArray): ByteArray {
        val qdCount = ((query[4].toInt() and 0xFF) shl 8) or (query[5].toInt() and 0xFF)
        var pos = 12
        var labelsSeen = 0
        while (pos < query.size && labelsSeen < qdCount) {
            val len = query[pos].toInt() and 0xFF
            if (len == 0) {
                pos += 1
                labelsSeen += 1
                continue
            }
            pos += 1 + len
        }
        pos += 4 // QTYPE + QCLASS

        val response = query.copyOf(pos)

        // Flags byte 1 (offset 2): QR=1, Opcode copied, AA=0, TC=0, RD copied
        val originalFlags1 = query[2].toInt() and 0xFF
        response[2] = (0x80 or (originalFlags1 and 0x01)).toByte() // QR=1, keep RD bit

        // Flags byte 2 (offset 3): RA=0, Z=0, RCODE=3 (NXDOMAIN)
        response[3] = 0x03

        // ANCOUNT / NSCOUNT / ARCOUNT = 0
        response[6] = 0; response[7] = 0
        response[8] = 0; response[9] = 0
        response[10] = 0; response[11] = 0

        return response
    }
}
