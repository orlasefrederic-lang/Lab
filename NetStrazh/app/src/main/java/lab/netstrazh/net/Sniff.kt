package lab.netstrazh.net

/**
 * Extracts the destination host name from the first bytes an app sends:
 * the SNI of a TLS ClientHello or the Host header of plain HTTP.
 */
object Sniff {
    /** Server name from a TLS ClientHello, or null if absent/incomplete. */
    fun tlsSni(b: ByteArray, len: Int): String? {
        if (len < 9 || B.u8(b, 0) != 0x16 || B.u8(b, 5) != 1) return null
        var p = 9 + 2 + 32 // record hdr + handshake hdr, client version, random
        if (p >= len) return null
        p += 1 + B.u8(b, p) // session id
        if (p + 2 > len) return null
        p += 2 + B.u16(b, p) // cipher suites
        if (p + 1 > len) return null
        p += 1 + B.u8(b, p) // compression methods
        if (p + 2 > len) return null
        val extEnd = minOf(len, p + 2 + B.u16(b, p))
        p += 2
        while (p + 4 <= extEnd) {
            val type = B.u16(b, p)
            val elen = B.u16(b, p + 2)
            p += 4
            if (type == 0) {
                if (p + 5 > len || B.u8(b, p + 2) != 0) return null
                val nlen = B.u16(b, p + 3)
                if (nlen == 0 || p + 5 + nlen > len) return null
                return String(b, p + 5, nlen, Charsets.US_ASCII).lowercase()
            }
            p += elen
        }
        return null
    }

    fun looksLikeTls(b: ByteArray, len: Int): Boolean = len >= 1 && B.u8(b, 0) == 0x16

    /** True when the whole first TLS record is available in [b]. */
    fun tlsRecordComplete(b: ByteArray, len: Int): Boolean = len >= 5 && len >= 5 + B.u16(b, 3)

    private val methods = arrayOf("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ")

    fun httpHost(b: ByteArray, len: Int): String? {
        val s = String(b, 0, minOf(len, 4096), Charsets.ISO_8859_1)
        if (methods.none { s.startsWith(it) }) return null
        val i = s.indexOf("\nhost:", ignoreCase = true)
        if (i < 0) return null
        var e = s.indexOf('\r', i + 6)
        if (e < 0) e = s.indexOf('\n', i + 6)
        if (e < 0) return null
        val h = s.substring(i + 6, e).trim()
        val host = if (h.startsWith("[")) h.substringBefore(']').removePrefix("[") else h.substringBefore(':')
        return host.lowercase().takeIf { it.isNotEmpty() }
    }

    fun looksLikeHttp(b: ByteArray, len: Int): Boolean {
        val s = String(b, 0, minOf(len, 8), Charsets.ISO_8859_1)
        return methods.any { s.startsWith(it) }
    }
}

/** Incrementally collects the start of an upstream stream until a host name can be extracted. */
class HostSniffer {
    private var buf = ByteArray(0)
    private var n = 0
    var done = false
        private set
    var host: String? = null
        private set
    /** The host came from TLS SNI (bound to the server by its certificate), not an HTTP Host header. */
    var tls = false
        private set

    /** Feeds the next chunk; returns true once sniffing is finished. */
    fun feed(data: ByteArray, off: Int, len: Int): Boolean {
        if (done) return true
        val take = minOf(len, LIMIT - n)
        if (buf.size < n + take) buf = buf.copyOf(maxOf(n + take, 2048))
        System.arraycopy(data, off, buf, n, take)
        n += take
        when {
            Sniff.looksLikeTls(buf, n) -> if (Sniff.tlsRecordComplete(buf, n) || n >= LIMIT) {
                host = Sniff.tlsSni(buf, n)
                tls = true
                finish()
            }
            Sniff.looksLikeHttp(buf, n) -> {
                host = Sniff.httpHost(buf, n)
                if (host != null || n >= LIMIT || String(buf, 0, n, Charsets.ISO_8859_1).contains("\r\n\r\n")) finish()
            }
            else -> finish()
        }
        return done
    }

    private fun finish() {
        done = true
        buf = ByteArray(0)
    }

    companion object {
        const val LIMIT = 16384
    }
}
