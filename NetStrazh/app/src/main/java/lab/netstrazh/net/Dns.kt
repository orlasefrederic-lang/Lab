package lab.netstrazh.net

import java.net.InetAddress

class DnsMessage(
    val id: Int,
    val isResponse: Boolean,
    val rcode: Int,
    val qname: String?,
    val qtype: Int,
    /** IP addresses from A/AAAA answers, in textual form. */
    val addresses: List<String>,
    val cnames: List<String>,
)

/** Minimal DNS wire-format parser: question name/type and A/AAAA/CNAME answers. */
object Dns {
    const val TYPE_A = 1
    const val TYPE_CNAME = 5
    const val TYPE_AAAA = 28

    fun parse(b: ByteArray, off: Int, len: Int): DnsMessage? {
        if (len < 12 || off < 0 || off + len > b.size) return null
        val end = off + len
        val id = B.u16(b, off)
        val flags = B.u16(b, off + 2)
        val qd = B.u16(b, off + 4)
        val an = B.u16(b, off + 6)
        var p = off + 12
        var qname: String? = null
        var qtype = 0
        for (i in 0 until qd) {
            val n = readName(b, off, end, p) ?: return null
            if (n.second + 4 > end) return null
            if (i == 0) {
                qname = n.first
                qtype = B.u16(b, n.second)
            }
            p = n.second + 4
        }
        val addrs = ArrayList<String>()
        val cnames = ArrayList<String>()
        for (i in 0 until an) {
            val n = readName(b, off, end, p) ?: break
            p = n.second
            if (p + 10 > end) break
            val type = B.u16(b, p)
            val rdlen = B.u16(b, p + 8)
            p += 10
            if (p + rdlen > end) break
            when {
                type == TYPE_A && rdlen == 4 ->
                    addrs.add(InetAddress.getByAddress(b.copyOfRange(p, p + 4)).hostAddress ?: "")
                type == TYPE_AAAA && rdlen == 16 ->
                    addrs.add(InetAddress.getByAddress(b.copyOfRange(p, p + 16)).hostAddress ?: "")
                type == TYPE_CNAME -> readName(b, off, end, p)?.let { cnames.add(it.first) }
            }
            p += rdlen
        }
        return DnsMessage(id, flags and 0x8000 != 0, flags and 0x0F, qname, qtype, addrs, cnames)
    }

    /** Returns the decoded name and the offset just after the name at [start]. */
    private fun readName(b: ByteArray, base: Int, end: Int, start: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var p = start
        var next = -1
        var hops = 0
        while (true) {
            if (p >= end) return null
            val l = B.u8(b, p)
            if (l == 0) {
                if (next < 0) next = p + 1
                break
            }
            if (l and 0xC0 == 0xC0) {
                if (p + 1 >= end) return null
                if (next < 0) next = p + 2
                p = base + (((l and 0x3F) shl 8) or B.u8(b, p + 1))
                if (++hops > 32) return null
                continue
            }
            if (l and 0xC0 != 0) return null
            if (p + 1 + l > end) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 1..l) {
                val c = B.u8(b, p + i)
                sb.append(if (c in 33..126) c.toChar().lowercaseChar() else '?')
            }
            p += 1 + l
            if (sb.length > 255) return null
        }
        return Pair(sb.toString(), next)
    }

    /** Skips a (possibly compressed) name at [p]; returns the offset after it or -1. */
    private fun skipName(b: ByteArray, p0: Int, end: Int): Int {
        var p = p0
        while (p < end) {
            val l = B.u8(b, p)
            if (l == 0) return p + 1
            if (l and 0xC0 == 0xC0) return if (p + 2 <= end) p + 2 else -1
            if (l and 0xC0 != 0) return -1
            p += 1 + l
        }
        return -1
    }

    /**
     * Largest UDP response the asking resolver accepts: the EDNS(0) UDP payload size from the OPT
     * record of the query, or 512 bytes without one (RFC 1035 / RFC 6891).
     */
    fun udpLimit(q: ByteArray, off: Int, len: Int): Int {
        if (len < 12) return 512
        val end = off + len
        val counts = IntArray(4) { B.u16(q, off + 4 + it * 2) }
        var p = off + 12
        for (i in 0 until counts[0]) {
            p = skipName(q, p, end)
            if (p < 0 || p + 4 > end) return 512
            p += 4
        }
        for (sec in 1..3) for (i in 0 until counts[sec]) {
            p = skipName(q, p, end)
            if (p < 0 || p + 10 > end) return 512
            val type = B.u16(q, p)
            if (type == 41) return maxOf(512, B.u16(q, p + 2))
            p += 10 + B.u16(q, p + 8)
        }
        return 512
    }

    /** Header + question of [r] with the TC bit set and no records: tells the stub to retry over TCP. */
    fun truncated(r: ByteArray, len: Int): ByteArray {
        if (len < 12) return r.copyOf(len)
        var p = 12
        val qd = B.u16(r, 4)
        for (i in 0 until qd) {
            val e = skipName(r, p, len)
            if (e < 0 || e + 4 > len) { p = 12; break }
            p = e + 4
        }
        val out = r.copyOf(p)
        out[2] = (out[2].toInt() or 0x02).toByte() // TC
        if (p == 12) B.put16(out, 4, 0)
        B.put16(out, 6, 0)
        B.put16(out, 8, 0)
        B.put16(out, 10, 0)
        return out
    }

    fun typeName(t: Int): String = when (t) {
        TYPE_A -> "A"
        TYPE_AAAA -> "AAAA"
        TYPE_CNAME -> "CNAME"
        12 -> "PTR"
        15 -> "MX"
        16 -> "TXT"
        33 -> "SRV"
        64 -> "SVCB"
        65 -> "HTTPS"
        else -> "#$t"
    }
}
