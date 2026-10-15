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
