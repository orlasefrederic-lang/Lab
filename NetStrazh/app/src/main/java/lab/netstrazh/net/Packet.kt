package lab.netstrazh.net

/** Low-level helpers for big-endian fields. */
object B {
    fun u8(b: ByteArray, o: Int): Int = b[o].toInt() and 0xFF
    fun u16(b: ByteArray, o: Int): Int = (u8(b, o) shl 8) or u8(b, o + 1)
    fun u32(b: ByteArray, o: Int): Long = (u16(b, o).toLong() shl 16) or u16(b, o + 2).toLong()
    fun i64(b: ByteArray, o: Int): Long = (u32(b, o) shl 32) or u32(b, o + 4)

    fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v ushr 8).toByte()
        b[o + 1] = v.toByte()
    }

    fun put32(b: ByteArray, o: Int, v: Long) {
        put16(b, o, (v ushr 16).toInt() and 0xFFFF)
        put16(b, o + 2, v.toInt() and 0xFFFF)
    }

    fun eq(a: ByteArray, ao: Int, b: ByteArray, bo: Int, n: Int): Boolean {
        for (i in 0 until n) if (a[ao + i] != b[bo + i]) return false
        return true
    }
}

/** Internet checksum (RFC 1071). */
object Checksum {
    fun add(b: ByteArray, off: Int, len: Int, acc: Long = 0L): Long {
        var s = acc
        var i = off
        val last = off + len - 1
        while (i < last) {
            s += (((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i == last) s += ((b[i].toInt() and 0xFF) shl 8).toLong()
        return s
    }

    fun finish(acc: Long): Int {
        var s = acc
        while (s ushr 16 != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return (s.inv() and 0xFFFF).toInt()
    }
}

const val PROTO_TCP = 6
const val PROTO_UDP = 17

const val TCP_FIN = 0x01
const val TCP_SYN = 0x02
const val TCP_RST = 0x04
const val TCP_ACK = 0x10

/**
 * A parsed view over an IPv4/IPv6 packet stored in [buf]. Parsing does not copy;
 * the setters rewrite the packet in place and [fixChecksums] recomputes checksums.
 */
class Ip {
    var buf: ByteArray = ByteArray(0)
        private set
    var len = 0
        private set
    var v6 = false
        private set
    /** Offset of the transport header (= length of IP header incl. extensions). */
    var hdrLen = 0
        private set
    var proto = 0
        private set
    var srcOff = 0
        private set
    var dstOff = 0
        private set
    var addrLen = 0
        private set

    val l4Len: Int get() = len - hdrLen

    fun parse(b: ByteArray, n: Int): Boolean {
        buf = b
        if (n < 20) return false
        when (B.u8(b, 0) ushr 4) {
            4 -> {
                val ihl = (B.u8(b, 0) and 0x0F) * 4
                if (ihl < 20 || n < ihl) return false
                val total = B.u16(b, 2)
                if (total < ihl || total > n) return false
                // Fragments (MF set or non-zero offset) are not supported.
                if ((B.u16(b, 6) and 0x3FFF) != 0) return false
                v6 = false
                len = total
                proto = B.u8(b, 9)
                hdrLen = ihl
                srcOff = 12
                dstOff = 16
                addrLen = 4
                return true
            }
            6 -> {
                if (n < 40) return false
                val total = 40 + B.u16(b, 4)
                if (total > n) return false
                var nh = B.u8(b, 6)
                var off = 40
                while (nh == 0 || nh == 43 || nh == 60) { // hop-by-hop, routing, destination options
                    if (off + 8 > total) return false
                    val next = B.u8(b, off)
                    off += (B.u8(b, off + 1) + 1) * 8
                    nh = next
                }
                if (off > total) return false
                v6 = true
                len = total
                proto = nh
                hdrLen = off
                srcOff = 8
                dstOff = 24
                addrLen = 16
                return true
            }
        }
        return false
    }

    // --- addresses and ports ---
    fun srcIs(a: ByteArray): Boolean = a.size == addrLen && B.eq(buf, srcOff, a, 0, addrLen)
    fun dstIs(a: ByteArray): Boolean = a.size == addrLen && B.eq(buf, dstOff, a, 0, addrLen)
    fun srcAddr(): ByteArray = buf.copyOfRange(srcOff, srcOff + addrLen)
    fun dstAddr(): ByteArray = buf.copyOfRange(dstOff, dstOff + addrLen)
    fun setSrc(a: ByteArray) = System.arraycopy(a, 0, buf, srcOff, addrLen)
    fun setDst(a: ByteArray) = System.arraycopy(a, 0, buf, dstOff, addrLen)

    val srcPort: Int get() = B.u16(buf, hdrLen)
    val dstPort: Int get() = B.u16(buf, hdrLen + 2)
    fun setSrcPort(p: Int) = B.put16(buf, hdrLen, p)
    fun setDstPort(p: Int) = B.put16(buf, hdrLen + 2, p)

    // --- TCP ---
    val tcpSeq: Long get() = B.u32(buf, hdrLen + 4)
    val tcpAck: Long get() = B.u32(buf, hdrLen + 8)
    val tcpFlags: Int get() = B.u8(buf, hdrLen + 13)
    val tcpDataLen: Int get() = l4Len - (B.u8(buf, hdrLen + 12) ushr 4) * 4

    // --- UDP ---
    val udpPayloadOff: Int get() = hdrLen + 8
    val udpPayloadLen: Int get() = minOf(B.u16(buf, hdrLen + 4), l4Len) - 8

    fun fixChecksums() {
        if (!v6) {
            B.put16(buf, 10, 0)
            B.put16(buf, 10, Checksum.finish(Checksum.add(buf, 0, hdrLen)))
        }
        val l4 = l4Len
        val csOff = when (proto) {
            PROTO_TCP -> hdrLen + 16
            PROTO_UDP -> hdrLen + 6
            else -> return
        }
        // IPv4 UDP with a zero checksum means "no checksum": keep it that way.
        if (proto == PROTO_UDP && !v6 && B.u16(buf, csOff) == 0) return
        B.put16(buf, csOff, 0)
        var acc = Checksum.add(buf, srcOff, addrLen)
        acc = Checksum.add(buf, dstOff, addrLen, acc)
        acc += (proto + l4).toLong()
        acc = Checksum.add(buf, hdrLen, l4, acc)
        var cs = Checksum.finish(acc)
        if (proto == PROTO_UDP && cs == 0) cs = 0xFFFF
        B.put16(buf, csOff, cs)
    }

    /** Verifies transport checksum (used by tests). */
    fun l4ChecksumOk(): Boolean {
        var acc = Checksum.add(buf, srcOff, addrLen)
        acc = Checksum.add(buf, dstOff, addrLen, acc)
        acc += (proto + l4Len).toLong()
        acc = Checksum.add(buf, hdrLen, l4Len, acc)
        return Checksum.finish(acc) == 0
    }

    fun ipChecksumOk(): Boolean = v6 || Checksum.finish(Checksum.add(buf, 0, hdrLen)) == 0
}

/** Builds packets that we inject into the TUN interface. */
object PacketBuilder {
    @Volatile private var ipId = 1

    private fun ipHeader(b: ByteArray, v6: Boolean, proto: Int, src: ByteArray, dst: ByteArray, l4len: Int) {
        if (v6) {
            b[0] = 0x60
            B.put16(b, 4, l4len)
            b[6] = proto.toByte()
            b[7] = 64
            System.arraycopy(src, 0, b, 8, 16)
            System.arraycopy(dst, 0, b, 24, 16)
        } else {
            b[0] = 0x45
            B.put16(b, 2, 20 + l4len)
            B.put16(b, 4, ipId++ and 0xFFFF)
            B.put16(b, 6, 0x4000) // DF
            b[8] = 64
            b[9] = proto.toByte()
            System.arraycopy(src, 0, b, 12, 4)
            System.arraycopy(dst, 0, b, 16, 4)
        }
    }

    fun udp(v6: Boolean, src: ByteArray, sport: Int, dst: ByteArray, dport: Int,
            data: ByteArray, off: Int, n: Int): ByteArray {
        val ih = if (v6) 40 else 20
        val b = ByteArray(ih + 8 + n)
        ipHeader(b, v6, PROTO_UDP, src, dst, 8 + n)
        B.put16(b, ih, sport)
        B.put16(b, ih + 2, dport)
        B.put16(b, ih + 4, 8 + n)
        B.put16(b, ih + 6, 0xFFFF) // non-zero placeholder so fixChecksums computes it
        System.arraycopy(data, off, b, ih + 8, n)
        val p = Ip()
        p.parse(b, b.size)
        p.fixChecksums()
        return b
    }

    /** RST in answer to the TCP segment [p] (RFC 793 reset generation). */
    fun tcpRst(p: Ip): ByteArray {
        val ih = if (p.v6) 40 else 20
        val b = ByteArray(ih + 20)
        ipHeader(b, p.v6, PROTO_TCP, p.dstAddr(), p.srcAddr(), 20)
        B.put16(b, ih, p.dstPort)
        B.put16(b, ih + 2, p.srcPort)
        val f = p.tcpFlags
        if (f and TCP_ACK != 0) {
            B.put32(b, ih + 4, p.tcpAck)
            b[ih + 13] = TCP_RST.toByte()
        } else {
            var adv = p.tcpDataLen.toLong()
            if (f and TCP_SYN != 0) adv++
            if (f and TCP_FIN != 0) adv++
            B.put32(b, ih + 8, (p.tcpSeq + adv) and 0xFFFFFFFFL)
            b[ih + 13] = (TCP_RST or TCP_ACK).toByte()
        }
        b[ih + 12] = 0x50
        val q = Ip()
        q.parse(b, b.size)
        q.fixChecksums()
        return b
    }
}
