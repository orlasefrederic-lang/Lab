package lab.netstrazh.net

import lab.netstrazh.vpn.FlowKey
import lab.netstrazh.vpn.NatTable
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketTest {
    private fun ip4(vararg x: Int) = ByteArray(4) { x[it].toByte() }

    /** Builds an IPv4/TCP segment by hand with valid checksums. */
    private fun tcp4(src: ByteArray, sport: Int, dst: ByteArray, dport: Int, seq: Long, ack: Long, flags: Int, data: ByteArray = ByteArray(0)): ByteArray {
        val b = ByteArray(40 + data.size)
        b[0] = 0x45
        B.put16(b, 2, b.size)
        b[8] = 64
        b[9] = 6
        System.arraycopy(src, 0, b, 12, 4)
        System.arraycopy(dst, 0, b, 16, 4)
        B.put16(b, 20, sport)
        B.put16(b, 22, dport)
        B.put32(b, 24, seq)
        B.put32(b, 28, ack)
        b[32] = 0x50
        b[33] = flags.toByte()
        B.put16(b, 34, 65535)
        System.arraycopy(data, 0, b, 40, data.size)
        val p = Ip()
        assertTrue(p.parse(b, b.size))
        p.fixChecksums()
        return b
    }

    @Test fun checksumKnownVector() {
        // Example header from RFC 1071-style worked examples (checksum field zeroed): expected 0xB861
        val h = intArrayOf(0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
            0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7).map { it.toByte() }.toByteArray()
        assertEquals(0xB861, Checksum.finish(Checksum.add(h, 0, h.size)))
    }

    @Test fun parseAndRewriteTcp() {
        val b = tcp4(ip4(10, 111, 0, 1), 40000, ip4(93, 184, 216, 34), 443, 1000, 0, TCP_SYN)
        val p = Ip()
        assertTrue(p.parse(b, b.size))
        assertTrue(p.ipChecksumOk())
        assertTrue(p.l4ChecksumOk())
        assertEquals(6, p.proto)
        assertEquals(40000, p.srcPort)
        assertEquals(443, p.dstPort)
        assertTrue(p.srcIs(ip4(10, 111, 0, 1)))

        p.setSrc(ip4(10, 111, 0, 2)); p.setSrcPort(12345)
        p.setDst(ip4(10, 111, 0, 1)); p.setDstPort(5555)
        p.fixChecksums()
        val q = Ip()
        assertTrue(q.parse(b, b.size))
        assertTrue(q.ipChecksumOk())
        assertTrue(q.l4ChecksumOk())
        assertEquals(12345, q.srcPort)
        assertEquals(5555, q.dstPort)
    }

    @Test fun oddLengthPayloadChecksum() {
        val b = tcp4(ip4(10, 0, 0, 1), 1, ip4(10, 0, 0, 2), 2, 5, 6, TCP_ACK, byteArrayOf(1, 2, 3))
        val p = Ip()
        assertTrue(p.parse(b, b.size))
        assertTrue(p.l4ChecksumOk())
        assertEquals(3, p.tcpDataLen)
    }

    @Test fun rstForSyn() {
        val b = tcp4(ip4(10, 111, 0, 1), 40000, ip4(1, 2, 3, 4), 80, 1000, 0, TCP_SYN)
        val p = Ip(); p.parse(b, b.size)
        val r = PacketBuilder.tcpRst(p)
        val q = Ip()
        assertTrue(q.parse(r, r.size))
        assertTrue(q.ipChecksumOk()); assertTrue(q.l4ChecksumOk())
        assertTrue(q.srcIs(ip4(1, 2, 3, 4)))
        assertEquals(80, q.srcPort); assertEquals(40000, q.dstPort)
        assertEquals(TCP_RST or TCP_ACK, q.tcpFlags)
        assertEquals(1001L, q.tcpAck)
    }

    @Test fun rstForAck() {
        val b = tcp4(ip4(10, 111, 0, 1), 40000, ip4(1, 2, 3, 4), 80, 1000, 777, TCP_ACK, byteArrayOf(9, 9))
        val p = Ip(); p.parse(b, b.size)
        val q = Ip(); val r = PacketBuilder.tcpRst(p); q.parse(r, r.size)
        assertEquals(TCP_RST, q.tcpFlags)
        assertEquals(777L, q.tcpSeq)
    }

    @Test fun udpBuilderV4AndV6() {
        val payload = "hello".toByteArray()
        val b = PacketBuilder.udp(false, ip4(8, 8, 8, 8), 53, ip4(10, 111, 0, 1), 5000, payload, 0, payload.size)
        val p = Ip()
        assertTrue(p.parse(b, b.size))
        assertTrue(p.ipChecksumOk()); assertTrue(p.l4ChecksumOk())
        assertEquals(5, p.udpPayloadLen)
        assertEquals('h'.code.toByte(), b[p.udpPayloadOff])

        val s6 = ByteArray(16).also { it[0] = 0x20; it[15] = 1 }
        val d6 = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 1 }
        val b6 = PacketBuilder.udp(true, s6, 443, d6, 6000, payload, 0, payload.size)
        val p6 = Ip()
        assertTrue(p6.parse(b6, b6.size))
        assertTrue(p6.v6)
        assertTrue(p6.l4ChecksumOk())
        assertEquals(443, p6.srcPort)
    }

    @Test fun rejectsFragmentsAndGarbage() {
        val b = tcp4(ip4(10, 0, 0, 1), 1, ip4(10, 0, 0, 2), 2, 0, 0, TCP_SYN)
        B.put16(b, 6, 0x2000) // MF
        assertFalse(Ip().parse(b, b.size))
        assertFalse(Ip().parse(ByteArray(10), 10))
    }

    private fun dnsName(vararg labels: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (l in labels) { out.write(l.length); out.write(l.toByteArray()) }
        out.write(0)
        return out.toByteArray()
    }

    @Test fun dnsResponseWithCompression() {
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0, 1, 0, 2, 0, 0, 0, 0))
        out.write(dnsName("WWW", "Example", "com"))
        out.write(byteArrayOf(0, 1, 0, 1))
        // answer 1: CNAME -> pointer to offset 12
        out.write(byteArrayOf(0xC0.toByte(), 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0.toByte(), 16))
        // answer 2: A 93.184.216.34
        out.write(byteArrayOf(0xC0.toByte(), 16, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184.toByte(), 216.toByte(), 34))
        val b = out.toByteArray()
        val m = Dns.parse(b, 0, b.size)
        assertNotNull(m)
        m!!
        assertTrue(m.isResponse)
        assertEquals("www.example.com", m.qname)
        assertEquals(1, m.qtype)
        assertEquals(listOf("93.184.216.34"), m.addresses)
        assertEquals(listOf("example.com"), m.cnames)
    }

    @Test fun dnsPointerLoopIsRejected() {
        val b = byteArrayOf(0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0.toByte(), 12, 0, 1, 0, 1)
        assertNull(Dns.parse(b, 0, b.size))
    }

    private fun clientHello(sni: String, before: Int = 2): ByteArray {
        val exts = java.io.ByteArrayOutputStream()
        repeat(before) { i -> exts.write(byteArrayOf(0x0a, (i + 1).toByte(), 0, 2, 0, 0)) }
        val name = sni.toByteArray()
        val sn = java.io.ByteArrayOutputStream()
        sn.write(byteArrayOf(((name.size + 3) ushr 8).toByte(), (name.size + 3).toByte(), 0, (name.size ushr 8).toByte(), name.size.toByte()))
        sn.write(name)
        val snb = sn.toByteArray()
        exts.write(byteArrayOf(0, 0, (snb.size ushr 8).toByte(), snb.size.toByte())); exts.write(snb)
        val e = exts.toByteArray()
        val body = java.io.ByteArrayOutputStream()
        body.write(byteArrayOf(3, 3)); body.write(ByteArray(32)); body.write(0)
        body.write(byteArrayOf(0, 2, 0x13, 0x01)); body.write(byteArrayOf(1, 0))
        body.write(byteArrayOf((e.size ushr 8).toByte(), e.size.toByte())); body.write(e)
        val bb = body.toByteArray()
        val hs = java.io.ByteArrayOutputStream()
        hs.write(byteArrayOf(1, 0, (bb.size ushr 8).toByte(), bb.size.toByte())); hs.write(bb)
        val h = hs.toByteArray()
        val rec = java.io.ByteArrayOutputStream()
        rec.write(byteArrayOf(0x16, 3, 1, (h.size ushr 8).toByte(), h.size.toByte())); rec.write(h)
        return rec.toByteArray()
    }

    @Test fun sniExtraction() {
        val ch = clientHello("Api.Example.ORG")
        assertEquals("api.example.org", Sniff.tlsSni(ch, ch.size))
        assertNull(Sniff.tlsSni(ch, 20))
    }

    @Test fun snifferAcrossChunks() {
        val ch = clientHello("chunked.example.net", before = 5)
        val s = HostSniffer()
        assertFalse(s.feed(ch, 0, 30))
        assertTrue(s.feed(ch, 30, ch.size - 30))
        assertEquals("chunked.example.net", s.host)

        val http = "GET /x HTTP/1.1\r\nUser-Agent: t\r\nHost: Example.com:8080\r\n\r\n".toByteArray()
        val h = HostSniffer()
        assertTrue(h.feed(http, 0, http.size))
        assertEquals("example.com", h.host)

        val junk = HostSniffer()
        assertTrue(junk.feed(byteArrayOf(0, 1, 2, 3, 4, 5), 0, 6))
        assertNull(junk.host)
    }

    @Test fun natTableAllocatesAndSweeps() {
        val t = NatTable(20000, 20002)
        val k1 = FlowKey(false, 1, 1, 0, 80)
        val k2 = FlowKey(false, 2, 1, 0, 80)
        val e1 = t.create(k1, false, 1, ip4(1, 0, 0, 1), 80, 0)!!
        val e2 = t.create(k2, false, 2, ip4(1, 0, 0, 1), 80, 0)!!
        assertTrue(e1.natPort != e2.natPort)
        assertEquals(e1, t.byPort(e1.natPort))
        assertEquals(e2, t.get(k2))
        e1.accepted = true
        t.close(e1, 1000)
        assertEquals(2, t.size)
        // e2 never accepted -> swept after timeout; e1 swept after grace period
        t.sweep(NatTable.UNACCEPTED_MS + 1)
        assertNull(t.get(k2))
        assertNotNull(t.byPort(e1.natPort))
        t.sweep(1000 + NatTable.CLOSED_GRACE_MS + 1)
        assertNull(t.byPort(e1.natPort))
        assertEquals(0, t.size)
    }

    @Test fun flowKeyEquality() {
        val b = tcp4(ip4(10, 111, 0, 1), 40000, ip4(1, 2, 3, 4), 443, 1, 0, TCP_SYN)
        val p = Ip(); p.parse(b, b.size)
        assertEquals(FlowKey.of(p), FlowKey(false, 40000, 0x01020304L, 0, 443))
    }
}
