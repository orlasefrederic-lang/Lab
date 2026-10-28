package lab.netstrazh.net

import lab.netstrazh.vpn.DnsPipe
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.channels.SocketChannel
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

class DnsPipeTest {
    private val lo = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    private fun query(id: Int, name: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf((id ushr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        for (l in name.split('.')) { out.write(l.length); out.write(l.toByteArray()) }
        out.write(byteArrayOf(0, 0, 1, 0, 1))
        return out.toByteArray()
    }

    /**
     * Fake resolver: answers each connection's queries in REVERSE order once [batch] queries arrived,
     * echoing the query with the QR bit set, then closes the connection after [perConn] answers.
     */
    private fun server(batch: Int, perConn: Int, conns: AtomicInteger): ServerSocket {
        val ss = ServerSocket(0, 10, lo)
        thread(isDaemon = true) {
            while (!ss.isClosed) {
                val s = try { ss.accept() } catch (e: Exception) { break }
                conns.incrementAndGet()
                thread(isDaemon = true) {
                    try {
                        val i = DataInputStream(s.getInputStream())
                        val o = DataOutputStream(s.getOutputStream())
                        var answered = 0
                        while (answered < perConn) {
                            val got = ArrayList<ByteArray>()
                            while (got.size < batch) got += ByteArray(i.readUnsignedShort()).also { i.readFully(it) }
                            for (q in got.reversed()) {
                                q[2] = (q[2].toInt() or 0x80).toByte()
                                o.writeShort(q.size); o.write(q)
                                answered++
                            }
                            o.flush()
                        }
                    } catch (_: Exception) {
                    }
                    s.close()
                }
            }
        }
        return ss
    }

    @Test fun pipelinedOutOfOrderAnswersAreMatchedAndIdsRestored() {
        val conns = AtomicInteger()
        val ss = server(batch = 4, perConn = 1000, conns)
        val pipe = DnsPipe { SocketChannel.open(InetSocketAddress(lo, ss.localPort)) }
        val pool = Executors.newFixedThreadPool(4)
        // Same app-side ID for all four queries: the pipe must still keep them apart.
        val futures = (0 until 4).map { n -> pool.submit(Callable { n to pipe.query(query(0x0707, "q$n.example"), 0, query(0x0707, "q$n.example").size, 5000) }) }
        for (f in futures) {
            val (n, r) = f.get()
            assertEquals(0x07, r[0].toInt()); assertEquals(0x07, r[1].toInt())
            assertEquals("q$n.example", Dns.parse(r, 0, r.size)!!.qname)
            assertTrue(Dns.parse(r, 0, r.size)!!.isResponse)
        }
        assertEquals(1, conns.get())
        pipe.close(); pool.shutdown(); ss.close()
    }

    @Test fun reconnectsWhenResolverClosesIdleConnection() {
        val conns = AtomicInteger()
        val ss = server(batch = 1, perConn = 1, conns) // closes after every answer
        val pipe = DnsPipe { SocketChannel.open(InetSocketAddress(lo, ss.localPort)) }
        for (n in 0 until 3) {
            val q = query(100 + n, "r$n.example")
            Thread.sleep(50) // let the reader notice the close
            val r = pipe.query(q, 0, q.size, 5000)
            assertArrayEquals(q.copyOfRange(0, 2), r.copyOfRange(0, 2))
        }
        assertTrue(conns.get() >= 3)
        pipe.close(); ss.close()
    }

    @Test fun stalledConnectionIsReplaced() {
        val conns = AtomicInteger()
        val ss = ServerSocket(0, 10, lo)
        thread(isDaemon = true) {
            while (!ss.isClosed) {
                val s = try { ss.accept() } catch (e: Exception) { break }
                val n = conns.incrementAndGet()
                thread(isDaemon = true) {
                    try {
                        val i = DataInputStream(s.getInputStream())
                        val o = DataOutputStream(s.getOutputStream())
                        while (true) {
                            val q = ByteArray(i.readUnsignedShort()).also { i.readFully(it) }
                            if (n == 1) continue // the first path swallows everything, like a dead tunnel
                            q[2] = (q[2].toInt() or 0x80).toByte()
                            o.writeShort(q.size); o.write(q); o.flush()
                        }
                    } catch (_: Exception) {
                    }
                }
            }
        }
        val pipe = DnsPipe { SocketChannel.open(InetSocketAddress(lo, ss.localPort)) }
        val q1 = query(1, "a.example")
        val t0 = System.currentTimeMillis()
        try { pipe.query(q1, 0, q1.size, 300); fail("answered by a dead path") } catch (e: java.io.IOException) {}
        assertTrue("bounded by the timeout", System.currentTimeMillis() - t0 < 1500)
        val q2 = query(2, "b.example")
        val r = pipe.query(q2, 0, q2.size, 2000)
        assertEquals("b.example", Dns.parse(r, 0, r.size)!!.qname)
        assertEquals("stalled connection replaced", 2, conns.get())
        pipe.close(); ss.close()
    }

    @Test fun slowOpenAndBlockedWritesAreBounded() {
        // Opening through the proxy can hang: queries still give up after their timeout.
        val slow = DnsPipe { Thread.sleep(3000); throw java.io.IOException("too late") }
        val q = query(3, "c.example")
        var t0 = System.currentTimeMillis()
        try { slow.query(q, 0, q.size, 300); fail() } catch (e: java.io.IOException) {}
        assertTrue(System.currentTimeMillis() - t0 < 1500)
        t0 = System.currentTimeMillis()
        slow.close()
        assertTrue("close does not wait for the opener", System.currentTimeMillis() - t0 < 300)

        // A resolver path that never reads: writes fill the buffers and block; each query is still bounded.
        val ss = ServerSocket()
        ss.receiveBufferSize = 4096
        ss.bind(InetSocketAddress(lo, 0), 10)
        val held = java.util.concurrent.CopyOnWriteArrayList<java.net.Socket>()
        thread(isDaemon = true) { while (!ss.isClosed) held += try { ss.accept() } catch (e: Exception) { break } }
        val pipe = DnsPipe {
            SocketChannel.open().apply { socket().sendBufferSize = 4096; connect(InetSocketAddress(lo, ss.localPort)) }
        }
        val big = query(4, "d.example").copyOf(60_000)
        for (k in 0 until 8) {
            t0 = System.currentTimeMillis()
            try { pipe.query(big, 0, big.size, 300) } catch (e: java.io.IOException) {}
            assertTrue("query $k bounded", System.currentTimeMillis() - t0 < 1500)
        }
        t0 = System.currentTimeMillis()
        pipe.close()
        assertTrue(System.currentTimeMillis() - t0 < 300)
        for (s in held) s.close()
        ss.close()
    }

    @Test fun oneDeadlineCoversOpenWriteWaitAndAnswer() {
        // Opening takes most of the budget: the query must still end within the budget, not reuse it.
        val ss = ServerSocket(0, 10, lo)
        thread(isDaemon = true) { while (!ss.isClosed) try { ss.accept() } catch (e: Exception) { break } } // never answers
        val pipe = DnsPipe { Thread.sleep(250); SocketChannel.open(InetSocketAddress(lo, ss.localPort)) }
        val q = query(7, "slow.example")
        var t0 = System.nanoTime()
        try { pipe.query(q, 0, q.size, 300); fail() } catch (e: java.io.IOException) {}
        val took = (System.nanoTime() - t0) / 1_000_000
        assertTrue("open + answer within the budget, took $took ms", took < 450)
        pipe.close(); ss.close()

        // Another query's write holds the lock (its path does not read): a short query still ends in time.
        val ss2 = ServerSocket()
        ss2.receiveBufferSize = 4096
        ss2.bind(InetSocketAddress(lo, 0), 10)
        val held = java.util.concurrent.CopyOnWriteArrayList<java.net.Socket>()
        thread(isDaemon = true) { while (!ss2.isClosed) held += try { ss2.accept() } catch (e: Exception) { break } }
        val pipe2 = DnsPipe { SocketChannel.open().apply { socket().sendBufferSize = 4096; connect(InetSocketAddress(lo, ss2.localPort)) } }
        val big = query(8, "big.example").copyOf(60_000)
        val small = query(9, "small.example")
        // Warm up: open the connection with a tiny query first.
        try { pipe2.query(small, 0, small.size, 100) } catch (e: java.io.IOException) {}
        val writer = thread { try { pipe2.query(big, 0, big.size, 1200) } catch (e: java.io.IOException) {} }
        Thread.sleep(100) // let the big write take the lock and block
        t0 = System.nanoTime()
        try { pipe2.query(small, 0, small.size, 100); } catch (e: java.io.IOException) {}
        val waited = (System.nanoTime() - t0) / 1_000_000
        assertTrue("write wait bounded by its own deadline, took $waited ms", waited < 400)
        writer.join(3000)
        pipe2.close()
        for (s in held) s.close()
        ss2.close()
    }

    @Test fun refusedAnswerHasHeaderAndQuestionOnly() {
        val plain = query(0x4242, "ads.example")
        val withOpt = plain.copyOf().also { it[11] = 1 } + byteArrayOf(0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
        val r = Dns.refused(withOpt, 0, withOpt.size)!!
        assertEquals(plain.size, r.size)
        assertEquals(0x42, r[0].toInt()); assertEquals(0x42, r[1].toInt())
        assertEquals("QR + RD", 0x81, r[2].toInt() and 0xFF)
        assertEquals("RA + REFUSED", 0x85, r[3].toInt() and 0xFF)
        assertEquals(0, r[11].toInt())
        val m = Dns.parse(r, 0, r.size)!!
        assertTrue(m.isResponse)
        assertEquals("ads.example", m.qname)
        // Not for responses or garbage.
        assertEquals(null, Dns.refused(r, 0, r.size))
        assertEquals(null, Dns.refused(plain, 0, 8))
    }

    @Test fun hostRulesCoverSubdomains() {
        val all = setOf("miui.com")
        val own = setOf("tracker.example")
        assertTrue(Hosts.blocked("api.sec.intl.MIUI.com.", null, all))
        assertTrue(Hosts.blocked("miui.com", null, all))
        assertTrue(!Hosts.blocked("notmiui.com", null, all))
        assertTrue(Hosts.blocked("x.tracker.example", own, all))
        assertTrue(!Hosts.blocked("tracker.example.org", own, all))
        assertTrue(!Hosts.blocked(null, own, all))
        assertTrue(!Hosts.blocked("a.example", null, emptySet()))
    }

    @Test fun ednsLimitAndTruncation() {
        val plain = query(1, "a.example")
        assertEquals(512, Dns.udpLimit(plain, 0, plain.size))
        val withOpt = plain.copyOf().also { it[11] = 1 } + byteArrayOf(0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
        assertEquals(4096, Dns.udpLimit(withOpt, 0, withOpt.size))
        // Big response: header(ANCOUNT=1) + question + one huge TXT-like record.
        val resp = plain.copyOf().also { it[2] = 0x81.toByte(); it[7] = 1 } +
            byteArrayOf(0xC0.toByte(), 12, 0, 16, 0, 1, 0, 0, 0, 1, 0x07, 0xD0.toByte()) + ByteArray(2000)
        val t = Dns.truncated(resp, resp.size)
        assertEquals(plain.size, t.size)
        assertTrue("TC set", t[2].toInt() and 0x02 != 0)
        assertEquals(0, t[7].toInt())
        assertEquals("a.example", Dns.parse(t, 0, t.size)!!.qname)
    }
}
