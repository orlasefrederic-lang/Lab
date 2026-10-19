package lab.netstrazh.net

import lab.netstrazh.vpn.DnsPipe
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
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
