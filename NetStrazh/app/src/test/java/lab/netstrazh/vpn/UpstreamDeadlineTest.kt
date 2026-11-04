package lab.netstrazh.vpn

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.DataInputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors

/** DNS through the proxy keeps one deadline for every step: connection, greeting, CONNECT, the query. */
class UpstreamDeadlineTest {
    private val pool = Executors.newCachedThreadPool()
    private val lo = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private var server: ServerSocket? = null
    private var up: Upstream? = null

    private object Host : EngineHost {
        override fun protect(s: Socket) = true
        override fun protect(s: DatagramSocket) = true
        // The proxy app: some other app, never our DNS lookups.
        override fun ownerUid(proto: Int, local: InetSocketAddress, remote: InetSocketAddress) = 4242
        override fun netType() = NetType.WIFI
        override fun upstreamDns(): InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        override fun resolve(host: String): InetAddress = InetAddress.getByName(host)
        override val selfUid = 1
        override fun onEngineDied() {}
    }

    /** SOCKS5 proxy that answers the greeting and CONNECT after the given delays, then echoes DNS frames. */
    private fun proxy(greetMs: Long, connectMs: Long): Upstream {
        val ss = ServerSocket(0, 16, lo)
        server = ss
        pool.execute {
            while (!ss.isClosed) {
                val c = try { ss.accept() } catch (_: IOException) { break }
                pool.execute {
                    try {
                        c.use {
                            val i = DataInputStream(c.getInputStream())
                            val o = c.getOutputStream()
                            i.readUnsignedByte()
                            i.skipBytes(i.readUnsignedByte())
                            Thread.sleep(greetMs)
                            o.write(byteArrayOf(5, 0))
                            i.readUnsignedByte(); i.readUnsignedByte(); i.readUnsignedByte()
                            when (i.readUnsignedByte()) {
                                1 -> i.skipBytes(4)
                                4 -> i.skipBytes(16)
                                else -> i.skipBytes(i.readUnsignedByte())
                            }
                            i.readUnsignedShort()
                            Thread.sleep(connectMs)
                            o.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                            while (true) {
                                val n = i.readUnsignedShort()
                                val q = ByteArray(n).also { i.readFully(it) }
                                o.write(byteArrayOf((n ushr 8).toByte(), n.toByte()) + q)
                            }
                        }
                    } catch (_: Exception) {
                    }
                }
            }
        }
        val u = Upstream(Host)
        u.configure(ProxyConfig(type = ProxyType.SOCKS5, host = "127.0.0.1", port = ss.localPort, dnsServer = "1.1.1.1"))
        up = u
        return u
    }

    private val query = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a'.code.toByte(), 0, 0, 1, 0, 1)

    @After
    fun tearDown() {
        up?.close()
        try { server?.close() } catch (_: Exception) {}
        pool.shutdownNow()
    }

    @Test
    fun answersWithinTheBudget() {
        val u = proxy(0, 0)
        val r = u.dnsQueryOnce(InetSocketAddress("1.1.1.1", 53), query, 0, query.size, 2_000)
        assertArrayEquals(query, r)
    }

    @Test
    fun greetingAndConnectShareTheBudget() {
        // Each step alone fits in 300 ms, both together do not: the query must give up at about 300 ms
        // (each step with its own full 300 ms took 440 ms and more).
        val u = proxy(220, 220)
        val t0 = System.nanoTime()
        try {
            u.dnsQueryOnce(InetSocketAddress("1.1.1.1", 53), query, 0, query.size, 300)
            fail("answered although the proxy needs 440 ms")
        } catch (_: IOException) {
        }
        val ms = (System.nanoTime() - t0) / 1_000_000
        assertTrue("took $ms ms", ms < 420)
    }

    @Test
    fun wholeLookupEndsWithinTheTotal() {
        // The pipelined connection times out, the fallback gets only what is left of the total.
        val u = proxy(2_500, 2_500)
        val t0 = System.nanoTime()
        try {
            u.dnsQuery(query, 0, query.size)
            fail("answered although the proxy needs 5 s per connection")
        } catch (_: IOException) {
        }
        val ms = (System.nanoTime() - t0) / 1_000_000
        assertTrue("took $ms ms", ms < Upstream.DNS_TOTAL_MS + 500)
    }
}
