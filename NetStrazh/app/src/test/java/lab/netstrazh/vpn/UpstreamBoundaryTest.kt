package lab.netstrazh.vpn

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/**
 * What the system does slowly (looking a host name up, protecting a socket) must not carry a DNS
 * lookup past its deadline, and running out of time must not leave a channel open.
 */
class UpstreamBoundaryTest {
    private val lo = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val query = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a'.code.toByte(), 0, 0, 1, 0, 1)
    private val target = InetSocketAddress(InetAddress.getByAddress(byteArrayOf(198.toByte(), 51, 100, 10)), 53)
    private var server: ServerSocket? = null
    private var up: Upstream? = null

    /** The Android side, with a resolver or protect() that takes its time. */
    private class SlowHost(val slowName: String?, val resolveMs: Long = 0, val protectMs: Long = 0) : EngineHost {
        val sockets = CopyOnWriteArrayList<Socket>()
        val resolves = AtomicInteger()
        override fun protect(s: Socket): Boolean {
            sockets += s
            if (protectMs > 0) Thread.sleep(protectMs)
            return true
        }
        override fun protect(s: DatagramSocket) = true
        override fun ownerUid(proto: Int, local: InetSocketAddress, remote: InetSocketAddress) = -1
        override fun netType() = NetType.WIFI
        override fun upstreamDns(): InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        override fun resolve(host: String): InetAddress {
            if (host == slowName) {
                resolves.incrementAndGet()
                Thread.sleep(resolveMs)
            }
            return if (host == "slow-dns.invalid") InetAddress.getByAddress(byteArrayOf(198.toByte(), 51, 100, 10))
            else InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        }
        override val selfUid = 10001
        override fun onEngineDied() {}
        fun open(): Int = sockets.count { it.channel?.isOpen == true }
    }

    /** A "proxy" that accepts connections and never answers. */
    private fun upstream(host: SlowHost, proxyHost: String, dnsServer: String = "198.51.100.10"): Upstream {
        val ss = ServerSocket(0, 16, lo)
        server = ss
        val u = Upstream(host)
        u.configure(ProxyConfig(type = ProxyType.SOCKS5, host = proxyHost, port = ss.localPort, dnsServer = dnsServer))
        up = u
        return u
    }

    private fun elapsedMs(block: () -> Unit): Long {
        val t0 = System.nanoTime()
        try {
            block()
            fail("answered although the proxy never does")
        } catch (_: IOException) {
        }
        return (System.nanoTime() - t0) / 1_000_000
    }

    @After
    fun tearDown() {
        up?.close()
        try { server?.close() } catch (_: Exception) {}
    }

    @Test
    fun slowProxyNameDoesNotOutliveTheBudget() {
        // The proxy's name takes 600 ms to resolve, the query has 100 ms.
        val host = SlowHost("slow-proxy.invalid", resolveMs = 600)
        val u = upstream(host, "slow-proxy.invalid")
        val ms = elapsedMs { u.dnsQueryOnce(target, query, 0, query.size, 100) }
        assertTrue("took $ms ms", ms < 400)
        assertEquals("channels left open", 0, host.open())
        // The lookup went on meanwhile: the next query does not ask again, and gets its turn.
        Thread.sleep(700)
        val again = elapsedMs { u.dnsQueryOnce(target, query, 0, query.size, 200) }
        assertTrue("second query took $again ms", again in 150..1000)
        assertEquals("name looked up once", 1, host.resolves.get())
        assertEquals("channels left open after the second query", 0, host.open())
    }

    @Test
    fun timeRunningOutWhileProtectingLeavesNoChannelOpen() {
        // protect() takes longer than the query has: the channel made meanwhile must be closed.
        val host = SlowHost(null, protectMs = 300)
        val u = upstream(host, "127.0.0.1")
        elapsedMs { u.dnsQueryOnce(target, query, 0, query.size, 60) }
        assertEquals("one channel was made", 1, host.sockets.size)
        assertEquals("channels left open", 0, host.open())
    }

    /** A SOCKS5 proxy that answers at once and then echoes DNS frames. */
    private fun serveSocks(ss: ServerSocket) {
        kotlin.concurrent.thread(isDaemon = true) {
            while (!ss.isClosed) {
                val c = try { ss.accept() } catch (_: IOException) { break }
                kotlin.concurrent.thread(isDaemon = true) {
                    try {
                        c.use {
                            val i = java.io.DataInputStream(c.getInputStream())
                            val o = c.getOutputStream()
                            i.readUnsignedByte()
                            i.skipBytes(i.readUnsignedByte())
                            o.write(byteArrayOf(5, 0))
                            i.readUnsignedByte(); i.readUnsignedByte(); i.readUnsignedByte()
                            when (i.readUnsignedByte()) {
                                1 -> i.skipBytes(4)
                                4 -> i.skipBytes(16)
                                else -> i.skipBytes(i.readUnsignedByte())
                            }
                            i.readUnsignedShort()
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
    }

    @Test
    fun proxyThatComesUpAMomentLaterIsWaitedFor() {
        // A proxy app restarting its core: its port is closed for a moment, then serves again. Every
        // refused attempt closes its channel; the one that gets through answers the query.
        val port = ServerSocket(0, 16, lo).use { it.localPort }
        val host = SlowHost(null)
        val u = Upstream(host)
        u.configure(ProxyConfig(type = ProxyType.SOCKS5, host = "127.0.0.1", port = port, dnsServer = "198.51.100.10"))
        up = u
        kotlin.concurrent.thread(isDaemon = true) {
            Thread.sleep(700)
            val ss = ServerSocket(port, 16, lo)
            server = ss
            serveSocks(ss)
        }
        val r = u.dnsQueryOnce(target, query, 0, query.size, 3_000)
        org.junit.Assert.assertArrayEquals(query, r)
        assertTrue("refused attempts were retried: ${host.sockets.size}", host.sockets.size >= 2)
        assertEquals("channels left open", 0, host.open())
    }

    @Test
    fun slowDnsServerNameStaysWithinTheTotal() {
        // The resolver's own name takes 3.5 s: the pipelined attempt and the fallback share one lookup,
        // and the whole query still ends by its total.
        val host = SlowHost("slow-dns.invalid", resolveMs = 3_500)
        val u = upstream(host, "127.0.0.1", dnsServer = "slow-dns.invalid")
        val ms = elapsedMs { u.dnsQuery(query, 0, query.size) }
        assertTrue("took $ms ms", ms < Upstream.DNS_TOTAL_MS + 500)
        assertEquals("name looked up once", 1, host.resolves.get())
    }
}
