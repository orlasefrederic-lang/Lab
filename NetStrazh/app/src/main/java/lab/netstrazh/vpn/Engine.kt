package lab.netstrazh.vpn

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import lab.netstrazh.data.Rules
import lab.netstrazh.net.HostSniffer
import lab.netstrazh.net.Ip
import lab.netstrazh.net.PROTO_TCP
import lab.netstrazh.net.PROTO_UDP
import lab.netstrazh.net.PacketBuilder
import lab.netstrazh.net.TCP_ACK
import lab.netstrazh.net.TCP_RST
import lab.netstrazh.net.TCP_SYN
import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** Addresses of our VPN interface. */
class TunConfig(val v6: Boolean) {
    val t4 = byteArrayOf(10, 111, 0, 1)        // interface address
    val p4 = byteArrayOf(10, 111, 0, 2)        // fake peer used for TCP NAT
    val dns4 = byteArrayOf(10, 111, 0, 53)     // DNS server announced to apps
    val t6 = v6addr(0x1)
    val p6 = v6addr(0x2)

    private fun v6addr(last: Int): ByteArray = ByteArray(16).also {
        it[0] = 0xfd.toByte(); it[1] = 0x00; it[2] = 0x7a; it[3] = 0x11
        it[15] = last.toByte()
    }

    companion object {
        const val T4 = "10.111.0.1"
        const val DNS4 = "10.111.0.53"
        const val T6 = "fd00:7a11::1"
        const val MTU = 1500
    }
}

/** What the engine needs from the VpnService. */
interface EngineHost {
    fun protect(s: Socket): Boolean
    fun protect(s: DatagramSocket): Boolean
    fun ownerUid(proto: Int, local: InetSocketAddress, remote: InetSocketAddress): Int
    fun netType(): NetType
    fun upstreamDns(): InetAddress
    fun onEngineDied()
}

/**
 * Packet engine. All traffic of the device (except excluded apps) arrives here from the TUN fd:
 *  - TCP is translated (NAT) so the kernel terminates it on our local server socket, then relayed
 *    through a protected socket to the real destination;
 *  - UDP is relayed per flow through protected datagram channels ([UdpRelay]);
 *  - DNS to our fake server is forwarded to the real resolver and logged.
 * Blocked apps get their connections reset / datagrams dropped.
 */
class Engine(val host: EngineHost, private val pfd: ParcelFileDescriptor, val cfg: TunConfig) {
    private val fd: FileDescriptor = pfd.fileDescriptor
    @Volatile var running = false
        private set
    val nat = NatTable()
    private val wake: Array<FileDescriptor> = Os.pipe()
    private var tcp4: ServerSocketChannel? = null
    private var tcp6: ServerSocketChannel? = null
    @Volatile private var port4 = -1
    @Volatile private var port6 = -1
    private val udp = UdpRelay(this)
    val pool: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(null, r, "ns-relay", 256L * 1024).apply { isDaemon = true }
    }
    private val house = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "ns-house").apply { isDaemon = true }
    }
    private val threads = ArrayList<Thread>()
    private val writeLock = Any()

    fun start() {
        running = true
        val s4 = bindServer(InetAddress.getByAddress(cfg.t4))
        tcp4 = s4
        port4 = s4.socket().localPort
        if (cfg.v6) {
            try {
                val s6 = bindServer(InetAddress.getByAddress(cfg.t6))
                tcp6 = s6
                port6 = s6.socket().localPort
            } catch (e: Exception) {
                Log.w(TAG, "IPv6 server socket failed", e)
            }
        }
        udp.start()
        threads += thread(name = "ns-tun", isDaemon = true) { readLoop() }
        threads += thread(name = "ns-accept4", isDaemon = true) { acceptLoop(s4) }
        tcp6?.let { s6 -> threads += thread(name = "ns-accept6", isDaemon = true) { acceptLoop(s6) } }
        house.scheduleWithFixedDelay({ housekeeping() }, 5, 5, TimeUnit.SECONDS)
    }

    fun stop() {
        if (!running) return
        running = false
        try { Os.write(wake[1], byteArrayOf(1), 0, 1) } catch (_: Exception) {}
        closeQuietly(tcp4)
        closeQuietly(tcp6)
        udp.stop()
        house.shutdownNow()
        for (c in Live.active.values.toList()) c.kill()
        pool.shutdown()
        for (t in threads) {
            if (t !== Thread.currentThread()) try { t.join(1500) } catch (_: InterruptedException) {}
        }
        try { Os.close(wake[0]) } catch (_: Exception) {}
        try { Os.close(wake[1]) } catch (_: Exception) {}
        try { pfd.close() } catch (_: Exception) {}
        nat.clear()
    }

    private fun bindServer(addr: InetAddress): ServerSocketChannel {
        var last: Exception? = null
        repeat(12) {
            val ch = ServerSocketChannel.open()
            try {
                ch.socket().reuseAddress = true
                ch.bind(InetSocketAddress(addr, 0), 1024)
                return ch
            } catch (e: Exception) {
                last = e
                closeQuietly(ch)
                Thread.sleep(100)
            }
        }
        throw last ?: IOException("bind failed")
    }

    // ---------------------------------------------------------------- TUN I/O

    fun write(b: ByteArray, len: Int) {
        synchronized(writeLock) {
            try {
                Os.write(fd, b, 0, len)
            } catch (_: Exception) {
                // interface gone or queue full: drop the packet
            }
        }
    }

    private fun readLoop() {
        val buf = ByteArray(65536)
        val pkt = Ip()
        val tunPoll = StructPollfd().apply { fd = this@Engine.fd; events = OsConstants.POLLIN.toShort() }
        val wakePoll = StructPollfd().apply { fd = wake[0]; events = OsConstants.POLLIN.toShort() }
        val fds = arrayOf(tunPoll, wakePoll)
        val bad = OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL
        outer@ while (running) {
            try {
                Os.poll(fds, -1)
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.EINTR) continue
                break
            }
            if (!running) break
            if (tunPoll.revents.toInt() and bad != 0) break
            while (running) {
                val n = try {
                    Os.read(fd, buf, 0, buf.size)
                } catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EAGAIN) break
                    if (e.errno == OsConstants.EINTR) continue
                    break@outer
                } catch (e: Exception) {
                    break@outer
                }
                if (n <= 0) break
                try {
                    if (pkt.parse(buf, n)) when (pkt.proto) {
                        PROTO_TCP -> tcpFromTun(pkt)
                        PROTO_UDP -> udp.fromApp(pkt)
                    }
                } catch (t: Throwable) {
                    Log.w(TAG, "packet error", t)
                }
            }
        }
        if (running) {
            Log.w(TAG, "TUN read loop ended unexpectedly")
            host.onEngineDied()
        }
    }

    // ---------------------------------------------------------------- TCP NAT

    private fun tcpFromTun(p: Ip) {
        if (p.l4Len < 20) return
        val t = if (p.v6) cfg.t6 else cfg.t4
        val peer = if (p.v6) cfg.p6 else cfg.p4
        val srv = if (p.v6) port6 else port4
        if (!p.srcIs(t)) return
        if (srv < 0) {
            // No server socket for this family: refuse quickly so the app falls back (e.g. IPv6 -> IPv4).
            if (p.tcpFlags and TCP_RST == 0) PacketBuilder.tcpRst(p).let { write(it, it.size) }
            return
        }
        val now = System.currentTimeMillis()

        if (p.srcPort == srv && p.dstIs(peer)) {
            // Kernel (our server socket) -> app: map back to the original remote endpoint.
            val e = nat.byPort(p.dstPort) ?: return
            e.lastSeen = now
            p.setSrc(e.dstAddr)
            p.setSrcPort(e.dstPort)
            p.setDst(t)
            p.setDstPort(e.srcPort)
            p.fixChecksums()
            write(p.buf, p.len)
            return
        }

        // App -> remote: redirect to our server socket.
        val key = FlowKey.of(p)
        val flags = p.tcpFlags
        var e = nat.get(key)
        val syn = flags and TCP_SYN != 0 && flags and TCP_ACK == 0
        if (syn && (e == null || e.closedAt != 0L)) {
            e = nat.create(key, p.v6, p.srcPort, p.dstAddr(), p.dstPort, now)
        }
        if (e == null) {
            if (flags and TCP_RST == 0) {
                val rst = PacketBuilder.tcpRst(p)
                write(rst, rst.size)
            }
            return
        }
        e.lastSeen = now
        p.setSrc(peer)
        p.setSrcPort(e.natPort)
        p.setDst(t)
        p.setDstPort(srv)
        p.fixChecksums()
        write(p.buf, p.len)
    }

    private fun acceptLoop(ss: ServerSocketChannel) {
        while (running) {
            val ch: SocketChannel = try {
                ss.accept() ?: continue
            } catch (e: Exception) {
                if (!running) break
                Thread.sleep(50)
                continue
            }
            val e = nat.byPort(ch.socket().port)
            if (e == null) {
                closeQuietly(ch)
                continue
            }
            e.accepted = true
            try {
                pool.execute { relayTcp(e, ch) }
            } catch (ex: RejectedExecutionException) {
                closeQuietly(ch)
            }
        }
    }

    private fun relayTcp(e: NatEntry, client: SocketChannel) {
        val dst = InetAddress.getByAddress(e.dstAddr)
        val fakeDns = isFakeDns(e.dstAddr)
        if (fakeDns && e.dstPort != 53) {
            // e.g. DNS-over-TLS probe to our fake resolver: refuse so the system falls back to plain DNS.
            reset(client)
            nat.close(e, System.currentTimeMillis())
            return
        }
        val ip = dst.hostAddress ?: "?"
        val local = InetAddress.getByAddress(if (e.v6) cfg.t6 else cfg.t4)
        val uid = host.ownerUid(OsConstants.IPPROTO_TCP, InetSocketAddress(local, e.srcPort), InetSocketAddress(dst, e.dstPort))
        val conn = Conn(uid, if (fakeDns) "DNS" else "TCP", if (fakeDns) "" else ip, e.dstPort,
            if (fakeDns) null else DnsCache.get(uid, ip), host.netType().label)
        Live.open(conn)
        var out: SocketChannel? = null
        try {
            if (!fakeDns && isBlocked(uid)) {
                conn.blocked = true
                reset(client)
                return
            }
            val target = if (fakeDns) InetSocketAddress(host.upstreamDns(), 53) else InetSocketAddress(dst, e.dstPort)
            val o = SocketChannel.open()
            out = o
            conn.killer = {
                reset(client)
                closeQuietly(o)
            }
            if (!host.protect(o.socket())) throw IOException("protect failed")
            o.socket().connect(target, CONNECT_TIMEOUT_MS)
            o.socket().tcpNoDelay = true
            client.socket().tcpNoDelay = true
            val down = pool.submit { pump(o, client, conn, false) }
            pump(client, o, conn, true)
            down.get()
        } catch (ex: Exception) {
            reset(client)
        } finally {
            closeQuietly(client)
            closeQuietly(out)
            nat.close(e, System.currentTimeMillis())
            Live.close(conn)
        }
    }

    private fun pump(src: SocketChannel, dst: SocketChannel, conn: Conn, up: Boolean) {
        val bb = ByteBuffer.allocate(BUF_SIZE)
        val sniffer = if (up && conn.proto == "TCP") HostSniffer() else null
        try {
            while (true) {
                bb.clear()
                val n = src.read(bb)
                if (n < 0) {
                    try { dst.shutdownOutput() } catch (_: Exception) {}
                    return
                }
                if (n == 0) continue
                if (sniffer != null && !sniffer.done && sniffer.feed(bb.array(), 0, n)) {
                    // A literal IP in SNI/Host says nothing new; keep the name learned from DNS then.
                    sniffer.host?.let { if (!isIpLiteral(it) || conn.host == null) conn.host = it }
                }
                bb.flip()
                while (bb.hasRemaining()) dst.write(bb)
                if (up) conn.addTx(n.toLong()) else conn.addRx(n.toLong())
            }
        } catch (_: Exception) {
            closeQuietly(src)
            closeQuietly(dst)
        }
    }

    private fun reset(ch: SocketChannel) {
        try { ch.socket().setSoLinger(true, 0) } catch (_: Exception) {}
        closeQuietly(ch)
    }

    // ---------------------------------------------------------------- rules / misc

    fun isFakeDns(addr: ByteArray): Boolean = addr.contentEquals(cfg.dns4)

    fun isBlocked(uid: Int): Boolean = Rules.isBlocked(uid, host.netType())

    /** Re-applies firewall rules to live connections (after a rule or network change). */
    fun enforceRules() {
        for (c in Live.active.values) {
            if (!c.blocked && c.proto != "DNS" && isBlocked(c.uid)) c.kill()
        }
        udp.reevaluateBlocked()
    }

    private fun housekeeping() {
        val now = System.currentTimeMillis()
        try { nat.sweep(now) } catch (e: Exception) { Log.w(TAG, "nat sweep", e) }
        try { udp.sweep(now) } catch (e: Exception) { Log.w(TAG, "udp sweep", e) }
    }

    companion object {
        const val TAG = "NetStrazh"
        const val CONNECT_TIMEOUT_MS = 15_000
        const val BUF_SIZE = 32 * 1024

        fun closeQuietly(c: Closeable?) {
            try { c?.close() } catch (_: Exception) {}
        }

        fun isIpLiteral(h: String): Boolean = h.contains(':') || h.all { it.isDigit() || it == '.' }
    }
}
