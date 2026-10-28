package lab.netstrazh.vpn

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import lab.netstrazh.data.Rules
import lab.netstrazh.net.Dns
import lab.netstrazh.net.DnsTcp
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
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
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
    /** Resolves an IP literal or host name without going through our own VPN. */
    fun resolve(host: String): InetAddress
    /** Our own UID (never treated as the proxy app). */
    val selfUid: Int
    fun onEngineDied()
    /** The app with this UID serves the proxy and its traffic still enters our VPN. */
    fun onProxyApp(uid: Int) {}
    /** Name of the proxy app for messages, when known. */
    fun proxyAppLabel(): String? = null
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
    val upstream = Upstream(host)
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
    /** TCP connections being relayed right now. */
    private val relays = AtomicInteger()

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
        // Learn the proxy app early, so its first lookups after a (re)start go directly.
        if (upstream.enabled) house.execute { upstream.ensureProxyUid() }
    }

    fun stop() {
        if (!running) return
        running = false
        try { Os.write(wake[1], byteArrayOf(1), 0, 1) } catch (_: Exception) {}
        closeQuietly(tcp4)
        closeQuietly(tcp6)
        udp.stop()
        upstream.close()
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
            // Only connections rewritten by tcpFromTun come from the fake peer; any other local
            // socket reaching the server address is not an app flow.
            val from = ch.socket().inetAddress?.address
            val peer = if (from?.size == 16) cfg.p6 else cfg.p4
            val e = if (from != null && from.contentEquals(peer)) nat.claim(ch.socket().port) else null
            if (e == null) {
                closeQuietly(ch)
                continue
            }
            if (relays.get() >= MAX_TCP_RELAYS) {
                // Thousands of open connections already: refuse, the app retries later.
                reset(ch)
                nat.close(e, System.currentTimeMillis())
                continue
            }
            relays.incrementAndGet()
            try {
                pool.execute {
                    try { relayTcp(e, ch) } finally { relays.decrementAndGet() }
                }
            } catch (ex: RejectedExecutionException) {
                relays.decrementAndGet()
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
        val uid = run {
            // An owner Android cannot name yet (e.g. a lookup racing with the socket's setup) is asked
            // again a few times before the connection counts as nobody's.
            fun lookup() = host.ownerUid(OsConstants.IPPROTO_TCP, InetSocketAddress(local, e.srcPort), InetSocketAddress(dst, e.dstPort))
            var u = lookup()
            var tries = 0
            while (u < 0 && tries++ < 3) {
                Thread.sleep(20)
                u = lookup()
            }
            u
        }
        val conn = Conn(uid, if (fakeDns) "DNS" else "TCP", if (fakeDns) "" else ip, e.dstPort,
            if (fakeDns) null else DnsCache.get(uid, ip), host.netType().label)
        Live.open(conn)
        val out = AtomicReference<SocketChannel?>()
        var first: ByteArray? = null
        conn.killer = {
            reset(client)
            closeQuietly(out.get())
        }
        try {
            if (isBlocked(uid) && (!fakeDns || Rules.blockDns)) {
                conn.blocked = true
                reset(client)
                return
            }
            if (fakeDns) {
                serveDnsTcp(client, conn, uid, out)
                return
            }
            val o: SocketChannel
            run {
                // Through a proxy, first read what the app sends (TLS ClientHello / HTTP request) to learn
                // the host name: the proxy then connects by name and its routing rules by domain work.
                var name: String? = null
                if (upstream.proxiedTo(uid, dst)) {
                    val (bytes, sniffer) = preread(client)
                    first = bytes
                    val sniffed = sniffer.host
                    if (sniffed != null) {
                        if (!isIpLiteral(sniffed) || conn.host == null) conn.host = sniffed
                        conn.hostSniffed = true
                        // Host rules go by the name the app itself sent: an IP is often shared by
                        // many sites, so the name our DNS cache has for it may be another one.
                        if (Rules.hostBlocked(uid, sniffed)) {
                            blockHost(conn)
                            reset(client)
                            return
                        }
                        // Connect by the name only when the app got this IP for it from our resolver:
                        // then the proxy reaching that name reaches the same service. Otherwise keep the
                        // IP the app chose: fronted or decoy names (MTProto fake-TLS, domain fronting)
                        // would lead the proxy elsewhere. Local addresses never get here (direct).
                        if (isHostName(sniffed) && !isLocal(dst) && DnsCache.has(uid, ip, sniffed)) name = sniffed
                    }
                }
                val opened = upstream.openTcp(InetSocketAddress(dst, e.dstPort), uid, CONNECT_TIMEOUT_MS, name) { out.set(it) }
                o = opened.ch
                if (opened.viaProxy) conn.via = VIA_PROXY
            }
            o.socket().tcpNoDelay = true
            client.socket().tcpNoDelay = true
            first?.let { b ->
                if (b.isNotEmpty()) {
                    val bb = ByteBuffer.wrap(b)
                    while (bb.hasRemaining()) o.write(bb)
                    conn.addTx(b.size.toLong())
                }
            }
            val down = pool.submit { pump(o, client, conn, false) }
            pump(client, o, conn, true, sniff = first == null)
            down.get()
        } catch (ex: Exception) {
            if (conn.tx == 0L && conn.rx == 0L) conn.note = failureNote(ex)
            reset(client)
        } finally {
            closeQuietly(client)
            closeQuietly(out.get())
            nat.close(e, System.currentTimeMillis())
            Live.close(conn)
        }
    }

    /**
     * DNS over TCP to our resolver address (e.g. after a truncated UDP answer). Every framed query gets
     * the decision a UDP one gets (refused, or resolved through the proxy or by the network's
     * resolver) and its answer, in order, on this connection.
     */
    private fun serveDnsTcp(client: SocketChannel, conn: Conn, uid: Int, out: AtomicReference<SocketChannel?>) {
        upstream.awaitProxyUid()
        val head = ByteBuffer.allocate(2)
        var answered = false
        var tcpRefused = false
        while (true) {
            head.clear()
            if (!readExactly(client, head)) return
            val n = ((head.get(0).toInt() and 0xFF) shl 8) or (head.get(1).toInt() and 0xFF)
            if (n < 12) return
            val q = ByteArray(n)
            if (!readExactly(client, ByteBuffer.wrap(q))) return
            conn.addTx(n + 2L)
            val name = Dns.parse(q, 0, n)?.qname
            if (conn.host == null && name != null) conn.host = name
            val why = dnsRefusal(uid, name)
            val r: ByteArray = if (why != null) {
                if (!answered) {
                    conn.blocked = true
                    conn.note = why
                }
                Dns.refused(q, 0, n) ?: return
            } else {
                val a = if (upstream.dnsViaProxy(uid)) {
                    conn.via = VIA_PROXY
                    upstream.dnsQuery(q, 0, n)
                } else {
                    val server = host.upstreamDns()
                    var a: ByteArray? = null
                    if (!tcpRefused) try {
                        val ch = out.get() ?: upstream.openTcpDirect(InetSocketAddress(server, 53), DNS_TCP_CONNECT_MS) { out.set(it) }
                        a = lab.netstrazh.net.withDeadline(ch, Upstream.DNS_TIMEOUT_MS) { DnsTcp.query(ch, q, 0, n) }
                    } catch (e: IOException) {
                        // A resolver without DNS over TCP (many home routers, the emulator): ask over UDP.
                        tcpRefused = true
                        closeQuietly(out.getAndSet(null))
                    }
                    a ?: udpDnsQuery(server, q, n)
                }
                if (conn.blocked) {
                    conn.blocked = false
                    conn.note = UdpRelay.NOTE_SOME_REFUSED
                }
                answered = true
                noteDnsAnswer(uid, a)
                a
            }
            val frame = ByteBuffer.allocate(2 + r.size)
            frame.put((r.size ushr 8).toByte()).put(r.size.toByte()).put(r).flip()
            while (frame.hasRemaining()) client.write(frame)
            conn.addRx(r.size + 2L)
        }
    }

    /** One plain DNS query over UDP to [server], outside the VPN. */
    private fun udpDnsQuery(server: InetAddress, q: ByteArray, n: Int): ByteArray {
        DatagramSocket().use { s ->
            if (!host.protect(s)) throw IOException("protect failed")
            s.soTimeout = DNS_TCP_CONNECT_MS
            s.connect(InetSocketAddress(server, 53))
            s.send(java.net.DatagramPacket(q, n))
            val buf = ByteArray(65535)
            val p = java.net.DatagramPacket(buf, buf.size)
            s.receive(p)
            return buf.copyOf(p.length)
        }
    }

    /** Remembers the names behind the addresses of a DNS answer, as the UDP path does. */
    private fun noteDnsAnswer(uid: Int, r: ByteArray) {
        val m = Dns.parse(r, 0, r.size) ?: return
        val name = m.qname ?: return
        for (a in m.addresses) DnsCache.put(uid, a, name)
    }

    /** Fills [bb] completely; false when the peer closed first. */
    private fun readExactly(ch: SocketChannel, bb: ByteBuffer): Boolean {
        while (bb.hasRemaining()) if (ch.read(bb) < 0) return false
        return true
    }

    private fun failureNote(ex: Exception): String = when (ex) {
        is Upstream.ProxyDown -> "прокси недоступен"
        is lab.netstrazh.net.ProxyException -> ex.message ?: "ошибка прокси"
        is java.net.SocketTimeoutException -> "нет ответа"
        is java.net.ConnectException -> "соединение отклонено"
        is java.nio.channels.ClosedChannelException -> "закрыто"
        else -> ex.message?.take(80) ?: ex.javaClass.simpleName
    }

    /**
     * Reads the app's first bytes for up to [PREREAD_MS] (client-first protocols send them at once;
     * server-first ones like SMTP/SSH simply time out) and extracts the host name from them.
     */
    private fun preread(client: SocketChannel): Pair<ByteArray, HostSniffer> {
        val sniffer = HostSniffer()
        val buf = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(BUF_SIZE)
        val sock = client.socket()
        val end = System.currentTimeMillis() + PREREAD_MS
        try {
            val ins = sock.getInputStream()
            while (!sniffer.done && buf.size() < HostSniffer.LIMIT) {
                val left = end - System.currentTimeMillis()
                if (left <= 0) break
                sock.soTimeout = left.toInt()
                val n = ins.read(chunk)
                if (n < 0) break
                buf.write(chunk, 0, n)
                sniffer.feed(chunk, 0, n)
            }
        } catch (_: java.net.SocketTimeoutException) {
        } finally {
            try { sock.soTimeout = 0 } catch (_: Exception) {}
        }
        return buf.toByteArray() to sniffer
    }

    private fun pump(src: SocketChannel, dst: SocketChannel, conn: Conn, up: Boolean, sniff: Boolean = true) {
        val bb = ByteBuffer.allocate(BUF_SIZE)
        val sniffer = if (up && sniff && conn.proto == "TCP") HostSniffer() else null
        try {
            while (true) {
                bb.clear()
                val n = src.read(bb)
                if (n < 0) {
                    if (!up && conn.via == VIA_PROXY && conn.rx == 0L) {
                        // Many proxies confirm CONNECT before dialing: "success, then EOF" means the dial failed.
                        conn.note = "сервер недоступен через прокси"
                        reset(dst)
                    } else {
                        try { dst.shutdownOutput() } catch (_: Exception) {}
                    }
                    return
                }
                if (n == 0) continue
                if (sniffer != null && !sniffer.done && sniffer.feed(bb.array(), 0, n)) {
                    // A literal IP in SNI/Host says nothing new; keep the name learned from DNS then.
                    sniffer.host?.let {
                        if (!isIpLiteral(it) || conn.host == null) conn.host = it
                        conn.hostSniffed = true
                    }
                    // An app that skipped our DNS (cached or hard-coded IP) still names the host here,
                    // before anything is forwarded.
                    if (Rules.hostBlocked(conn.uid, sniffer.host)) {
                        blockHost(conn)
                        reset(src)
                        closeQuietly(dst)
                        return
                    }
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

    /** Why a DNS query of [uid] for [name] is answered "refused", or null to resolve it. */
    fun dnsRefusal(uid: Int, name: String?): String? = when {
        Rules.blockDns && isBlocked(uid) -> NOTE_DNS_WITH_APP
        Rules.hostBlocked(uid, name) -> NOTE_HOST_BLOCKED
        else -> null
    }

    private fun blockHost(conn: Conn) {
        conn.blocked = true
        conn.note = NOTE_HOST_BLOCKED
    }

    /** Switches the outbound route; live connections are dropped so apps reconnect via the new route. */
    fun setProxy(c: ProxyConfig) {
        if (!running) return
        upstream.configure(c)
        for (conn in Live.active.values) if (!conn.blocked) conn.kill()
        udp.closeAll()
        upstream.ensureProxyUid()
    }

    /**
     * Applies proxy settings off the main thread, one change at a time; [current] is read when the task
     * runs, so the last saved settings always win.
     */
    fun applyProxyAsync(current: () -> ProxyConfig) {
        try {
            house.execute { if (running) setProxy(current()) }
        } catch (_: RejectedExecutionException) {
        }
    }

    /** Re-applies firewall rules to live connections (after a rule or network change). */
    fun enforceRules() {
        for (c in Live.active.values) {
            if (!c.blocked && c.proto != "DNS" && (isBlocked(c.uid) || c.hostSniffed && Rules.hostBlocked(c.uid, c.host))) c.kill()
        }
        udp.reevaluateBlocked()
    }

    private fun housekeeping() {
        val now = System.currentTimeMillis()
        // Connections silent for hours are almost always dead on the far side (carrier NATs drop idle
        // ones much sooner); apps that keep a connection open send keep-alives well within this.
        for (c in Live.active.values) {
            if (c.proto == "TCP" && now - c.lastAt > TCP_IDLE_MS) {
                c.note = "закрыто: нет активности ${TCP_IDLE_MS / 3_600_000} ч"
                c.kill()
            }
        }
        try { nat.sweep(now) } catch (e: Exception) { Log.w(TAG, "nat sweep", e) }
        try { udp.sweep(now) } catch (e: Exception) { Log.w(TAG, "udp sweep", e) }
    }

    companion object {
        const val TAG = "NetStrazh"
        const val CONNECT_TIMEOUT_MS = 15_000
        const val PREREAD_MS = 400L
        const val MAX_TCP_RELAYS = 2000
        const val DNS_TCP_CONNECT_MS = 3_000
        const val TCP_IDLE_MS = 2 * 3_600_000L
        const val NOTE_HOST_BLOCKED = "адрес заблокирован"
        const val NOTE_DNS_WITH_APP = "DNS запрещён вместе с приложением"
        const val BUF_SIZE = 32 * 1024

        fun closeQuietly(c: Closeable?) {
            try { c?.close() } catch (_: Exception) {}
        }

        fun isIpLiteral(h: String): Boolean = h.contains(':') || h.all { it.isDigit() || it == '.' }

        /** A DNS name (not an IP literal) safe to put into a SOCKS or HTTP CONNECT request. */
        fun isHostName(h: String): Boolean = h.length in 1..253 && !isIpLiteral(h) && h[0] != '.' &&
            h.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '.' || it == '-' || it == '_' }

        /**
         * Not a public address: private, link-local, loopback, multicast, carrier-grade NAT (100.64/10,
         * also used by mesh VPNs) or IPv6 unique local (fc00::/7).
         */
        fun isLocal(a: InetAddress): Boolean {
            val b = a.address
            return a.isSiteLocalAddress || a.isLinkLocalAddress || a.isLoopbackAddress || a.isAnyLocalAddress ||
                a.isMulticastAddress ||
                (b.size == 4 && b[0].toInt() == 100 && (b[1].toInt() and 0xC0) == 64) ||
                (b.size == 16 && (b[0].toInt() and 0xFE) == 0xFC)
        }
    }
}
