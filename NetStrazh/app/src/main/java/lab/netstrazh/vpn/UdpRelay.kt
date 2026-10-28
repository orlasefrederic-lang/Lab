package lab.netstrazh.vpn

import android.system.OsConstants
import android.util.Log
import lab.netstrazh.data.Rules
import lab.netstrazh.net.Dns
import lab.netstrazh.net.Ip
import lab.netstrazh.net.PacketBuilder
import lab.netstrazh.net.Socks5
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Relays UDP flows (incl. DNS to our fake resolver). Directly, through protected datagram channels;
 * in proxy mode through SOCKS5 UDP ASSOCIATE, and DNS as DNS-over-TCP through the proxy.
 */
class UdpRelay(private val eng: Engine) {
    private class Session(
        val key: FlowKey,
        val v6: Boolean,
        val appAddr: ByteArray,
        val appPort: Int,
        val remoteAddr: ByteArray,
        val remotePort: Int,
        val conn: Conn,
        val isDns: Boolean,
    ) {
        @Volatile var path: Upstream.UdpPath? = null
        @Volatile var state = PENDING
        /** DNS queries are resolved one by one over TCP through the proxy. */
        @Volatile var dnsOverProxy = false
        @Volatile var last = System.currentTimeMillis()
        /** For flows dropped because of the proxy: when to set the path up again. */
        @Volatile var retryAt = 0L
        /** DNS datagrams to a third-party resolver when the proxy cannot carry UDP. */
        @Volatile var dnsServer: InetSocketAddress? = null
        /** DNS of a blocked app while "block DNS too" is on: every query of this flow is refused. */
        @Volatile var refuseAll = false
        /** Owner lookups made so far while the owner is unknown (0: it is known). */
        @Volatile var uidLookups = 0
        val closed = AtomicBoolean(false)
        /** Datagrams received while the path is being set up (guarded by the session). */
        val queue = ArrayDeque<ByteArray>()
    }

    private class Control(val s: Session)

    private val selector: Selector = Selector.open()
    private val sessions = ConcurrentHashMap<FlowKey, Session>()
    private val pending = ConcurrentLinkedQueue<Session>()
    // Bounded: a stuck proxy must not pile up a thread per DNS query. Over the limit a session is
    // dropped and the app (or the system resolver) simply retries.
    private val setup = java.util.concurrent.ThreadPoolExecutor(SETUP_THREADS, SETUP_THREADS, 30, java.util.concurrent.TimeUnit.SECONDS,
        java.util.concurrent.LinkedBlockingQueue(SETUP_QUEUE)) { r -> Thread(null, r, "ns-udp-setup", 256L * 1024).apply { isDaemon = true } }
        .apply { allowCoreThreadTimeOut(true) }
    @Volatile private var running = false
    private var thread: Thread? = null

    fun start() {
        running = true
        thread = thread(name = "ns-udp", isDaemon = true) { loop() }
    }

    fun stop() {
        running = false
        try { selector.wakeup() } catch (_: Exception) {}
        for (s in sessions.values.toList()) close(s)
        setup.shutdownNow()
        try { thread?.join(1500) } catch (_: InterruptedException) {}
        try { selector.close() } catch (_: Exception) {}
    }

    /** Called from the TUN reader thread for every UDP packet sent by an app. Must not block. */
    fun fromApp(p: Ip) {
        if (p.l4Len < 8) return
        val t = if (p.v6) eng.cfg.t6 else eng.cfg.t4
        if (!p.srcIs(t)) return
        val n = p.udpPayloadLen
        if (n < 0) return
        val key = FlowKey.of(p)
        var s = sessions[key]
        if (s == null || s.closed.get()) s = create(p, key) ?: return
        val now = System.currentTimeMillis()
        if (s.uidLookups in 1 until MAX_UID_LOOKUPS && now - s.conn.start > 100) {
            // The owner was not known when the flow started (e.g. a socket that had just been created):
            // ask again a few times rather than treating its traffic as nobody's for the whole flow.
            s.uidLookups++
            val u = eng.host.ownerUid(OsConstants.IPPROTO_UDP, InetSocketAddress(InetAddress.getByAddress(p.srcAddr()), p.srcPort),
                InetSocketAddress(InetAddress.getByAddress(p.dstAddr()), p.dstPort))
            if (u >= 0) {
                close(s)
                s = create(p, key) ?: return
            }
        }
        s.last = now
        val off = p.udpPayloadOff
        if (s.isDns) {
            val name = Dns.parse(p.buf, off, n)?.qname
            if (s.conn.host == null && name != null) s.conn.host = name
            // Decided per query: one socket may ask for several names, and only blocked ones are refused.
            val why = if (s.refuseAll) s.conn.note else if (Rules.hostBlocked(s.conn.uid, name)) Engine.NOTE_HOST_BLOCKED else null
            if (why != null) {
                // Answer at once: silence would make the system resolver retry and wait.
                refuse(s, p.buf, off, n)
                if (s.state == NOPATH) {
                    s.conn.blocked = true
                    s.conn.note = why
                }
                return
            }
            if (s.state == NOPATH) {
                // An allowed name on a socket whose first queries were refused: set the path up now.
                s.conn.blocked = false
                s.conn.note = NOTE_SOME_REFUSED
                synchronized(s) { s.state = PENDING }
                if (!startPath(s, s.conn.uid, InetAddress.getByAddress(s.remoteAddr))) return
            }
        } else if (s.conn.blocked) {
            return
        }
        when (s.state) {
            READY -> send(s, p.buf, off, n)
            PENDING -> {
                var queued = false
                synchronized(s) {
                    if (s.state == PENDING) {
                        if (s.queue.size < MAX_QUEUED) s.queue.add(p.buf.copyOfRange(off, off + n))
                        queued = true
                    }
                }
                if (!queued && s.state == READY) send(s, p.buf, off, n)
            }
            else -> {}
        }
    }

    private fun refuse(s: Session, b: ByteArray, off: Int, n: Int) {
        val r = Dns.refused(b, off, n) ?: return
        val pk = PacketBuilder.udp(s.v6, s.remoteAddr, s.remotePort, s.appAddr, s.appPort, r, 0, r.size)
        eng.write(pk, pk.size)
    }

    private fun send(s: Session, b: ByteArray, off: Int, n: Int) {
        if (s.dnsOverProxy) {
            resolveOverProxy(s, b.copyOfRange(off, off + n))
            return
        }
        val path = s.path ?: return
        try {
            val h = path.header
            if (h == null) path.ch.write(ByteBuffer.wrap(b, off, n))
            else path.ch.write(arrayOf(ByteBuffer.wrap(h), ByteBuffer.wrap(b, off, n)))
            s.conn.addTx(n.toLong())
        } catch (e: Exception) {
            close(s)
        }
    }

    private fun create(p: Ip, key: FlowKey): Session? {
        val dst = p.dstAddr()
        val dport = p.dstPort
        val isDns = eng.isFakeDns(dst)
        if (isDns && dport != 53) return null
        if (isMulticastOrBroadcast(dst)) return null
        // Bounded, so a flood of flows cannot exhaust memory and descriptors; the app just retries.
        if (sessions.size >= MAX_SESSIONS) return null
        val dstInet = InetAddress.getByAddress(dst)
        val srcInet = InetAddress.getByAddress(p.srcAddr())
        val uid = eng.host.ownerUid(OsConstants.IPPROTO_UDP, InetSocketAddress(srcInet, p.srcPort), InetSocketAddress(dstInet, dport))
        val ip = dstInet.hostAddress ?: "?"
        val conn = Conn(uid, if (isDns) "DNS" else "UDP", if (isDns) "" else ip, dport,
            if (isDns) null else DnsCache.get(uid, ip), eng.host.netType().label)
        val s = Session(key, p.v6, p.srcAddr(), p.srcPort, dst, dport, conn, isDns)
        if (uid < 0 && !isDns) s.uidLookups = 1
        Live.open(conn)
        sessions[key] = s
        conn.killer = { close(s) }
        // DNS of a blocked app is resolved unless the user asked to block it too; blocked names are
        // refused query by query in fromApp. REFUSED is not cached by the shared system resolver.
        if (isDns) {
            if (Rules.blockDns && eng.isBlocked(uid)) {
                conn.blocked = true
                conn.note = Engine.NOTE_DNS_WITH_APP
                s.refuseAll = true
                s.state = DROP
                return s
            }
            if (Rules.hostBlocked(uid, Dns.parse(p.buf, p.udpPayloadOff, p.udpPayloadLen)?.qname)) {
                // No path until a query for an allowed name comes.
                s.state = NOPATH
                return s
            }
        }
        if (!isDns && eng.isBlocked(uid)) {
            conn.blocked = true
            s.state = DROP
            return s
        }
        // QUIC to a host blocked for this app (by the name this app resolved for the IP): dropping it
        // is harmless even if the IP serves other sites too, browsers then retry over TCP, where
        // the name in TLS decides exactly.
        if (!isDns && (dport == 443 || dport == 80) && DnsCache.ownNames(uid, ip).any { Rules.hostBlocked(uid, it) }) {
            conn.blocked = true
            conn.note = Engine.NOTE_HOST_BLOCKED
            s.state = DROP
            return s
        }
        return if (startPath(s, uid, dstInet)) s else null
    }

    /** Sets the session's path up; false (session closed) when that is not possible. */
    private fun startPath(s: Session, uid: Int, dstInet: InetAddress): Boolean {
        if (!eng.upstream.enabled) {
            // Direct: opening a datagram channel never blocks, so do it right here.
            if (openPath(s, uid, dstInet, directOnly = true)) return true
            close(s)
            return false
        }
        // Proxy mode: talking to the proxy can block, so set the path up on another thread.
        try {
            setup.execute {
                val ok = try { openPath(s, uid, dstInet) } catch (e: Exception) { false }
                if (!ok) close(s)
            }
        } catch (e: RejectedExecutionException) {
            close(s)
            return false
        }
        return true
    }

    /** Chooses and opens the path for a new session, then flushes datagrams queued meanwhile. */
    private fun openPath(s: Session, uid: Int, dstInet: InetAddress, directOnly: Boolean = false): Boolean {
        val up = eng.upstream
        try {
            // DNS and HTTP-proxy UDP decide by the proxy app's UID without connecting to the proxy first.
            if (!directOnly) up.awaitProxyUid()
            if (directOnly) {
                s.path = up.directUdp(InetSocketAddress(if (s.isDns) eng.host.upstreamDns() else dstInet, s.remotePort))
            } else if (s.isDns) {
                if (up.dnsViaProxy(uid)) {
                    s.dnsOverProxy = true
                    s.conn.via = VIA_PROXY
                } else {
                    s.path = up.directUdp(InetSocketAddress(eng.host.upstreamDns(), 53))
                }
            } else {
                val path = up.openUdp(InetSocketAddress(dstInet, s.remotePort), uid)
                if (path == null) {
                    if (s.remotePort == 53 && up.proxiedTo(uid, dstInet)) {
                        // An app asking a resolver directly (e.g. 8.8.8.8): resolve over TCP through the proxy.
                        s.dnsServer = InetSocketAddress(dstInet, 53)
                        s.dnsOverProxy = true
                        s.conn.via = VIA_PROXY
                    } else {
                        s.conn.note = up.udpDropReason()
                        // Re-evaluate later: the proxy may come back (soon) or gain UDP (after the recheck).
                        // An HTTP proxy never carries UDP: keep one dropped session until the flow goes idle
                        // (a settings change closes it anyway) instead of re-creating it every few seconds.
                        s.retryAt = when {
                            up.cfg.type == ProxyType.HTTP -> 0L
                            up.udpUnsupported -> System.currentTimeMillis() + Upstream.UDP_RECHECK_MS
                            else -> System.currentTimeMillis() + 5_000L
                        }
                        synchronized(s) {
                            s.queue.clear()
                            s.state = DROP
                        }
                        return true
                    }
                } else {
                    s.path = path
                    if (path.viaProxy) s.conn.via = VIA_PROXY
                }
            }
        } catch (e: Exception) {
            Log.w(Engine.TAG, "udp open failed: ${s.conn.ip}:${s.remotePort}", e)
            return false
        }
        if (s.closed.get()) {
            s.path?.close()
            return true
        }
        s.path?.let { pending.add(s) }
        try { selector.wakeup() } catch (_: Exception) {}
        val queued: List<ByteArray>
        synchronized(s) {
            queued = s.queue.toList()
            s.queue.clear()
            s.state = READY
        }
        for (d in queued) send(s, d, 0, d.size)
        return true
    }

    private fun resolveOverProxy(s: Session, query: ByteArray) {
        try {
            setup.execute {
                try {
                    val server = s.dnsServer
                    val full = if (server != null) eng.upstream.dnsQueryOnce(server, query, 0, query.size)
                    else eng.upstream.dnsQuery(query, 0, query.size)
                    s.last = System.currentTimeMillis()
                    s.conn.addTx(query.size.toLong())
                    s.conn.addRx(full.size.toLong())
                    onDnsResponse(s, full, full.size)
                    // A TCP answer can be bigger than the stub accepts over UDP: then say "truncated" so it retries over TCP.
                    val r = if (full.size > Dns.udpLimit(query, 0, query.size)) Dns.truncated(full, full.size) else full
                    val pk = PacketBuilder.udp(s.v6, s.remoteAddr, s.remotePort, s.appAddr, s.appPort, r, 0, r.size)
                    eng.write(pk, pk.size)
                } catch (e: Exception) {
                    s.conn.note = "DNS через прокси: ${e.message ?: "ошибка"}"
                    eng.upstream.noteEvent(s.conn.note!!)
                }
                close(s)
            }
        } catch (e: RejectedExecutionException) {
            close(s)
        }
    }

    private fun loop() {
        val bb = ByteBuffer.allocate(65536)
        while (running) {
            try {
                selector.select(2000)
            } catch (e: Exception) {
                break
            }
            while (true) {
                val s = pending.poll() ?: break
                val path = s.path ?: continue
                if (s.closed.get()) continue
                try {
                    path.ch.configureBlocking(false)
                    path.ch.register(selector, SelectionKey.OP_READ, s)
                    // SOCKS: the association ends when its TCP control connection closes (Xray closes it after idling).
                    path.control?.let {
                        it.configureBlocking(false)
                        it.register(selector, SelectionKey.OP_READ, Control(s))
                    }
                } catch (e: Exception) {
                    close(s)
                }
            }
            val keys = try { selector.selectedKeys() } catch (e: Exception) { break }
            val it = keys.iterator()
            while (it.hasNext()) {
                val k = it.next()
                it.remove()
                if (!k.isValid) continue
                val att = k.attachment()
                if (att is Control) {
                    try {
                        bb.clear()
                        if ((k.channel() as java.nio.channels.SocketChannel).read(bb) < 0) close(att.s)
                    } catch (e: Exception) {
                        close(att.s)
                    }
                    continue
                }
                val s = att as Session
                val path = s.path ?: continue
                try {
                    while (true) {
                        bb.clear()
                        val n = path.ch.read(bb)
                        if (n <= 0) break
                        var off = 0
                        if (path.header != null) {
                            off = Socks5.udpPayloadOffset(bb.array(), n)
                            if (off < 0) continue
                            // Full-cone proxies relay datagrams from any host; keep only this flow's peer,
                            // as a connected socket would on the direct path. By port only: a proxy that
                            // sniffed a domain (Xray) dials it itself and reports the address it resolved,
                            // which may differ from the one the app chose.
                            val src = Socks5.udpSource(bb.array(), n)
                            if (src != null && src.port != s.remotePort) continue
                        }
                        val len = n - off
                        s.last = System.currentTimeMillis()
                        s.conn.addRx(len.toLong())
                        if (s.isDns) onDnsResponse(s, bb.array(), len, off)
                        val pk = PacketBuilder.udp(s.v6, s.remoteAddr, s.remotePort, s.appAddr, s.appPort, bb.array(), off, len)
                        eng.write(pk, pk.size)
                        if (s.isDns) {
                            close(s)
                            break
                        }
                    }
                } catch (e: Exception) {
                    close(s)
                }
            }
        }
    }

    private fun onDnsResponse(s: Session, b: ByteArray, n: Int, off: Int = 0) {
        val m = Dns.parse(b, off, n) ?: return
        val name = m.qname ?: return
        if (s.conn.host == null) s.conn.host = name
        for (a in m.addresses) DnsCache.put(s.conn.uid, a, name)
        if (m.addresses.isNotEmpty()) {
            s.conn.ip = if (m.addresses.size == 1) m.addresses[0] else m.addresses[0] + " +" + (m.addresses.size - 1)
        } else if (m.rcode == 3) {
            s.conn.ip = "NXDOMAIN"
        }
    }

    private fun close(s: Session) {
        if (!s.closed.compareAndSet(false, true)) return
        sessions.remove(s.key, s)
        synchronized(s) {
            s.queue.clear()
            if (s.state == PENDING) s.state = DROP
        }
        s.path?.close()
        Live.close(s.conn)
    }

    fun sweep(now: Long) {
        for (s in sessions.values) {
            if (s.state == DROP && !s.conn.blocked && s.retryAt != 0L && now >= s.retryAt) {
                close(s)
                continue
            }
            val idle = now - s.last
            val limit = when {
                s.isDns -> DNS_TIMEOUT_MS
                s.conn.blocked || s.state == DROP -> BLOCKED_TIMEOUT_MS
                else -> UDP_TIMEOUT_MS
            }
            if (idle > limit) close(s)
        }
    }

    /** After a rule change: forget "blocked" markers so the next datagram is evaluated again. */
    fun reevaluateBlocked() {
        for (s in sessions.values) {
            if (s.conn.blocked && !eng.isBlocked(s.conn.uid)) close(s)
        }
    }

    /** Drops every flow, e.g. after the proxy settings changed. */
    fun closeAll() {
        for (s in sessions.values.toList()) close(s)
    }

    private fun isMulticastOrBroadcast(a: ByteArray): Boolean =
        if (a.size == 4) (a[0].toInt() and 0xF0) == 0xE0 || (a[0].toInt() and 0xFF) == 255
        else (a[0].toInt() and 0xFF) == 0xFF

    companion object {
        const val UDP_TIMEOUT_MS = 120_000L
        const val DNS_TIMEOUT_MS = 20_000L
        const val BLOCKED_TIMEOUT_MS = 30_000L
        const val MAX_QUEUED = 32
        const val SETUP_THREADS = 64
        const val SETUP_QUEUE = 1024
        const val MAX_SESSIONS = 4096
        const val MAX_UID_LOOKUPS = 4
        const val NOTE_SOME_REFUSED = "часть запросов отклонена: адрес заблокирован"
        private const val PENDING = 0
        private const val READY = 1
        private const val DROP = 2
        /** DNS flow whose queries so far were all refused: no path opened yet. */
        private const val NOPATH = 3
    }
}
