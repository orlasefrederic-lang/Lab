package lab.netstrazh.vpn

import android.system.OsConstants
import lab.netstrazh.net.DeadlineException
import lab.netstrazh.net.DnsTcp
import lab.netstrazh.net.HttpConnect
import lab.netstrazh.net.ProxyException
import lab.netstrazh.net.Socks5
import lab.netstrazh.net.isLoopback
import lab.netstrazh.net.withDeadline
import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel

enum class ProxyType { NONE, SOCKS5, HTTP }

/** Where relayed traffic leaves the device: directly, or through another app's local proxy. */
data class ProxyConfig(
    val type: ProxyType = ProxyType.NONE,
    val host: String = "127.0.0.1",
    val port: Int = 0,
    val user: String = "",
    val pass: String = "",
    /** Resolve apps' DNS queries through the proxy (DNS over TCP to [dnsServer]). */
    val dnsViaProxy: Boolean = true,
    val dnsServer: String = "1.1.1.1",
    /** Send UDP directly when the proxy cannot carry it (otherwise UDP is dropped). */
    val udpDirect: Boolean = false,
    /** Go directly when the proxy is unreachable (otherwise connections fail). */
    val directIfDown: Boolean = false,
    /**
     * Keep the proxy app itself out of our VPN, as it keeps itself out of its own VPN: its server
     * connections and DNS then use the real network directly, whatever happens inside our tunnel.
     */
    val bypassApp: Boolean = true,
    /** Package of the app serving the proxy, when known (picked in the settings or detected). */
    val appPkg: String = "",
) {
    val enabled: Boolean get() = type != ProxyType.NONE && port in 1..65535 && host.isNotBlank()

    fun sameEndpoint(o: ProxyConfig): Boolean =
        type == o.type && host == o.host && port == o.port && user == o.user && pass == o.pass

    companion object {
        val OFF = ProxyConfig()
    }
}

/** Opens outbound TCP connections, UDP paths and DNS lookups for the engine. */
class Upstream(private val host: EngineHost) {
    class Opened(val ch: SocketChannel, val viaProxy: Boolean)

    /** A UDP path: a datagram channel, plus the SOCKS control connection and header when proxied. */
    class UdpPath(val ch: DatagramChannel, val control: SocketChannel?, val header: ByteArray?) : Closeable {
        val viaProxy: Boolean get() = header != null
        override fun close() {
            Engine.closeQuietly(ch)
            Engine.closeQuietly(control)
        }
    }

    @Volatile var cfg: ProxyConfig = ProxyConfig.OFF
        private set
    @Volatile private var proxyAddr: InetSocketAddress? = null
    /** UID of the app that serves the local proxy: its own traffic must never be sent back into the proxy. */
    @Volatile var proxyUid = UID_UNKNOWN
        private set
    @Volatile private var proxyUidCheckedAt = 0L
    @Volatile private var probeFailedAt = 0L
    @Volatile private var udpUnsupportedAt = 0L
    @Volatile var lastError: String? = null
        private set
    @Volatile var lastErrorAt = 0L
        private set
    /** Last time the proxy as a whole failed (unreachable, login refused), unlike one refused destination. */
    @Volatile var downAt = 0L
        private set
    @Volatile var lastOkAt = 0L
        private set
    private val lock = Any()
    private val dnsPipe = DnsPipe {
        openTcp(InetSocketAddress(host.resolve(cfg.dnsServer), 53), UID_DNS, PROXY_CONNECT_MS) {}.ch
    }

    val enabled: Boolean get() = cfg.enabled
    val udpUnsupported: Boolean get() = udpUnsupportedAt != 0L && System.currentTimeMillis() - udpUnsupportedAt < UDP_RECHECK_MS

    fun configure(c: ProxyConfig) {
        synchronized(lock) {
            cfg = c
            proxyAddr = null
            proxyUid = UID_UNKNOWN
            proxyUidCheckedAt = 0L
            probeFailedAt = 0L
            udpUnsupportedAt = 0L
            lastError = null
            lastErrorAt = 0L
            downAt = 0L
            lastOkAt = 0L
        }
        dnsPipe.close()
    }

    /** A connection to the proxy itself (e.g. a LAN proxy) is never sent through that proxy. */
    private fun isProxyEndpoint(dst: InetSocketAddress): Boolean =
        try { proxyEndpoint() == dst } catch (_: Exception) { false }

    private fun proxyEndpoint(): InetSocketAddress {
        proxyAddr?.let { return it }
        val c = cfg
        val e = InetSocketAddress(host.resolve(c.host), c.port)
        if (cfg === c) proxyAddr = e
        return e
    }

    /**
     * True when traffic of [uid] goes through the proxy. Never blocks: the proxy app's UID is learned on
     * every proxy connection (see [proxyChannel]), so even before it is known no loop can form.
     */
    fun proxied(uid: Int): Boolean = cfg.enabled && uid != proxyUid

    /**
     * Like [proxied], for a destination: the local network (router, printers, phones next to you)
     * is reached directly, as the proxy app's own VPN mode leaves it outside the tunnel.
     */
    fun proxiedTo(uid: Int, dst: InetAddress?): Boolean = proxied(uid) && (dst == null || !Engine.isLocal(dst))

    /**
     * Finds the app that listens on the proxy port. If that app's traffic also enters our VPN, relaying it
     * back into its own proxy would loop forever, so its connections go directly instead.
     */
    fun ensureProxyUid() {
        if (!cfg.enabled) return
        val now = System.currentTimeMillis()
        if (proxyUid != UID_UNKNOWN && now - proxyUidCheckedAt < PROXY_UID_TTL_MS) return
        // An unreachable proxy (e.g. a LAN proxy dropping packets) must not stall every DNS setup.
        if (now - probeFailedAt < PROXY_UID_RETRY_MS) return
        if (!probing.compareAndSet(false, true)) return
        var ch: SocketChannel? = null
        try {
            ch = SocketChannel.open()
            host.protect(ch.socket())
            ch.socket().connect(proxyEndpoint(), 2000)
            learnProxyUid(ch)
        } catch (e: Exception) {
            probeFailedAt = System.currentTimeMillis()
            noteError("прокси недоступен: ${e.message ?: e.javaClass.simpleName}", down = true)
        } finally {
            Engine.closeQuietly(ch)
            probing.set(false)
        }
    }

    private val probing = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * For routing decisions that cannot learn the proxy app's UID themselves (DNS answered through
     * the proxy, UDP an HTTP proxy cannot carry): finds it first if still unknown, e.g. right after
     * the engine started, so the proxy app's own lookups never go into its proxy. May block ~2 s.
     */
    fun awaitProxyUid() {
        if (!cfg.enabled || proxyUid != UID_UNKNOWN) return
        ensureProxyUid()
        // Another thread's probe may still be running.
        val end = System.currentTimeMillis() + 2_500
        while (proxyUid == UID_UNKNOWN && probing.get() && System.currentTimeMillis() < end) Thread.sleep(20)
    }

    /**
     * Finds which app serves the proxy reached by [ch]. Returns the value stored in [proxyUid], or
     * null when it cannot be told right now (the previous value is kept then).
     *
     * The owner of the proxy's *listening* socket is asked for: the proxy's end of our connection
     * waits in the accept queue until the proxy app accepts it (late when the app is busy or frozen),
     * and the kernel reports such a socket as owned by root (uid 0). A lookup for a peer that never
     * connected (port 1) finds the listener, which always carries its app's UID.
     */
    private fun learnProxyUid(ch: SocketChannel): Int? {
        val c = cfg
        val local = ch.socket().localSocketAddress as? InetSocketAddress ?: return null
        val remote = ch.socket().remoteSocketAddress as? InetSocketAddress ?: return null
        var uid = host.ownerUid(OsConstants.IPPROTO_TCP, remote, InetSocketAddress(remote.address, 1))
        if (uid < 0) {
            // Not found that way (or the app is outside our VPN): our connection's other end tells,
            // unless it has not been accepted yet.
            val u = host.ownerUid(OsConstants.IPPROTO_TCP, remote, local)
            if (u == 0) return null
            uid = u
        }
        if (cfg !== c) return null
        val learned = if (uid >= 0 && uid != host.selfUid) uid else UID_NONE
        val before = proxyUid
        proxyUid = learned
        if (learned >= 0 && learned != before) host.onProxyApp(learned)
        proxyUidCheckedAt = System.currentTimeMillis()
        return learned
    }

    private fun newChannel(track: (SocketChannel) -> Unit): SocketChannel {
        val ch = SocketChannel.open()
        track(ch)
        if (!host.protect(ch.socket())) {
            Engine.closeQuietly(ch)
            throw IOException("protect failed")
        }
        return ch
    }

    /** The caller is the proxy app itself: its traffic must go directly. */
    class IsProxyApp : IOException("proxy app")

    /**
     * Connects to the proxy for a flow of [uid]. The proxy app's UID is learned from this very
     * connection every time (another app may have taken over the port), so the proxy app's own
     * traffic is never sent into its proxy.
     */
    private fun proxyChannel(uid: Int, track: (SocketChannel) -> Unit): SocketChannel {
        val ep = proxyEndpoint()
        // A local proxy app restarts its core on every network change (v2rayNG: about a second with
        // the port closed): keep trying a refused connection for a moment instead of failing the app.
        // Not when the proxy has just been found down, so a stopped proxy app fails quickly.
        val now = System.currentTimeMillis()
        val justDown = downAt > lastOkAt && now - downAt < 10_000
        val end = if (isLoopback(ep.address) && !justDown) now + RELOAD_GRACE_MS else now
        var ch: SocketChannel
        while (true) {
            ch = newChannel(track)
            try {
                ch.socket().connect(ep, PROXY_CONNECT_MS)
                break
            } catch (e: IOException) {
                Engine.closeQuietly(ch)
                if (e is java.net.ConnectException && System.currentTimeMillis() + RELOAD_RETRY_MS < end) {
                    Thread.sleep(RELOAD_RETRY_MS)
                    continue
                }
                throw ProxyDown(e)
            }
        }
        // Compare with what this very connection found, not the shared field another thread may be writing.
        val owner = try { learnProxyUid(ch) } catch (_: Exception) { null } ?: proxyUid
        if (uid == owner) {
            Engine.closeQuietly(ch)
            throw IsProxyApp()
        }
        return ch
    }

    /**
     * Opens a TCP connection to [dst] for [uid]. Through the proxy, the destination is sent as [name]
     * when known (so the proxy app can route by domain), otherwise as the IP. [track] gets the channel
     * early so a kill can close it.
     */
    fun openTcp(dst: InetSocketAddress, uid: Int, timeoutMs: Int, name: String? = null, handshakeMs: Long = 0,
                track: (SocketChannel) -> Unit): Opened {
        if (proxiedTo(uid, dst.address) && !isProxyEndpoint(dst)) {
            val c = cfg
            try {
                val ch = proxyChannel(uid, track)
                try {
                    val target = if (name != null) InetSocketAddress.createUnresolved(name, dst.port) else dst
                    val connectMs = if (handshakeMs > 0) handshakeMs else HANDSHAKE_MS
                    when (c.type) {
                        // The reply comes once the proxy reached the destination (Tor: seconds).
                        ProxyType.HTTP -> withDeadline(ch, connectMs) { HttpConnect.connect(ch, c.user, c.pass, target) }
                        else -> {
                            greet(ch, c, connectMs)
                            withDeadline(ch, connectMs) { Socks5.connectRequest(ch, target) }
                        }
                    }
                } catch (e: Exception) {
                    Engine.closeQuietly(ch)
                    throw e
                }
                lastOkAt = System.currentTimeMillis()
                return Opened(ch, true)
            } catch (e: IsProxyApp) {
                // fall through to a direct connection
            } catch (e: ProxyDown) {
                noteError("прокси недоступен: ${e.cause?.message ?: "нет соединения"}", down = true)
                if (!c.directIfDown) throw e
            } catch (e: ProxyException) {
                // The proxy is up but refused: the destination is unreachable through it. Never fall back.
                // No reply code (not a proxy, login refused) or HTTP 407 means every connection fails.
                if (e.code !in 3..6) noteError(e.message ?: "ошибка прокси", down = e.code == -1 || e.code == 407)
                throw e
            }
        }
        return Opened(openTcpDirect(dst, timeoutMs, track), false)
    }

    /** Plain protected TCP connection, never through the proxy. */
    fun openTcpDirect(dst: InetSocketAddress, timeoutMs: Int, track: (SocketChannel) -> Unit): SocketChannel {
        val ch = newChannel(track)
        try {
            ch.socket().connect(dst, timeoutMs)
        } catch (e: Exception) {
            Engine.closeQuietly(ch)
            throw e
        }
        return ch
    }

    /** Opens a UDP path to [dst]; null means the datagrams must be dropped (proxy without UDP / down). */
    fun openUdp(dst: InetSocketAddress, uid: Int): UdpPath? {
        if (proxiedTo(uid, dst.address)) {
            val c = cfg
            if (c.type == ProxyType.SOCKS5 && !udpUnsupported) {
                var ctl: SocketChannel? = null
                var dc: DatagramChannel? = null
                try {
                    val ctlCh = proxyChannel(uid) {}
                    ctl = ctlCh
                    val relay = try {
                        greet(ctlCh, c, HANDSHAKE_MS)
                        withDeadline(ctlCh, HANDSHAKE_MS) { Socks5.udpAssociateRequest(ctlCh, proxyEndpoint()) }
                    } catch (e: ProxyException) {
                        // Only an explicit refusal of the command means "no UDP"; a restart or timeout does not.
                        if (e.code == 7 || e.code == 1 || e.code == 2) udpUnsupportedAt = System.currentTimeMillis()
                        throw e
                    }
                    val d = DatagramChannel.open()
                    dc = d
                    if (!host.protect(d.socket())) throw IOException("protect failed")
                    d.connect(relay)
                    lastOkAt = System.currentTimeMillis()
                    return UdpPath(d, ctlCh, Socks5.udpHeader(dst.address, dst.port))
                } catch (e: IsProxyApp) {
                    // the proxy app's own UDP goes directly
                    Engine.closeQuietly(ctl)
                    return directUdp(dst)
                } catch (e: ProxyDown) {
                    noteError("прокси недоступен: ${e.cause?.message ?: "нет соединения"}", down = true)
                    if (!c.directIfDown) return null
                } catch (e: Exception) {
                    Engine.closeQuietly(dc)
                    Engine.closeQuietly(ctl)
                    if (e !is ProxyException && e !is DeadlineException) noteError("UDP через прокси: ${e.message ?: e.javaClass.simpleName}")
                    if (!(udpUnsupported && c.udpDirect)) return null
                }
            } else if (!c.udpDirect) {
                return null
            }
        }
        return directUdp(dst)
    }

    /** Plain protected UDP path, never through the proxy. */
    fun directUdp(dst: InetSocketAddress): UdpPath {
        val dc = DatagramChannel.open()
        try {
            if (!host.protect(dc.socket())) throw IOException("protect failed")
            dc.connect(dst)
        } catch (e: Exception) {
            Engine.closeQuietly(dc)
            throw e
        }
        return UdpPath(dc, null, null)
    }

    /** Why [openUdp] returned null, for the journal. */
    fun udpDropReason(): String = when {
        cfg.type == ProxyType.HTTP -> "HTTP-прокси не передаёт UDP"
        udpUnsupported -> "прокси не передаёт UDP"
        else -> "прокси недоступен"
    }

    /** True when DNS queries of [uid] are resolved through the proxy. */
    fun dnsViaProxy(uid: Int): Boolean = cfg.enabled && cfg.dnsViaProxy && proxied(uid)

    /**
     * Resolves one DNS query (wire format) through the proxy: over the pipelined connection, then
     * (resolvers that answer one query per connection, a broken pipe) over a dedicated one, about
     * [DNS_TOTAL_MS] in all.
     */
    fun dnsQuery(q: ByteArray, off: Int, len: Int): ByteArray {
        val start = System.nanoTime()
        return try {
            // Short enough to leave time for the fallback before the system resolver gives up (~5 s).
            dnsPipe.query(q, off, len, DNS_PIPE_TIMEOUT_MS)
        } catch (e: IOException) {
            val left = DNS_TOTAL_MS - (System.nanoTime() - start) / 1_000_000
            dnsQueryOnce(InetSocketAddress(host.resolve(cfg.dnsServer), 53), q, off, len, maxOf(left, DNS_MIN_ONCE_MS))
        }
    }

    /** One DNS-over-TCP query to [server] through the proxy, on its own connection, within [budgetMs]. */
    fun dnsQueryOnce(server: InetSocketAddress, q: ByteArray, off: Int, len: Int, budgetMs: Long = DNS_ONCE_MS): ByteArray {
        val deadline = System.nanoTime() + budgetMs * 1_000_000
        val o = openTcp(server, UID_DNS, PROXY_CONNECT_MS, handshakeMs = budgetMs) {}
        try {
            val left = maxOf(1L, (deadline - System.nanoTime()) / 1_000_000)
            return withDeadline(o.ch, left) { DnsTcp.query(o.ch, q, off, len) }
        } catch (e: DeadlineException) {
            // The proxy took the request, but no answer came back through the tunnel.
            throw IOException("DNS-сервер ${server.address.hostAddress} не ответил через туннель за ${(budgetMs + 999) / 1000} с", e)
        } finally {
            Engine.closeQuietly(o.ch)
        }
    }

    /**
     * The SOCKS5 greeting (and login). Any working proxy answers it at once, before any remote
     * connection is involved: a proxy app on this phone that stays silent here is frozen or stuck, so
     * it is given up on sooner than one across the network, and said so.
     */
    private fun greet(ch: SocketChannel, c: ProxyConfig, limitMs: Long) {
        val local = try { isLoopback(proxyEndpoint().address) } catch (_: Exception) { false }
        try {
            withDeadline(ch, if (local) minOf(limitMs, LOCAL_HANDSHAKE_MS) else limitMs) { Socks5.handshake(ch, c.user, c.pass) }
        } catch (e: DeadlineException) {
            noteSilentProxy()
            throw e
        }
    }

    /** The proxy accepted the connection but did not answer the greeting. */
    private fun noteSilentProxy() {
        val local = try { isLoopback(proxyEndpoint().address) } catch (_: Exception) { false }
        noteError(if (local) "${host.proxyAppLabel() ?: "приложение прокси"} принимает соединения, но не отвечает: " +
            "похоже, система его усыпила или оно зависло"
        else "прокси не ответил за ${HANDSHAKE_MS / 1000} с", down = true)
    }

    fun close() = dnsPipe.close()

    private fun noteError(msg: String, down: Boolean = false) {
        lastError = msg
        lastErrorAt = System.currentTimeMillis()
        if (down) downAt = lastErrorAt
        noteEvent(msg)
    }

    /** A proxy problem worth showing later; repeats within a minute are counted, not listed. */
    class Event(val at: Long, val msg: String) {
        @Volatile var count = 1
        @Volatile var lastAt = at
    }

    private val events = ArrayDeque<Event>()

    fun noteEvent(msg: String) {
        val now = System.currentTimeMillis()
        synchronized(events) {
            val last = events.lastOrNull()
            if (last != null && last.msg == msg && now - last.lastAt < 60_000) {
                last.count++
                last.lastAt = now
            } else {
                events.addLast(Event(now, msg))
                if (events.size > MAX_EVENTS) events.removeFirst()
            }
        }
    }

    /** Recent proxy problems, newest first. */
    // Not reversed(): with compileSdk 35 that can bind to java.util.List.reversed(), absent before Android 15.
    fun recentEvents(): List<Event> = synchronized(events) { ArrayList(events).apply { reverse() } }

    /** The proxy itself could not be reached. */
    class ProxyDown(cause: IOException) : IOException(cause)

    companion object {
        const val UID_UNKNOWN = -2
        /** No proxy app found. Distinct from -1 (Process.INVALID_UID: owner of a flow unknown). */
        const val UID_NONE = -3
        /** Pseudo-UID for our own DNS lookups through the proxy. */
        const val UID_DNS = -100
        const val PROXY_CONNECT_MS = 5_000
        const val HANDSHAKE_MS = 20_000L
        const val LOCAL_HANDSHAKE_MS = 6_000L
        const val DNS_ONCE_MS = 4_000L
        const val DNS_TOTAL_MS = 6_000L
        const val DNS_MIN_ONCE_MS = 1_500L
        const val DNS_TIMEOUT_MS = 8_000L
        const val DNS_PIPE_TIMEOUT_MS = 3_000L
        const val MAX_EVENTS = 20
        const val RELOAD_GRACE_MS = 3_000L
        const val RELOAD_RETRY_MS = 300L
        const val PROXY_UID_TTL_MS = 60_000L
        const val PROXY_UID_RETRY_MS = 3_000L
        const val UDP_RECHECK_MS = 300_000L

        fun ipOrNull(s: String): InetAddress? {
            val t = s.trim().removePrefix("[").removeSuffix("]")
            val looksIp = t.isNotEmpty() && (t.contains(':') || t.all { it.isDigit() || it == '.' })
            return if (looksIp) try { InetAddress.getByName(t) } catch (_: Exception) { null } else null
        }
    }
}
