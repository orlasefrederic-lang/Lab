package lab.netstrazh.vpn

import android.system.OsConstants
import lab.netstrazh.net.DnsTcp
import lab.netstrazh.net.HttpConnect
import lab.netstrazh.net.ProxyException
import lab.netstrazh.net.Socks5
import lab.netstrazh.net.withDeadline
import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel

enum class ProxyType { NONE, SOCKS5, HTTP }

/** Where relayed traffic leaves the device: directly, or through another app's local proxy. */
class ProxyConfig(
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
    @Volatile private var udpUnsupportedAt = 0L
    @Volatile var lastError: String? = null
        private set
    @Volatile var lastErrorAt = 0L
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
            udpUnsupportedAt = 0L
            lastError = null
            lastErrorAt = 0L
            lastOkAt = 0L
        }
        dnsPipe.close()
    }

    /** A connection to the proxy itself (e.g. a LAN proxy) is never sent through that proxy. */
    private fun isProxyEndpoint(dst: InetSocketAddress): Boolean =
        try { proxyEndpoint() == dst } catch (_: Exception) { false }

    private fun proxyEndpoint(): InetSocketAddress {
        proxyAddr?.let { return it }
        val a = host.resolve(cfg.host)
        return InetSocketAddress(a, cfg.port).also { proxyAddr = it }
    }

    /** True when traffic of [uid] goes through the proxy. */
    fun proxied(uid: Int): Boolean {
        if (!cfg.enabled) return false
        ensureProxyUid()
        return uid != proxyUid
    }

    /**
     * Finds the app that listens on the proxy port. If that app's traffic also enters our VPN, relaying it
     * back into its own proxy would loop forever, so its connections go directly instead.
     */
    fun ensureProxyUid() {
        val now = System.currentTimeMillis()
        if (proxyUid != UID_UNKNOWN && now - proxyUidCheckedAt < PROXY_UID_TTL_MS) return
        synchronized(lock) {
            if (proxyUid != UID_UNKNOWN && now - proxyUidCheckedAt < PROXY_UID_TTL_MS) return
            if (proxyUid == UID_UNKNOWN && now - proxyUidCheckedAt < PROXY_UID_RETRY_MS) return
            proxyUidCheckedAt = now
            var ch: SocketChannel? = null
            try {
                val p = proxyEndpoint()
                ch = SocketChannel.open()
                host.protect(ch.socket())
                ch.socket().connect(p, 2000)
                val local = ch.socket().localSocketAddress as InetSocketAddress
                // The proxy's end of this connection: local = proxy endpoint, remote = our socket.
                val uid = host.ownerUid(OsConstants.IPPROTO_TCP, p, local)
                proxyUid = if (uid >= 0 && uid != host.selfUid) uid else UID_NONE
            } catch (e: Exception) {
                noteError("прокси недоступен: ${e.message ?: e.javaClass.simpleName}")
            } finally {
                Engine.closeQuietly(ch)
            }
        }
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

    /** Connects to the proxy and completes its greeting; the caller sends the command. */
    private fun proxyChannel(track: (SocketChannel) -> Unit): SocketChannel {
        val ch = newChannel(track)
        try {
            ch.socket().connect(proxyEndpoint(), PROXY_CONNECT_MS)
        } catch (e: IOException) {
            Engine.closeQuietly(ch)
            throw ProxyDown(e)
        }
        return ch
    }

    /** Opens a TCP connection to [dst] for [uid]. [track] gets the channel early so a kill can close it. */
    fun openTcp(dst: InetSocketAddress, uid: Int, timeoutMs: Int, track: (SocketChannel) -> Unit): Opened {
        if (proxied(uid) && !isProxyEndpoint(dst)) {
            val c = cfg
            try {
                val ch = proxyChannel(track)
                try {
                    withDeadline(ch, HANDSHAKE_MS) {
                        when (c.type) {
                            ProxyType.HTTP -> HttpConnect.connect(ch, c.user, c.pass, dst)
                            else -> Socks5.connect(ch, c.user, c.pass, dst)
                        }
                    }
                } catch (e: Exception) {
                    Engine.closeQuietly(ch)
                    throw e
                }
                lastOkAt = System.currentTimeMillis()
                return Opened(ch, true)
            } catch (e: ProxyDown) {
                noteError("прокси недоступен: ${e.cause?.message ?: "нет соединения"}")
                if (!c.directIfDown) throw e
            } catch (e: ProxyException) {
                // The proxy is up but refused: the destination is unreachable through it. Never fall back.
                if (e.code !in 3..6) noteError(e.message ?: "ошибка прокси")
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

    /** Opens a UDP path to [dst]; null means the datagrams must be dropped (proxy without UDP). */
    fun openUdp(dst: InetSocketAddress, uid: Int): UdpPath? {
        if (proxied(uid)) {
            val c = cfg
            if (c.type == ProxyType.SOCKS5 && !udpUnsupported) {
                var ctl: SocketChannel? = null
                try {
                    val ctlCh = proxyChannel {}
                    ctl = ctlCh
                    val relay = try {
                        withDeadline(ctlCh, HANDSHAKE_MS) { Socks5.udpAssociate(ctlCh, c.user, c.pass, proxyEndpoint()) }
                    } catch (e: IOException) {
                        // Reachable proxy that cannot associate: it has no UDP support.
                        udpUnsupportedAt = System.currentTimeMillis()
                        throw e
                    }
                    val dc = DatagramChannel.open()
                    if (!host.protect(dc.socket())) {
                        Engine.closeQuietly(dc)
                        throw IOException("protect failed")
                    }
                    dc.connect(relay)
                    lastOkAt = System.currentTimeMillis()
                    return UdpPath(dc, ctlCh, Socks5.udpHeader(dst.address, dst.port))
                } catch (e: ProxyDown) {
                    noteError("прокси недоступен: ${e.cause?.message ?: "нет соединения"}")
                    if (!c.directIfDown) return null
                } catch (e: IOException) {
                    Engine.closeQuietly(ctl)
                    if (!c.udpDirect) return null
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

    /** Resolves one DNS query (wire format) over a pipelined TCP connection through the proxy. */
    fun dnsQuery(q: ByteArray, off: Int, len: Int): ByteArray = try {
        dnsPipe.query(q, off, len, DNS_TIMEOUT_MS)
    } catch (e: IOException) {
        // Resolvers that answer only one query per connection: fall back to a dedicated connection.
        val o = openTcp(InetSocketAddress(host.resolve(cfg.dnsServer), 53), UID_DNS, PROXY_CONNECT_MS) {}
        try {
            withDeadline(o.ch, DNS_TIMEOUT_MS) { DnsTcp.query(o.ch, q, off, len) }
        } finally {
            Engine.closeQuietly(o.ch)
        }
    }

    fun close() = dnsPipe.close()

    private fun noteError(msg: String) {
        lastError = msg
        lastErrorAt = System.currentTimeMillis()
    }

    /** The proxy itself could not be reached. */
    class ProxyDown(cause: IOException) : IOException(cause)

    companion object {
        const val UID_UNKNOWN = -2
        const val UID_NONE = -1
        /** Pseudo-UID for our own DNS lookups through the proxy. */
        const val UID_DNS = -100
        const val PROXY_CONNECT_MS = 5_000
        const val HANDSHAKE_MS = 20_000L
        const val DNS_TIMEOUT_MS = 8_000L
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
