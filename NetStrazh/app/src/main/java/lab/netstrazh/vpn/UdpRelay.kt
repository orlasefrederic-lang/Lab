package lab.netstrazh.vpn

import android.system.OsConstants
import android.util.Log
import lab.netstrazh.net.Dns
import lab.netstrazh.net.Ip
import lab.netstrazh.net.PacketBuilder
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/** Relays UDP flows (incl. DNS to our fake resolver) through protected datagram channels. */
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
        @Volatile var ch: DatagramChannel? = null
        @Volatile var last = System.currentTimeMillis()
        val closed = AtomicBoolean(false)
    }

    private val selector: Selector = Selector.open()
    private val sessions = ConcurrentHashMap<FlowKey, Session>()
    private val pending = ConcurrentLinkedQueue<Session>()
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
        try { thread?.join(1500) } catch (_: InterruptedException) {}
        try { selector.close() } catch (_: Exception) {}
    }

    /** Called from the TUN reader thread for every UDP packet sent by an app. */
    fun fromApp(p: Ip) {
        if (p.l4Len < 8) return
        val t = if (p.v6) eng.cfg.t6 else eng.cfg.t4
        if (!p.srcIs(t)) return
        val n = p.udpPayloadLen
        if (n < 0) return
        val key = FlowKey.of(p)
        var s = sessions[key]
        if (s == null || s.closed.get()) s = create(p, key) ?: return
        s.last = System.currentTimeMillis()
        if (s.conn.blocked) return
        val ch = s.ch ?: return
        val off = p.udpPayloadOff
        if (s.isDns && s.conn.host == null) {
            Dns.parse(p.buf, off, n)?.qname?.let { s.conn.host = it }
        }
        try {
            ch.write(ByteBuffer.wrap(p.buf, off, n))
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
        val dstInet = InetAddress.getByAddress(dst)
        val srcInet = InetAddress.getByAddress(p.srcAddr())
        val uid = eng.host.ownerUid(OsConstants.IPPROTO_UDP, InetSocketAddress(srcInet, p.srcPort), InetSocketAddress(dstInet, dport))
        val ip = dstInet.hostAddress ?: "?"
        val conn = Conn(uid, if (isDns) "DNS" else "UDP", if (isDns) "" else ip, dport,
            if (isDns) null else DnsCache.get(uid, ip), eng.host.netType().label)
        val s = Session(key, p.v6, p.srcAddr(), p.srcPort, dst, dport, conn, isDns)
        Live.open(conn)
        sessions[key] = s
        // DNS is never blocked: the system resolver cache is shared between apps, so failing a
        // lookup for a blocked app could break other apps. Its connections are blocked instead.
        if (!isDns && eng.isBlocked(uid)) {
            conn.blocked = true
            return s
        }
        try {
            val ch = DatagramChannel.open()
            s.ch = ch
            conn.killer = { close(s) }
            if (!eng.host.protect(ch.socket())) throw IllegalStateException("protect failed")
            ch.configureBlocking(false)
            val target = if (isDns) InetSocketAddress(eng.host.upstreamDns(), 53) else InetSocketAddress(dstInet, dport)
            ch.connect(target)
            pending.add(s)
            selector.wakeup()
        } catch (e: Exception) {
            Log.w(Engine.TAG, "udp open failed: $ip:$dport", e)
            close(s)
            return null
        }
        return s
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
                val ch = s.ch ?: continue
                if (s.closed.get()) continue
                try {
                    ch.register(selector, SelectionKey.OP_READ, s)
                } catch (e: Exception) {
                    close(s)
                }
            }
            val keys = try { selector.selectedKeys() } catch (e: Exception) { break }
            val it = keys.iterator()
            while (it.hasNext()) {
                val k = it.next()
                it.remove()
                val s = k.attachment() as Session
                if (!k.isValid) continue
                val ch = s.ch ?: continue
                try {
                    while (true) {
                        bb.clear()
                        val n = ch.read(bb)
                        if (n <= 0) break
                        s.last = System.currentTimeMillis()
                        s.conn.addRx(n.toLong())
                        if (s.isDns) onDnsResponse(s, bb.array(), n)
                        val pk = PacketBuilder.udp(s.v6, s.remoteAddr, s.remotePort, s.appAddr, s.appPort, bb.array(), 0, n)
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

    private fun onDnsResponse(s: Session, b: ByteArray, n: Int) {
        val m = Dns.parse(b, 0, n) ?: return
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
        Engine.closeQuietly(s.ch)
        Live.close(s.conn)
    }

    fun sweep(now: Long) {
        for (s in sessions.values) {
            val idle = now - s.last
            val limit = when {
                s.isDns -> DNS_TIMEOUT_MS
                s.conn.blocked -> BLOCKED_TIMEOUT_MS
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

    private fun isMulticastOrBroadcast(a: ByteArray): Boolean =
        if (a.size == 4) (a[0].toInt() and 0xF0) == 0xE0 || (a[0].toInt() and 0xFF) == 255
        else (a[0].toInt() and 0xFF) == 0xFF

    companion object {
        const val UDP_TIMEOUT_MS = 120_000L
        const val DNS_TIMEOUT_MS = 20_000L
        const val BLOCKED_TIMEOUT_MS = 30_000L
    }
}
