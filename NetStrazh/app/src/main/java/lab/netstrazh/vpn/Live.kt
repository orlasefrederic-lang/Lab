package lab.netstrazh.vpn

import lab.netstrazh.data.Db
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** One connection (TCP), flow (UDP) or DNS query seen by the VPN. */
class Conn(
    val uid: Int,
    val proto: String,
    @Volatile var ip: String,
    val port: Int,
    @Volatile var host: String?,
    val net: String,
) {
    val id: Long = seq.incrementAndGet()
    val start: Long = System.currentTimeMillis()
    @Volatile var tx = 0L
        private set
    @Volatile var rx = 0L
        private set
    @Volatile var end = 0L
    /** Last time data moved either way. */
    @Volatile var lastAt = start
    @Volatile var blocked = false
    /** [VIA_PROXY] when the traffic went through the upstream proxy. */
    @Volatile var via = ""
    /** Why the connection failed or was dropped, shown in the journal. */
    @Volatile var note: String? = null
    /** [host] was sent by the app itself (TLS SNI / HTTP Host), not guessed from the DNS cache. */
    @Volatile var hostSniffed = false
    /** Closes the underlying sockets; set by the relay. */
    @Volatile var killer: (() -> Unit)? = null
    internal val logged = AtomicBoolean(false)

    // Each direction is written by a single thread, so plain volatile increments are safe.
    fun addTx(n: Long) {
        tx += n
        lastAt = System.currentTimeMillis()
        Live.stat(uid).tx.addAndGet(n)
    }

    fun addRx(n: Long) {
        rx += n
        lastAt = System.currentTimeMillis()
        Live.stat(uid).rx.addAndGet(n)
    }

    fun kill() {
        try { killer?.invoke() } catch (_: Exception) {}
    }

    companion object {
        private val seq = AtomicLong()
    }
}

const val VIA_PROXY = "proxy"

class UidStat {
    val tx = AtomicLong()
    val rx = AtomicLong()
    val conns = AtomicInteger()
    val blocked = AtomicInteger()
    @Volatile var lastActive = 0L
}

/** In-memory registry of live connections and per-app counters since the VPN started. */
object Live {
    val active = ConcurrentHashMap<Long, Conn>()
    val stats = ConcurrentHashMap<Int, UidStat>()
    @Volatile var startedAt = 0L

    fun stat(uid: Int): UidStat = stats.getOrPut(uid) { UidStat() }

    fun open(c: Conn): Conn {
        active[c.id] = c
        val s = stat(c.uid)
        s.conns.incrementAndGet()
        s.lastActive = c.start
        return c
    }

    fun close(c: Conn) {
        active.remove(c.id)
        if (c.logged.compareAndSet(false, true)) {
            c.end = System.currentTimeMillis()
            val s = stat(c.uid)
            s.lastActive = c.end
            if (c.blocked) s.blocked.incrementAndGet()
            Db.log(c)
        }
    }

    fun reset() {
        active.clear()
        stats.clear()
        startedAt = System.currentTimeMillis()
    }
}

/**
 * Remembers which host names an IP address was resolved from (per app and globally), newest first:
 * one IP often serves many sites (CDNs).
 */
object DnsCache {
    private const val NAMES = 4
    private val map = object : LinkedHashMap<String, Array<String>>(2048, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Array<String>>?): Boolean = size > 16384
    }

    @Synchronized fun put(uid: Int, ip: String, host: String) {
        add("$uid|$ip", host)
        add(ip, host)
    }

    private fun add(k: String, host: String) {
        val old = map[k]
        map[k] = if (old == null) arrayOf(host) else (listOf(host) + old.filter { it != host }).take(NAMES).toTypedArray()
    }

    /** The name [ip] was resolved from last (by [uid], or else by any app). */
    @Synchronized fun get(uid: Int, ip: String): String? = (map["$uid|$ip"] ?: map[ip])?.get(0)

    /** Only the names [uid] itself resolved for [ip], no fallback to other apps' lookups. */
    @Synchronized fun ownNames(uid: Int, ip: String): List<String> = map["$uid|$ip"]?.toList() ?: emptyList()

    /** True when [ip] was recently resolved from [host] (by [uid], or by any app). */
    @Synchronized fun has(uid: Int, ip: String, host: String): Boolean =
        map["$uid|$ip"]?.any { it.equals(host, true) } == true || map[ip]?.any { it.equals(host, true) } == true
}
