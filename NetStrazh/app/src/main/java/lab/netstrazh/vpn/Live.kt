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
    @Volatile var blocked = false
    /** [VIA_PROXY] when the traffic went through the upstream proxy. */
    @Volatile var via = ""
    /** Why the connection failed or was dropped, shown in the journal. */
    @Volatile var note: String? = null
    /** Closes the underlying sockets; set by the relay. */
    @Volatile var killer: (() -> Unit)? = null
    internal val logged = AtomicBoolean(false)

    // Each direction is written by a single thread, so plain volatile increments are safe.
    fun addTx(n: Long) {
        tx += n
        Live.stat(uid).tx.addAndGet(n)
    }

    fun addRx(n: Long) {
        rx += n
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

/** Remembers which host name an IP address was resolved from (per app and globally). */
object DnsCache {
    private val map = object : LinkedHashMap<String, String>(2048, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean = size > 16384
    }

    @Synchronized fun put(uid: Int, ip: String, host: String) {
        map["$uid|$ip"] = host
        map[ip] = host
    }

    @Synchronized fun get(uid: Int, ip: String): String? = map["$uid|$ip"] ?: map[ip]
}
