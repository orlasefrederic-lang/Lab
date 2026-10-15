package lab.netstrazh.vpn

import lab.netstrazh.net.B
import lab.netstrazh.net.Ip

/** Identifies an app-side flow: source port + destination address/port (source address is always the TUN address). */
data class FlowKey(val v6: Boolean, val sport: Int, val a: Long, val b: Long, val dport: Int) {
    companion object {
        fun of(p: Ip): FlowKey {
            val o = p.dstOff
            return if (p.v6) FlowKey(true, p.srcPort, B.i64(p.buf, o), B.i64(p.buf, o + 8), p.dstPort)
            else FlowKey(false, p.srcPort, B.u32(p.buf, o), 0, p.dstPort)
        }
    }
}

class NatEntry(
    val natPort: Int,
    val key: FlowKey,
    val v6: Boolean,
    val srcPort: Int,
    val dstAddr: ByteArray,
    val dstPort: Int,
    val created: Long,
) {
    @Volatile var lastSeen = created
    @Volatile var accepted = false
    @Volatile var closedAt = 0L
}

/**
 * TCP NAT table. An app connection (T:sport -> D:dport) is rewritten to (P:natPort -> T:serverPort)
 * so that the kernel TCP stack terminates it on our local server socket; replies are mapped back.
 */
class NatTable(private val portMin: Int = 10000, private val portMax: Int = 65000) {
    private val byKey = HashMap<FlowKey, NatEntry>()
    private val byPort = arrayOfNulls<NatEntry>(65536)
    private var next = portMin
    private var count = 0

    @Synchronized fun get(k: FlowKey): NatEntry? = byKey[k]

    @Synchronized fun byPort(p: Int): NatEntry? = if (p in 0..65535) byPort[p] else null

    @Synchronized fun create(k: FlowKey, v6: Boolean, srcPort: Int, dstAddr: ByteArray, dstPort: Int, now: Long): NatEntry? {
        val span = portMax - portMin + 1
        for (i in 0 until span) {
            val p = next
            next = if (next >= portMax) portMin else next + 1
            if (byPort[p] == null) {
                val e = NatEntry(p, k, v6, srcPort, dstAddr, dstPort, now)
                byPort[p] = e
                byKey[k] = e
                count++
                return e
            }
        }
        return null
    }

    @Synchronized fun close(e: NatEntry, now: Long) {
        if (e.closedAt == 0L) e.closedAt = now
    }

    /** Drops entries closed long ago and SYNs that never reached the server socket. */
    @Synchronized fun sweep(now: Long): Int {
        var removed = 0
        for (p in portMin..portMax) {
            val e = byPort[p] ?: continue
            val dead = (e.closedAt != 0L && now - e.closedAt > CLOSED_GRACE_MS) ||
                (!e.accepted && now - e.created > UNACCEPTED_MS)
            if (dead) {
                byPort[p] = null
                if (byKey[e.key] === e) byKey.remove(e.key)
                count--
                removed++
            }
        }
        return removed
    }

    @Synchronized fun clear() {
        byKey.clear()
        java.util.Arrays.fill(byPort, null)
        count = 0
    }

    val size: Int @Synchronized get() = count

    companion object {
        const val CLOSED_GRACE_MS = 90_000L
        const val UNACCEPTED_MS = 60_000L
    }
}
