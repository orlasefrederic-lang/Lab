package lab.netstrazh.data

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import lab.netstrazh.net.Hosts
import lab.netstrazh.vpn.NetType
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Firewall rules per package: block on Wi-Fi, block on mobile data, or exclude from the VPN entirely.
 * Rules are applied by app id (uid % 100000), so they also cover work profiles and app clones.
 * Besides, host names can be blocked for one app or for all, and DNS can be blocked with the app.
 * A UID without a package (the kernel, system services, connections Android could not attribute)
 * gets its rules under the key [keyForUid]; such a UID cannot be excluded from the VPN.
 */
object Rules {
    const val WIFI = 1
    const val MOBILE = 2
    const val EXCLUDE = 4
    const val BLOCK_ALL = WIFI or MOBILE

    /** Package key of host rules that apply to every app. */
    const val ALL = "*"

    /** Owner of a flow Android could not name (Process.INVALID_UID). */
    const val UNKNOWN_UID = -1
    private const val UID_PREFIX = "uid:"

    private lateinit var sp: SharedPreferences
    private lateinit var hsp: SharedPreferences
    private lateinit var pm: PackageManager
    @Volatile private var byPkg: Map<String, Int> = emptyMap()
    @Volatile private var byAppId: Map<Int, Int> = emptyMap()
    @Volatile private var hostsByPkg: Map<String, Set<String>> = emptyMap()
    @Volatile private var hostsByAppId: Map<Int, Set<String>> = emptyMap()
    @Volatile private var globalHosts: Set<String> = emptySet()
    @Volatile private var hostRuleList: List<HostRule> = emptyList()
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    /**
     * One host rule: [host] and its subdomains are blocked for [key] (a package, a [keyForUid] key, or
     * [ALL]). [since] is when the rule was made, 0 when that was not recorded yet (rules made before
     * version 3.5). [appId] is the app it applies to: null for [ALL] and for a package that is gone.
     */
    class HostRule(val key: String, val host: String, val since: Long, val appId: Int?) {
        /** True when the rule blocks [name]: the host itself or a subdomain of it. */
        fun covers(name: String): Boolean = name == host || name.endsWith(".$host")
    }

    /** DNS queries of a blocked app are answered "refused" instead of being resolved. */
    @Volatile var blockDns = false
        private set

    fun init(ctx: Context) {
        sp = ctx.getSharedPreferences("rules", Context.MODE_PRIVATE)
        hsp = ctx.getSharedPreferences("hostrules", Context.MODE_PRIVATE)
        pm = ctx.packageManager
        reload()
    }

    @Synchronized fun reload() {
        reloadHosts()
        val m = HashMap<String, Int>()
        for ((k, v) in sp.all) if (v is Int && v != 0) m[k] = v
        byPkg = m
        val ids = HashMap<Int, Int>()
        for ((key, f) in m) {
            val id = appIdOf(key) ?: continue
            ids[id] = (ids[id] ?: 0) or f
        }
        byAppId = ids
    }

    /**
     * Host rules: keys "<package>|<host>" (or "*|<host>" for all apps). The value is the time the rule
     * was made (a Long); rules made before that was recorded have the value true.
     */
    @Synchronized private fun reloadHosts() {
        blockDns = hsp.getBoolean(KEY_BLOCK_DNS, false)
        val pkgs = HashMap<String, MutableSet<String>>()
        val ids = HashMap<Int, MutableSet<String>>()
        val all = HashSet<String>()
        val list = ArrayList<HostRule>()
        for ((k, v) in hsp.all) {
            val since = when (v) {
                is Long -> v
                true -> 0L
                else -> continue
            }
            val i = k.indexOf('|')
            if (i <= 0 || i == k.length - 1) continue
            val pkg = k.substring(0, i)
            val host = k.substring(i + 1)
            if (pkg == ALL) {
                all += host
                list += HostRule(pkg, host, since, null)
                continue
            }
            pkgs.getOrPut(pkg) { HashSet() } += host
            val id = appIdOf(pkg)
            list += HostRule(pkg, host, since, id)
            if (id != null) ids.getOrPut(id) { HashSet() } += host
        }
        hostsByPkg = pkgs
        hostsByAppId = ids
        globalHosts = all
        hostRuleList = list
    }

    /** Rule key of a UID without a package. */
    fun keyForUid(uid: Int): String = UID_PREFIX + appId(uid)

    /** The UID a [keyForUid] key stands for, or null for a package key. */
    fun uidOfKey(key: String): Int? = if (key.startsWith(UID_PREFIX)) key.substring(UID_PREFIX.length).toIntOrNull() else null

    private fun appId(uid: Int): Int = if (uid < 0) uid else uid % 100000

    /** App id a rule key applies to; null for a package that is not installed. */
    private fun appIdOf(key: String): Int? = uidOfKey(key)
        ?: try { pm.getApplicationInfo(key, 0).uid % 100000 } catch (_: Exception) { null }

    fun flags(pkg: String): Int = byPkg[pkg] ?: 0

    fun setBlockDns(on: Boolean) {
        hsp.edit().putBoolean(KEY_BLOCK_DNS, on).apply()
        reload()
        for (l in listeners) l()
    }

    /** Blocks [host] and its subdomains for [pkg], or for every app when [pkg] is [ALL]. */
    fun setHostBlocked(pkg: String, host: String, blocked: Boolean) {
        val h = normalizeHost(host)
        if (h.isEmpty()) return
        val k = "$pkg|$h"
        // The time a rule was made stays with it: blocking the same address again does not reset it.
        if (!blocked) hsp.edit().remove(k).apply()
        else if (!hsp.contains(k)) hsp.edit().putLong(k, System.currentTimeMillis()).apply()
        reload()
        for (l in listeners) l()
    }

    fun blockedHosts(pkg: String): Set<String> = if (pkg == ALL) globalHosts else hostsByPkg[pkg] ?: emptySet()

    /** Every host rule: those of single apps and those for all. */
    fun hostRules(): List<HostRule> = hostRuleList

    /** The host rules [uid] is under: its own first, then those for all apps. */
    fun hostRulesFor(uid: Int): List<HostRule> {
        val id = appId(uid)
        val list = hostRuleList
        return list.filter { it.appId == id && it.key != ALL } + list.filter { it.key == ALL }
    }

    /** The rules that block [host] for [uid] (an address may be covered by more than one). */
    fun hostRulesCovering(uid: Int, host: String?): List<HostRule> {
        if (host.isNullOrEmpty()) return emptyList()
        val h = normalizeHost(host)
        return hostRulesFor(uid).filter { it.covers(h) }
    }

    /** True when [host] (or a parent domain of it) is blocked for [uid] or for all apps. */
    fun hostBlocked(uid: Int, host: String?): Boolean =
        Hosts.blocked(host, hostsByAppId[appId(uid)], globalHosts)

    fun normalizeHost(h: String): String = Hosts.normalize(h)

    fun set(pkg: String, flags: Int) {
        if (flags == 0) sp.edit().remove(pkg).apply() else sp.edit().putInt(pkg, flags).apply()
        reload()
        for (l in listeners) l()
    }

    fun all(): Map<String, Int> = byPkg

    fun blockedPackages(): Set<String> = byPkg.filterValues { it and BLOCK_ALL != 0 }.keys

    fun excludedPackages(): Set<String> = byPkg.filter { (k, f) -> f and EXCLUDE != 0 && uidOfKey(k) == null }.keys

    fun flagsForUid(uid: Int): Int = byAppId[appId(uid)] ?: 0

    fun isBlocked(uid: Int, net: NetType): Boolean {
        val f = flagsForUid(uid)
        if (f == 0) return false
        return when (net) {
            NetType.MOBILE -> f and MOBILE != 0
            NetType.NONE -> f and BLOCK_ALL != 0
            else -> f and WIFI != 0
        }
    }

    private const val KEY_BLOCK_DNS = "!block_dns"

    fun addListener(l: () -> Unit) = listeners.add(l)
    fun removeListener(l: () -> Unit) = listeners.remove(l)
}
