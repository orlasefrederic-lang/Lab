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
 */
object Rules {
    const val WIFI = 1
    const val MOBILE = 2
    const val EXCLUDE = 4
    const val BLOCK_ALL = WIFI or MOBILE

    /** Package key of host rules that apply to every app. */
    const val ALL = "*"

    private lateinit var sp: SharedPreferences
    private lateinit var hsp: SharedPreferences
    private lateinit var pm: PackageManager
    @Volatile private var byPkg: Map<String, Int> = emptyMap()
    @Volatile private var byAppId: Map<Int, Int> = emptyMap()
    @Volatile private var hostsByPkg: Map<String, Set<String>> = emptyMap()
    @Volatile private var hostsByAppId: Map<Int, Set<String>> = emptyMap()
    @Volatile private var globalHosts: Set<String> = emptySet()
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

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
        for ((pkg, f) in m) {
            val uid = try { pm.getApplicationInfo(pkg, 0).uid } catch (_: Exception) { continue }
            val id = uid % 100000
            ids[id] = (ids[id] ?: 0) or f
        }
        byAppId = ids
    }

    /** Host rules: keys "<package>|<host>" (or "*|<host>" for all apps), value true. */
    @Synchronized private fun reloadHosts() {
        blockDns = hsp.getBoolean(KEY_BLOCK_DNS, false)
        val pkgs = HashMap<String, MutableSet<String>>()
        val ids = HashMap<Int, MutableSet<String>>()
        val all = HashSet<String>()
        for ((k, v) in hsp.all) {
            if (v != true) continue
            val i = k.indexOf('|')
            if (i <= 0) continue
            val pkg = k.substring(0, i)
            val host = k.substring(i + 1)
            if (pkg == ALL) { all += host; continue }
            pkgs.getOrPut(pkg) { HashSet() } += host
            val uid = try { pm.getApplicationInfo(pkg, 0).uid } catch (_: Exception) { continue }
            ids.getOrPut(uid % 100000) { HashSet() } += host
        }
        hostsByPkg = pkgs
        hostsByAppId = ids
        globalHosts = all
    }

    fun flags(pkg: String): Int = byPkg[pkg] ?: 0

    fun setBlockDns(on: Boolean) {
        hsp.edit().putBoolean(KEY_BLOCK_DNS, on).apply()
        reload()
        for (l in listeners) l()
    }

    /** Blocks [host] and its subdomains for [pkg], or for every app when [pkg] is [ALL]. */
    fun setHostBlocked(pkg: String, host: String, blocked: Boolean) {
        val k = pkg + "|" + normalizeHost(host)
        if (blocked) hsp.edit().putBoolean(k, true).apply() else hsp.edit().remove(k).apply()
        reload()
        for (l in listeners) l()
    }

    fun blockedHosts(pkg: String): Set<String> = if (pkg == ALL) globalHosts else hostsByPkg[pkg] ?: emptySet()

    /** True when [host] (or a parent domain of it) is blocked for [uid] or for all apps. */
    fun hostBlocked(uid: Int, host: String?): Boolean =
        Hosts.blocked(host, if (uid >= 0) hostsByAppId[uid % 100000] else null, globalHosts)

    fun normalizeHost(h: String): String = Hosts.normalize(h)

    fun set(pkg: String, flags: Int) {
        if (flags == 0) sp.edit().remove(pkg).apply() else sp.edit().putInt(pkg, flags).apply()
        reload()
        for (l in listeners) l()
    }

    fun all(): Map<String, Int> = byPkg

    fun blockedPackages(): Set<String> = byPkg.filterValues { it and BLOCK_ALL != 0 }.keys

    fun excludedPackages(): Set<String> = byPkg.filterValues { it and EXCLUDE != 0 }.keys

    fun flagsForUid(uid: Int): Int = if (uid < 0) 0 else byAppId[uid % 100000] ?: 0

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
