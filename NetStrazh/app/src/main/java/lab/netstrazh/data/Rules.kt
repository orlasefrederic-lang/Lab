package lab.netstrazh.data

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import lab.netstrazh.vpn.NetType
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Firewall rules per package: block on Wi-Fi, block on mobile data, or exclude from the VPN entirely.
 * Rules are applied by app id (uid % 100000), so they also cover work profiles and app clones.
 */
object Rules {
    const val WIFI = 1
    const val MOBILE = 2
    const val EXCLUDE = 4
    const val BLOCK_ALL = WIFI or MOBILE

    private lateinit var sp: SharedPreferences
    private lateinit var pm: PackageManager
    @Volatile private var byPkg: Map<String, Int> = emptyMap()
    @Volatile private var byAppId: Map<Int, Int> = emptyMap()
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    fun init(ctx: Context) {
        sp = ctx.getSharedPreferences("rules", Context.MODE_PRIVATE)
        pm = ctx.packageManager
        reload()
    }

    @Synchronized fun reload() {
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

    fun flags(pkg: String): Int = byPkg[pkg] ?: 0

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

    fun addListener(l: () -> Unit) = listeners.add(l)
    fun removeListener(l: () -> Unit) = listeners.remove(l)
}
