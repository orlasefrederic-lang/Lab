package lab.netstrazh.data

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import java.util.concurrent.ConcurrentHashMap

/** Resolves UIDs and packages to human-readable app info. */
object Apps {
    class Info(
        val uid: Int,
        val label: String,
        /** Main package, null for system UIDs without a package. */
        val pkg: String?,
        val pkgs: List<String>,
        val system: Boolean,
        val hasInternet: Boolean = true,
    ) {
        val userId: Int get() = if (uid >= 0) uid / 100000 else 0
    }

    private lateinit var ctx: Context
    private lateinit var pm: PackageManager
    private val byUid = ConcurrentHashMap<Int, Info>()
    private val icons = ConcurrentHashMap<String, Drawable>()

    private val special = mapOf(
        -1 to "Неизвестно",
        0 to "Ядро / root",
        1000 to "Система Android",
        1001 to "Телефония (radio)",
        1002 to "Bluetooth",
        1010 to "Wi-Fi (система)",
        1013 to "Медиасервер",
        1019 to "DRM",
        1020 to "mDNS",
        1021 to "GPS",
        1051 to "DNS-резолвер",
        1052 to "DNS (точка доступа)",
        1073 to "Сетевой стек",
        2000 to "Shell (adb)",
        -4 to "Удалённые приложения",
        -5 to "Точка доступа (раздача)",
    )

    fun init(c: Context) {
        ctx = c.applicationContext
        pm = ctx.packageManager
    }

    fun invalidate() {
        byUid.clear()
    }

    fun forUid(uid: Int): Info = byUid.getOrPut(uid) { resolve(uid) }

    private fun resolve(uid: Int): Info {
        special[uid]?.let { return Info(uid, it, if (uid == 1000) "android" else null, emptyList(), true) }
        val appId = if (uid >= 0) uid % 100000 else uid
        val userId = if (uid >= 0) uid / 100000 else 0
        val suffix = when (userId) {
            0 -> ""
            999 -> " (двойник)"
            else -> " (профиль $userId)"
        }
        special[appId]?.let { return Info(uid, it + suffix, null, emptyList(), true) }
        if (appId in 99000..99999) return Info(uid, "Изолированный процесс$suffix", null, emptyList(), true)
        val pkgs = (try { pm.getPackagesForUid(appId) } catch (_: Exception) { null })?.toList() ?: emptyList()
        if (pkgs.isEmpty()) {
            val name = try { pm.getNameForUid(appId) } catch (_: Exception) { null }
            return Info(uid, (name ?: "UID $uid") + suffix, null, emptyList(), appId < 10000)
        }
        // Prefer a package with a real label (not just its package name).
        val infos = pkgs.mapNotNull { p ->
            try { pm.getApplicationInfo(p, 0).let { it to it.loadLabel(pm).toString() } } catch (_: Exception) { null }
        }
        if (infos.isEmpty()) return Info(uid, pkgs[0] + suffix, pkgs[0], pkgs, false)
        val (ai, bestLabel) = infos.firstOrNull { it.second != it.first.packageName } ?: infos[0]
        val more = if (pkgs.size > 1) " +${pkgs.size - 1}" else ""
        return Info(uid, bestLabel + more + suffix, ai.packageName, pkgs, ai.flags and ApplicationInfo.FLAG_SYSTEM != 0)
    }

    fun icon(pkg: String?): Drawable? {
        if (pkg == null) return null
        icons[pkg]?.let { return it }
        val d = try { pm.getApplicationIcon(pkg) } catch (_: Exception) { null } ?: return null
        icons[pkg] = d
        return d
    }

    fun forPackage(pkg: String): Info? = try {
        forUid(pm.getApplicationInfo(pkg, 0).uid)
    } catch (_: Exception) {
        null
    }

    /** All installed packages (one entry per package, label = app label). */
    fun installed(): List<Info> {
        var withPerms = true
        val list = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (_: Exception) {
            withPerms = false
            pm.getInstalledPackages(0)
        }
        val out = ArrayList<Info>(list.size)
        for (p: PackageInfo in list) {
            val ai = p.applicationInfo ?: continue
            val label = try { ai.loadLabel(pm).toString() } catch (_: Exception) { p.packageName }
            val internet = if (withPerms) p.requestedPermissions?.contains(Manifest.permission.INTERNET) ?: false else true
            out += Info(ai.uid, label, p.packageName, listOf(p.packageName), ai.flags and ApplicationInfo.FLAG_SYSTEM != 0, internet)
        }
        out.sortWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
        return out
    }

    fun labelForPackage(pkg: String): String = try {
        pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString()
    } catch (_: Exception) {
        pkg
    }
}
