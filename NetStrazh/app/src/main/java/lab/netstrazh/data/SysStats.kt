package lab.netstrazh.data

import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.net.ConnectivityManager
import android.os.Process

/** System-wide per-app traffic (NetworkStatsManager) and app activity (UsageStatsManager). */
object SysStats {
    class Usage(val uid: Int) {
        var rxWifi = 0L
        var txWifi = 0L
        var rxMobile = 0L
        var txMobile = 0L
        val rx get() = rxWifi + rxMobile
        val tx get() = txWifi + txMobile
        val total get() = rx + tx
    }

    class AppState(val lastUsed: Long, val onScreen: Boolean, val service: Boolean)

    fun hasUsageAccess(ctx: Context): Boolean {
        val ops = ctx.getSystemService(AppOpsManager::class.java)
        val mode = ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        return mode == AppOpsManager.MODE_ALLOWED
    }

    /** Traffic per UID between [start] and [end]. */
    @Suppress("DEPRECATION")
    fun traffic(ctx: Context, start: Long, end: Long): Map<Int, Usage> {
        val nsm = ctx.getSystemService(NetworkStatsManager::class.java)
        val out = HashMap<Int, Usage>()
        for (type in intArrayOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)) {
            val stats = try {
                nsm.querySummary(type, null, start, end)
            } catch (_: Exception) {
                null
            } ?: continue
            val b = NetworkStats.Bucket()
            try {
                while (stats.hasNextBucket()) {
                    stats.getNextBucket(b)
                    val u = out.getOrPut(b.uid) { Usage(b.uid) }
                    if (type == ConnectivityManager.TYPE_WIFI) {
                        u.rxWifi += b.rxBytes
                        u.txWifi += b.txBytes
                    } else {
                        u.rxMobile += b.rxBytes
                        u.txMobile += b.txBytes
                    }
                }
            } finally {
                stats.close()
            }
        }
        return out
    }

    /** Per-package: last time used, whether it is on screen now, whether it runs a foreground service. */
    fun appStates(ctx: Context): Map<String, AppState> {
        val usm = ctx.getSystemService(UsageStatsManager::class.java)
        val now = System.currentTimeMillis()
        val last = HashMap<String, Long>()
        try {
            for (s in usm.queryUsageStats(UsageStatsManager.INTERVAL_BEST, now - 30L * 86_400_000L, now)) {
                val t = maxOf(s.lastTimeUsed, s.lastTimeForegroundServiceUsed)
                if (t > (last[s.packageName] ?: 0L)) last[s.packageName] = t
            }
        } catch (_: Exception) {
        }
        val resumed = HashMap<String, MutableSet<String>>()
        val services = HashMap<String, MutableSet<String>>()
        try {
            val ev = usm.queryEvents(now - 3L * 86_400_000L, now)
            val e = UsageEvents.Event()
            while (ev.hasNextEvent()) {
                ev.getNextEvent(e)
                val pkg = e.packageName ?: continue
                val cls = e.className ?: ""
                when (e.eventType) {
                    UsageEvents.Event.ACTIVITY_RESUMED -> resumed.getOrPut(pkg) { HashSet() }.add(cls)
                    UsageEvents.Event.ACTIVITY_PAUSED, UsageEvents.Event.ACTIVITY_STOPPED ->
                        resumed[pkg]?.remove(cls)
                    UsageEvents.Event.FOREGROUND_SERVICE_START -> services.getOrPut(pkg) { HashSet() }.add(cls)
                    UsageEvents.Event.FOREGROUND_SERVICE_STOP -> services[pkg]?.remove(cls)
                }
                if (e.timeStamp > (last[pkg] ?: 0L) &&
                    (e.eventType == UsageEvents.Event.ACTIVITY_RESUMED || e.eventType == UsageEvents.Event.ACTIVITY_PAUSED)) {
                    last[pkg] = e.timeStamp
                }
            }
        } catch (_: Exception) {
        }
        val out = HashMap<String, AppState>()
        val pkgs = HashSet<String>().apply { addAll(last.keys); addAll(resumed.keys); addAll(services.keys) }
        for (p in pkgs) {
            out[p] = AppState(last[p] ?: 0L, resumed[p]?.isNotEmpty() == true, services[p]?.isNotEmpty() == true)
        }
        return out
    }
}
