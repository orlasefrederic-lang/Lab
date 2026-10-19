package lab.netstrazh

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.os.Build
import android.os.StrictMode
import lab.netstrazh.data.Apps
import lab.netstrazh.data.Db
import lab.netstrazh.data.Rules
import lab.netstrazh.vpn.ProxyConfig
import lab.netstrazh.vpn.ProxyType

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        // The VPN service sets up its local sockets from the main thread.
        StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder(StrictMode.getThreadPolicy()).permitNetwork().build())
        Prefs.init(this)
        Db.init(this)
        Rules.init(this)
        Apps.init(this)
        // Installed/updated apps get new UIDs: refresh the rule and name caches.
        val f = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                Rules.reload()
                Apps.invalidate()
            }
        }
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(r, f, Context.RECEIVER_NOT_EXPORTED) else registerReceiver(r, f)
    }
}

object Prefs {
    private lateinit var sp: SharedPreferences

    fun init(ctx: Context) {
        sp = ctx.getSharedPreferences("prefs", Context.MODE_PRIVATE)
    }

    /** Whether the user wants protection on (restored after reboot). */
    var enabled: Boolean
        get() = sp.getBoolean("enabled", false)
        set(v) = sp.edit().putBoolean("enabled", v).apply()

    var lastTab: Int
        get() = sp.getInt("tab", 0)
        set(v) = sp.edit().putInt("tab", v).apply()

    var trafficPeriod: Int
        get() = sp.getInt("period", 0)
        set(v) = sp.edit().putInt("period", v).apply()

    var showSystemApps: Boolean
        get() = sp.getBoolean("sys", false)
        set(v) = sp.edit().putBoolean("sys", v).apply()

    /** Route IPv6 through the VPN too (experimental). Off: the VPN is IPv4-only and Android blocks IPv6 for apps. */
    var ipv6: Boolean
        get() = sp.getBoolean("ipv6", false)
        set(v) = sp.edit().putBoolean("ipv6", v).apply()

    /** Upstream proxy for working together with another VPN app (in its proxy-only mode). */
    var proxy: ProxyConfig
        get() = ProxyConfig(
            type = runCatching { ProxyType.valueOf(sp.getString("px_type", null) ?: "NONE") }.getOrDefault(ProxyType.NONE),
            host = sp.getString("px_host", null) ?: "127.0.0.1",
            port = sp.getInt("px_port", 0),
            user = sp.getString("px_user", null) ?: "",
            pass = sp.getString("px_pass", null) ?: "",
            dnsViaProxy = sp.getBoolean("px_dns", true),
            dnsServer = sp.getString("px_dns_server", null) ?: "1.1.1.1",
            udpDirect = sp.getBoolean("px_udp_direct", false),
            directIfDown = sp.getBoolean("px_direct_if_down", false),
        )
        set(v) = sp.edit()
            .putString("px_type", v.type.name)
            .putString("px_host", v.host)
            .putInt("px_port", v.port)
            .putString("px_user", v.user)
            .putString("px_pass", v.pass)
            .putBoolean("px_dns", v.dnsViaProxy)
            .putString("px_dns_server", v.dnsServer)
            .putBoolean("px_udp_direct", v.udpDirect)
            .putBoolean("px_direct_if_down", v.directIfDown)
            .apply()

    /** When another VPN (or the user in system settings) last switched us off. */
    var revokedAt: Long
        get() = sp.getLong("revoked_at", 0L)
        set(v) = sp.edit().putLong("revoked_at", v).apply()

    var logDays: Int
        get() = sp.getInt("log_days", 7)
        set(v) = sp.edit().putInt("log_days", v).apply()
}
