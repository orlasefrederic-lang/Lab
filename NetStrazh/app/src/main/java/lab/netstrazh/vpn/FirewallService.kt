package lab.netstrazh.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import lab.netstrazh.Prefs
import lab.netstrazh.R
import lab.netstrazh.data.Db
import lab.netstrazh.data.Rules
import lab.netstrazh.ui.MainActivity
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

class FirewallService : VpnService(), EngineHost {
    private var engine: Engine? = null
    private lateinit var net: NetMonitor
    private lateinit var cm: ConnectivityManager
    private val main = Handler(Looper.getMainLooper())
    private var lastType = NetType.NONE
    private val rulesListener: () -> Unit = { main.post { onRulesChanged() } }

    private val netChanged = Runnable { onNetworkChanged() }

    override fun onCreate() {
        super.onCreate()
        instance = this
        cm = getSystemService(ConnectivityManager::class.java)
        net = NetMonitor(this) {
            // Tell the system the real underlying network right away (HyperOS applies its per-app
            // Wi-Fi/mobile rules based on it); rules and restarts are debounced.
            main.post { if (engine != null) net.best?.let { setUnderlyingNetworks(arrayOf(it)) } }
            main.removeCallbacks(netChanged)
            main.postDelayed(netChanged, 1000)
        }
        Rules.addListener(rulesListener)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            Prefs.enabled = false
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        startForegroundCompat()
        if (prepare(this) != null) {
            Log.w(Engine.TAG, "VPN permission missing")
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        Prefs.enabled = true
        if (engine == null) startEngine()
        return START_STICKY
    }

    override fun onRevoke() {
        // The user disconnected us in system settings or another VPN took over.
        Prefs.enabled = false
        Prefs.revokedAt = System.currentTimeMillis()
        shutdown()
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        Rules.removeListener(rulesListener)
        if (instance === this) instance = null
        super.onDestroy()
    }

    /**
     * Brings up the VPN interface and the engine. When an engine is already running (restart after a
     * rule or network change) the new interface is established first, so traffic never bypasses us.
     */
    private fun startEngine() {
        net.start()
        lastType = net.type
        val cfg = TunConfig(wantIpv6())
        val pfd = establishTun(cfg)
        if (pfd == null) {
            shutdown()
            stopSelf()
            return
        }
        stopEngine()
        Live.reset()
        val e = Engine(this, pfd, cfg)
        e.upstream.configure(Prefs.proxy)
        try {
            e.start()
        } catch (ex: Exception) {
            Log.e(Engine.TAG, "engine start failed", ex)
            e.stop()
            shutdown()
            stopSelf()
            return
        }
        engine = e
        running = true
        Prefs.revokedAt = 0L
        Db.pruneAsync()
        updateNotification()
    }

    private fun establishTun(cfg: TunConfig): ParcelFileDescriptor? {
        val b = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(TunConfig.MTU)
            .addAddress(TunConfig.T4, 24)
            // All unicast IPv4 except 224.0.0.0/3 (multicast & reserved), so local discovery keeps working.
            .addRoute("0.0.0.0", 1)
            .addRoute("128.0.0.0", 2)
            .addRoute("192.0.0.0", 3)
            .addDnsServer(TunConfig.DNS4)
            .setBlocking(false)
            .setConfigureIntent(mainIntent())
        if (cfg.v6) {
            b.addAddress(TunConfig.T6, 64)
            // All IPv6 except link-local fe80::/10 and multicast ff00::/8 (local discovery), like IPv4.
            // That includes NAT64 prefixes (IPv4-only hosts on IPv6-only mobile networks) and ULA.
            for ((a, n) in V6_ROUTES) b.addRoute(a, n)
        }
        b.setMetered(false)
        net.best?.let { b.setUnderlyingNetworks(arrayOf(it)) }
        appliedExcluded = Rules.excludedPackages()
        for (pkg in appliedExcluded) {
            try { b.addDisallowedApplication(pkg) } catch (_: Exception) {}
        }
        return try {
            b.establish()
        } catch (e: Exception) {
            Log.e(Engine.TAG, "establish failed", e)
            null
        }
    }

    private fun stopEngine() {
        val e = engine ?: return
        engine = null
        e.stop()
    }

    private fun shutdown() {
        main.removeCallbacks(netChanged)
        stopEngine()
        net.stop()
        running = false
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun restartEngine() {
        if (engine == null) return
        startEngine()
    }

    private fun onNetworkChanged() {
        val e = engine ?: return
        net.best?.let { setUnderlyingNetworks(arrayOf(it)) }
        if (wantIpv6() != e.cfg.v6) {
            restartEngine()
            return
        }
        if (net.type != lastType) {
            lastType = net.type
            e.enforceRules()
        }
    }

    private fun onRulesChanged() {
        val e = engine ?: return
        if (Rules.excludedPackages() != appliedExcluded) {
            restartEngine()
        } else {
            e.enforceRules()
            updateNotification()
        }
    }

    private fun wantIpv6(): Boolean = Prefs.ipv6 && net.hasIpv6

    /** Apps excluded from the VPN when the interface was established. */
    private var appliedExcluded: Set<String> = emptySet()

    // ------------------------------------------------------------ EngineHost

    override fun ownerUid(proto: Int, local: InetSocketAddress, remote: InetSocketAddress): Int =
        try { cm.getConnectionOwnerUid(proto, local, remote) } catch (_: Exception) { -1 }

    override fun netType(): NetType = net.type

    override fun upstreamDns(): InetAddress = net.upstreamDns()

    override val selfUid: Int = android.os.Process.myUid()

    override fun resolve(host: String): InetAddress {
        Upstream.ipOrNull(host)?.let { return it }
        if (host.equals("localhost", true)) return InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        // Resolve on the real network so the lookup does not loop through our own VPN.
        val n = net.best ?: throw java.net.UnknownHostException(host)
        return n.getAllByName(host).first()
    }

    /** Current upstream (proxy) state, for the UI. */
    val upstream: Upstream? get() = engine?.upstream

    override fun onEngineDied() {
        main.post {
            if (engine != null) restartEngine()
        }
    }

    // protect(Socket) / protect(DatagramSocket) are inherited from VpnService.
    override fun protect(s: Socket): Boolean = super.protect(s)
    override fun protect(s: DatagramSocket): Boolean = super.protect(s)

    // ------------------------------------------------------------ notification

    private fun mainIntent(): PendingIntent = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.channel_status), NotificationManager.IMPORTANCE_LOW))
        }
        val blocked = Rules.blockedPackages().size
        val stop = PendingIntent.getService(this, 1, Intent(this, FirewallService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(getString(R.string.notif_on))
            .setContentText(
                (if (blocked == 0) getString(R.string.notif_no_rules) else getString(R.string.notif_blocked, blocked)) +
                    if (Prefs.proxy.enabled) " · " + getString(R.string.notif_via_proxy) else ""
            )
            .setContentIntent(mainIntent())
            .setOngoing(true)
            .setShowWhen(false)
            .addAction(Notification.Action.Builder(null, getString(R.string.notif_stop), stop).build())
            .build()
    }

    private fun startForegroundCompat() {
        val n = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun updateNotification() {
        if (engine == null) return
        try {
            getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification())
        } catch (_: Exception) {
        }
    }

    companion object {
        const val ACTION_START = "lab.netstrazh.START"
        const val ACTION_STOP = "lab.netstrazh.STOP"
        private val V6_ROUTES = listOf(
            "::" to 1, "8000::" to 2, "c000::" to 3, "e000::" to 4, "f000::" to 5,
            "f800::" to 6, "fc00::" to 7, "fe00::" to 9, "fec0::" to 10,
        )
        private const val CHANNEL = "status"
        private const val NOTIF_ID = 1

        @Volatile var instance: FirewallService? = null
            private set
        @Volatile var running = false
            private set

        fun start(ctx: Context) {
            val i = Intent(ctx, FirewallService::class.java).setAction(ACTION_START)
            ctx.startForegroundService(i)
        }

        /** Applies changed proxy settings to the running engine. */
        fun applyProxy() {
            val s = instance ?: return
            s.main.post {
                s.engine?.applyProxyAsync { Prefs.proxy }
                s.updateNotification()
            }
        }

        /** Re-establishes the interface after a settings change (e.g. IPv6). */
        fun reconfigure() {
            val s = instance ?: return
            s.main.post { s.restartEngine() }
        }

        fun stop(ctx: Context) {
            Prefs.enabled = false
            val s = instance
            if (s != null) {
                s.shutdown()
                s.stopSelf()
            }
        }
    }
}
