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
import lab.netstrazh.data.Apps
import lab.netstrazh.data.Db
import lab.netstrazh.data.ProxyApps
import lab.netstrazh.data.Rules
import lab.netstrazh.ui.MainActivity
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * The apps to keep out of the VPN: those the user marked ([byUser]), and the proxy app when it is to
 * go around us. Under Android's "Block connections without VPN" ([lockdown]) the proxy app is never
 * among them, not even when the user marked it by hand: Android cuts off every app outside the VPN,
 * so the proxy would lose its server, and every other app its internet with it. Inside the VPN its
 * traffic leaves directly all the same (the engine knows it by its UID).
 */
fun appsToExclude(p: ProxyConfig, byUser: Set<String>, lockdown: Boolean, self: String): Set<String> {
    val proxyApp = p.appPkg.takeIf { p.enabled && it.isNotEmpty() && it != self } ?: return byUser
    return when {
        lockdown -> byUser - proxyApp
        p.bypassApp -> byUser + proxyApp
        else -> byUser
    }
}

class FirewallService : VpnService(), EngineHost {
    private var engine: Engine? = null
    private lateinit var net: NetMonitor
    private lateinit var cm: ConnectivityManager
    private val main = Handler(Looper.getMainLooper())
    private var lastType = NetType.NONE
    private val rulesListener: () -> Unit = { main.post { onRulesChanged() } }

    private val netChanged = Runnable { onNetworkChanged() }
    /**
     * Android sometimes reports the VPN as up while it routes apps around it (seen on Android 10
     * after switching off and on, and after rebuilding the interface). So after every start, and
     * every minute, a probe from our own process (which, like every app, belongs inside the VPN)
     * must arrive through the interface; if not, the interface is built anew.
     */
    private val captureCheck = Runnable { checkCapture() }
    private val checker = java.util.concurrent.Executors.newSingleThreadExecutor { r -> Thread(r, "ns-capture").apply { isDaemon = true } }
    private var captureFailures = 0

    /**
     * Nothing tells a VPN service that the system's "always-on VPN" or "block connections without
     * VPN" was switched while it runs, so it asks every few seconds (two cheap calls): under the block
     * the proxy app has to be inside the VPN, without it outside. Looking once a minute, as before,
     * left the proxy app cut off from its server for up to that long.
     */
    private val modeCheck = object : Runnable {
        override fun run() {
            main.postDelayed(this, MODE_EVERY_MS)
            if (engine != null && excludedNow() != appliedExcluded) restartEngine()
        }
    }

    /** Our interface exists on the system's side: only then does Android say how it runs us. */
    private var tunUp = false

    /** The journal keeps only the configured number of days, also while the VPN runs for weeks. */
    private val prune = object : Runnable {
        override fun run() {
            Db.pruneAsync()
            main.postDelayed(this, PRUNE_EVERY_MS)
        }
    }

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
        // Started again while running (the app's switch, the system making us the always-on VPN): a
        // moment to look whether the system's block changed (see modeCheck).
        else if (excludedNow() != appliedExcluded) restartEngine()
        return START_STICKY
    }

    override fun onRevoke() {
        // The user disconnected us in system settings or another VPN took over. Either way we are not
        // the always-on VPN any more (while we are, Android lets nobody take over), so its block is
        // not ours to remember: the next start is an ordinary one.
        Prefs.enabled = false
        Prefs.revokedAt = System.currentTimeMillis()
        Prefs.lockdownSeen = false
        shutdown()
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        // A probe still waiting belongs to this instance only: end it with the service.
        checker.shutdownNow()
        Rules.removeListener(rulesListener)
        if (instance === this) instance = null
        super.onDestroy()
    }

    /**
     * Brings up the VPN interface and the engine. When an engine is already running (restart after a
     * rule or network change) the new interface is established before the old one is closed, so the
     * VPN is never down in between. How fast Android routes apps into the new one is up to Android:
     * the capture check watches that.
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
        main.removeCallbacks(prune)
        main.post(prune)
        updateNotification()
        main.removeCallbacks(captureCheck)
        main.postDelayed(captureCheck, CAPTURE_FIRST_MS)
        main.removeCallbacks(modeCheck)
        main.postDelayed(modeCheck, MODE_EVERY_MS)
    }

    private fun checkCapture() {
        val e = engine ?: return
        // Right after a start Android may need seconds to install the interface's routes (a loaded
        // system; until then apps go around us and nothing can hurry it): probe often, so the first
        // packet through is seen at once, but rebuild only if the routes do not come at all.
        val windowMs = if (captureVerifiedAt < Live.startedAt) CAPTURE_FIRST_WINDOW_MS else CAPTURE_WINDOW_MS
        try {
            checker.execute {
                val ok = try { probe(e, windowMs) } catch (_: InterruptedException) { return@execute }
                main.post { onCaptureChecked(e, ok) }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
        }
    }

    /** Sends a probe into the interface from this process every 200 ms; true once one arrived. */
    private fun probe(e: Engine, windowMs: Long): Boolean {
        val nonce = java.util.Random().nextLong().let { if (it == 0L) 1L else it }
        val payload = java.nio.ByteBuffer.allocate(Engine.PROBE_MAGIC.size + 8).put(Engine.PROBE_MAGIC).putLong(nonce).array()
        val dst = InetSocketAddress(InetAddress.getByName(TunConfig.DNS4), Engine.PROBE_PORT)
        val end = android.os.SystemClock.elapsedRealtime() + windowMs
        var nextSend = 0L
        while (true) {
            val now = android.os.SystemClock.elapsedRealtime()
            if (e.lastProbe == nonce) return true
            if (now >= end) return false
            if (now >= nextSend) {
                nextSend = now + PROBE_EVERY_MS
                try {
                    DatagramSocket().use { s -> s.send(DatagramPacket(payload, payload.size, dst)) }
                } catch (_: Exception) {
                }
            }
            Thread.sleep(20)
        }
    }

    private fun onCaptureChecked(e: Engine, ok: Boolean) {
        if (engine !== e) return // restarted meanwhile; the new engine has its own check
        if (ok) {
            captureFailures = 0
            // The notification says "checking" until this engine's first probe arrived.
            val first = captureVerifiedAt < Live.startedAt
            captureVerifiedAt = System.currentTimeMillis()
            if (captureBroken || first) {
                captureBroken = false
                updateNotification()
            }
            main.postDelayed(captureCheck, CAPTURE_EVERY_MS)
            return
        }
        captureFailures++
        captureRecoveries++
        Log.w(Engine.TAG, "capture probe lost ($captureFailures): Android routes around the VPN interface")
        if (captureFailures <= MAX_CAPTURE_RESTARTS) {
            // A new interface while the old one is still up: Android installs fresh routing for it.
            restartEngine()
        } else {
            captureBroken = true
            updateNotification()
            main.postDelayed(captureCheck, CAPTURE_EVERY_MS)
        }
    }

    /**
     * Establishes the interface. The first one after a start is made for the system's block as it
     * was last seen: Android tells how things really are only once an interface is up (see
     * [readSystemMode]). If that turns out different, the interface is established again at once,
     * with the right apps in it, instead of leaving the proxy app cut off until the next check.
     */
    private fun establishTun(cfg: TunConfig): ParcelFileDescriptor? {
        val known = tunUp
        val first = establishFor(cfg, excludedNow()) ?: return null
        tunUp = true
        if (known) return first
        val wanted = excludedNow()
        if (wanted == appliedExcluded) return first
        Log.i(Engine.TAG, "the system's VPN block turned out to be ${if (lockdown) "on" else "off"}: establishing again for it")
        val second = establishFor(cfg, wanted) ?: return first
        try { first.close() } catch (_: Exception) {}
        return second
    }

    private fun establishFor(cfg: TunConfig, excluded: Set<String>): ParcelFileDescriptor? {
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
        for (pkg in excluded) {
            try { b.addDisallowedApplication(pkg) } catch (_: Exception) {}
        }
        return try {
            b.establish()?.also {
                appliedExcluded = excluded
                interfacesBuilt++
            }
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
        main.removeCallbacks(prune)
        main.removeCallbacks(captureCheck)
        main.removeCallbacks(modeCheck)
        captureFailures = 0
        captureBroken = false
        stopEngine()
        tunUp = false
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
        if (excludedNow() != appliedExcluded) {
            restartEngine()
        } else {
            e.enforceRules()
            updateNotification()
        }
    }

    private fun wantIpv6(): Boolean = Prefs.ipv6 && net.hasIpv6

    /** Apps excluded from the VPN when the interface was established. */
    @Volatile private var appliedExcluded: Set<String> = emptySet()

    /** The apps the running interface leaves outside the VPN (for diagnostics and tests). */
    val excludedApps: Set<String> get() = appliedExcluded

    /** Apps to keep out of the VPN as things are now: see [appsToExclude] for the rules. */
    private fun excludedNow(): Set<String> {
        readSystemMode()
        return appsToExclude(Prefs.proxy, Rules.excludedPackages(), lockdown, packageName)
    }

    /**
     * Asks Android whether it runs us as the always-on VPN and blocks connections outside the VPN.
     * It answers only while our interface is up: before the first one both read "no", whatever the
     * settings are. Until then the block is taken as it was seen last (remembered across starts), so
     * that a start under the block does not shut the proxy app out first.
     */
    private fun readSystemMode() {
        if (!tunUp) {
            lockdown = Prefs.lockdownSeen
            return
        }
        lockdown = try { isLockdownEnabled } catch (_: Exception) { false }
        alwaysOn = try { isAlwaysOn } catch (_: Exception) { false }
        if (Prefs.lockdownSeen != lockdown) Prefs.lockdownSeen = lockdown
    }

    /**
     * The proxy app's traffic still comes through us: remember it and rebuild the VPN without it.
     * Automatically only for a known proxy client; another app that took the port is suggested in the
     * proxy settings instead, so nothing escapes the firewall without the user saying so.
     */
    override fun onProxyApp(uid: Int) {
        main.post {
            val p = Prefs.proxy
            if (engine == null || !p.enabled || !p.bypassApp || uid == selfUid) return@post
            val pkgs = Apps.packagesForUid(uid)
            if (pkgs.isEmpty() || p.appPkg in pkgs) return@post
            val known = ProxyApps.known.flatMap { it.packages }
            val pkg = pkgs.firstOrNull { it in known }
            if (pkg == null) {
                suggestedProxyPkg = pkgs[0]
                return@post
            }
            // Remembered under the system's block too, where it stays inside: once the block is
            // lifted, it is known whom to let out.
            Prefs.proxy = p.copy(appPkg = pkg)
            if (excludedNow() != appliedExcluded) {
                Log.i(Engine.TAG, "proxy served by $pkg: keeping it out of the VPN")
                restartEngine()
            }
        }
    }

    override fun proxyAppLabel(): String? = Prefs.proxy.appPkg.takeIf { it.isNotEmpty() }?.let { Apps.labelForPackage(it) }

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
            .setContentTitle(getString(when {
                captureBroken -> R.string.notif_bypassed
                // Not "on" before a probe showed that traffic really enters this engine's interface.
                engine == null || captureVerifiedAt < Live.startedAt -> R.string.notif_checking
                else -> R.string.notif_on
            }))
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
        private const val PRUNE_EVERY_MS = 6 * 3_600_000L
        private const val CAPTURE_FIRST_MS = 200L
        private const val CAPTURE_EVERY_MS = 60_000L
        /** How long probes may go unanswered before the capture counts as lost. */
        private const val CAPTURE_FIRST_WINDOW_MS = 5_000L
        private const val CAPTURE_WINDOW_MS = 2_500L
        private const val PROBE_EVERY_MS = 200L
        private const val MAX_CAPTURE_RESTARTS = 3
        /** How often the system is asked whether it blocks connections outside the VPN. */
        const val MODE_EVERY_MS = 5_000L
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
        /** Android's "Block connections without VPN" is on for us. */
        @Volatile var lockdown = false
            private set
        /** Android's "Always-on VPN" is on for us (as of the last start or check). */
        @Volatile var alwaysOn = false
            private set
        /** An app (not a known proxy client) that serves the proxy port, for the user to confirm. */
        @Volatile var suggestedProxyPkg: String? = null
        /** When a probe last proved that traffic really goes through the interface. */
        @Volatile var captureVerifiedAt = 0L
            private set
        /** Rebuilding the interface did not help: Android keeps routing apps around the VPN. */
        @Volatile var captureBroken = false
            private set
        /** How many times a lost capture was detected (for diagnostics and tests). */
        @Volatile var captureRecoveries = 0
            private set
        /** How many interfaces were established since the app started (for diagnostics and tests). */
        @Volatile var interfacesBuilt = 0
            private set

        /**
         * True when [pkg] is the proxy app and the system's block keeps it inside the VPN, although it
         * is marked to go around it (by the proxy settings or by the user).
         */
        fun keptInside(pkg: String?): Boolean {
            val p = Prefs.proxy
            return pkg != null && running && lockdown && p.enabled && p.appPkg == pkg
        }

        fun start(ctx: Context) {
            val i = Intent(ctx, FirewallService::class.java).setAction(ACTION_START)
            ctx.startForegroundService(i)
        }

        /** Applies changed proxy settings to the running engine. */
        fun applyProxy() {
            val s = instance ?: return
            s.main.post {
                // Whether the proxy app bypasses the VPN is part of the interface: rebuild it then.
                if (s.engine != null && s.excludedNow() != s.appliedExcluded) {
                    s.restartEngine()
                    s.updateNotification()
                    return@post
                }
                s.engine?.applyProxyAsync { Prefs.proxy }
                s.updateNotification()
            }
        }

        /**
         * Looks whether the system's always-on VPN / "block connections without VPN" changed (nothing
         * announces it), and moves the proxy app into the VPN or out of it accordingly.
         */
        fun recheck() {
            val s = instance ?: return
            s.main.post { if (s.engine != null && s.excludedNow() != s.appliedExcluded) s.restartEngine() }
        }

        /** Re-establishes the interface after a settings change (e.g. IPv6). */
        fun reconfigure() {
            val s = instance ?: return
            s.main.post { s.restartEngine() }
        }

        /**
         * True when a VPN other than ours is up. Our own network (still registered for a moment after
         * stopping) is recognised by its interface address: NetworkCapabilities.getOwnerUid() would
         * need API 30.
         */
        fun otherVpnActive(ctx: Context): Boolean = try {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            @Suppress("DEPRECATION")
            cm.allNetworks.any { n ->
                val caps = cm.getNetworkCapabilities(n)
                caps != null && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) &&
                    cm.getLinkProperties(n)?.linkAddresses?.none { it.address.hostAddress == TunConfig.T4 } != false
            }
        } catch (_: Exception) {
            false
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
