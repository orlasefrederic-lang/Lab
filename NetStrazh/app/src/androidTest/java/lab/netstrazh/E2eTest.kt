package lab.netstrazh

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.util.Log
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import lab.netstrazh.data.Db
import lab.netstrazh.data.Rules
import lab.netstrazh.data.SysStats
import lab.netstrazh.ui.AppActivity
import lab.netstrazh.ui.HostsActivity
import lab.netstrazh.ui.MainActivity
import lab.netstrazh.ui.PickerActivity
import lab.netstrazh.ui.SettingsActivity
import lab.netstrazh.vpn.Engine
import lab.netstrazh.vpn.FirewallService
import lab.netstrazh.vpn.Live
import lab.netstrazh.vpn.NetType
import lab.netstrazh.vpn.ProxyConfig
import lab.netstrazh.vpn.ProxyTester
import lab.netstrazh.vpn.ProxyType
import lab.netstrazh.vpn.TunConfig
import lab.netstrazh.vpn.Upstream
import lab.netstrazh.vpn.VIA_PROXY
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * End-to-end tests on a real Android device/emulator: the VPN is started for real and the test
 * process (which is the app itself) generates traffic through it.
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class E2eTest {
    /** What the engine recorded about one connection (live or from the journal). */
    data class Seen(val uid: Int, val proto: String, val host: String?, val ip: String, val port: Int,
                    val tx: Long, val rx: Long, val blocked: Boolean, val via: String, val ts: Long)

    companion object {
        private const val TAG = "NetStrazhE2E"
        lateinit var ctx: Context
        val myUid = Process.myUid()

        fun shell(cmd: String): String {
            val pfd = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(cmd)
            return ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().use { it.readText() }
        }

        fun waitFor(ms: Long, what: String, cond: () -> Boolean) {
            val end = SystemClock.uptimeMillis() + ms
            while (SystemClock.uptimeMillis() < end) {
                if (cond()) return
                Thread.sleep(100)
            }
            fail("timeout waiting for: $what")
        }

        /**
         * Which way a fresh socket of this app would leave right now: "vpn", "direct" (the physical
         * network) or "none". Connecting a UDP socket sends nothing, it only makes the system choose
         * the route, and with it the source address.
         */
        fun routeNow(): String = try {
            DatagramSocket().use { s ->
                s.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1)), 53))
                val a = s.localAddress
                when {
                    a == null || a.isAnyLocalAddress -> "none"
                    a.hostAddress == TunConfig.T4 -> "vpn"
                    else -> "direct"
                }
            }
        } catch (_: Exception) {
            "none"
        }

        /** The service flags as one word, for [RouteWatch]. */
        fun serviceState(): String =
            (if (FirewallService.running) "on" else "off") +
                (if (FirewallService.running && FirewallService.captureVerifiedAt >= Live.startedAt) "+verified" else "")

        @BeforeClass @JvmStatic
        fun startVpn() {
            ctx = InstrumentationRegistry.getInstrumentation().targetContext
            val pkg = ctx.packageName
            // Pre-grant what a user grants by hand: VPN consent and usage access.
            Log.i(TAG, "appops vpn: " + shell("appops set $pkg ACTIVATE_VPN allow"))
            Log.i(TAG, "appops usage: " + shell("appops set $pkg GET_USAGE_STATS allow"))
            shell("pm grant $pkg android.permission.POST_NOTIFICATIONS")
            Rules.set(pkg, 0)
            Prefs.proxy = ProxyConfig.OFF
            val prepared = android.net.VpnService.prepare(ctx) == null
            val tStart = System.currentTimeMillis()
            val watch = RouteWatch()
            // Start like the app's own switch does: from a visible activity (FGS start from the
            // background is restricted, and the service needs BIND_VPN_SERVICE, which the shell lacks).
            ActivityScenario.launch(MainActivity::class.java).use { sc ->
                watch.mark("start")
                sc.onActivity { FirewallService.start(it) }
                try {
                    waitFor(25_000, "VPN running") { FirewallService.running }
                } catch (e: AssertionError) {
                    throw AssertionError("VPN did not start; vpn pre-consented=$prepared\n" +
                        shell("logcat -d -t 300 -s NetStrazh:V AndroidRuntime:E ActivityManager:W Vpn:V ConnectivityService:W"), e)
                }
            }
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            waitFor(10_000, "default network is our VPN") {
                cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
            // Android reports the VPN as the default network before its routes exist (a loaded system
            // takes seconds): only the capture probe shows traffic really enters the interface.
            try {
                waitFor(25_000, "capture verified") { FirewallService.captureVerifiedAt >= tStart }
            } finally {
                Log.i(TAG, "route timeline, first start: " + watch.finish())
            }
        }

        @AfterClass @JvmStatic
        fun stopVpn() {
            Rules.set(ctx.packageName, 0)
            Prefs.proxy = ProxyConfig.OFF
            InstrumentationRegistry.getInstrumentation().runOnMainSync { FirewallService.stop(ctx) }
        }
    }

    /**
     * Records, every few milliseconds, where fresh sockets would go and what the service says, so a
     * test can log how long Android keeps routing apps around the VPN after a start or a rebuild
     * (e.g. "0:direct/off 310:[switch on] 420:direct/on 1890:vpn/on 2010:vpn/on+verified").
     */
    class RouteWatch {
        private val t0 = SystemClock.elapsedRealtime()
        private val log = ArrayList<Pair<Long, String>>()
        @Volatile private var stop = false
        private val thread = kotlin.concurrent.thread(name = "route-watch", isDaemon = true) {
            var last = ""
            while (!stop) {
                val s = routeNow() + "/" + serviceState()
                if (s != last) {
                    synchronized(log) { log += (SystemClock.elapsedRealtime() - t0) to s }
                    last = s
                }
                Thread.sleep(5)
            }
        }

        fun mark(what: String) {
            synchronized(log) { log += (SystemClock.elapsedRealtime() - t0) to "[$what]" }
        }

        /** Stops watching. Returns the timeline, and how long sockets went around a running service. */
        fun finish(): String {
            stop = true
            thread.join(2_000)
            val end = SystemClock.elapsedRealtime() - t0
            val all = synchronized(log) { ArrayList(log) }
            val changes = all.filter { !it.second.startsWith("[") }
            var outside = 0L
            for ((i, c) in changes.withIndex()) {
                val until = changes.getOrNull(i + 1)?.first ?: end
                if (!c.second.startsWith("vpn/") && c.second.contains("/on")) outside += until - c.first
            }
            return all.sortedBy { it.first }.joinToString(" ") { "${it.first}:${it.second}" } + " | around a running VPN: $outside ms"
        }
    }

    private fun seen(): List<Seen> {
        val live = Live.active.values.map { Seen(it.uid, it.proto, it.host, it.ip, it.port, it.tx, it.rx, it.blocked, it.via, it.start) }
        val db = Db.recent(Db.F_ALL, null, null, 1000).map { Seen(it.uid, it.proto, it.host, it.ip, it.port, it.tx, it.rx, it.blocked, it.via, it.ts) }
        return live + db
    }

    private fun waitSeen(what: String, pred: (Seen) -> Boolean): Seen {
        var found: Seen? = null
        waitFor(15_000, what) { found = seen().firstOrNull(pred); found != null }
        Log.i(TAG, "seen $what: $found")
        return found!!
    }

    private fun httpGet(host: String): String {
        Socket().use { s ->
            s.soTimeout = 15_000
            s.connect(InetSocketAddress(host, 80), 15_000)
            s.getOutputStream().write("GET / HTTP/1.1\r\nHost: $host\r\nUser-Agent: NetStrazhE2E\r\nConnection: close\r\n\r\n".toByteArray())
            return s.getInputStream().readBytes().toString(Charsets.ISO_8859_1)
        }
    }

    private fun dnsQueryUdp(server: String, name: String): ByteArray? {
        val labels = name.split('.')
        val q = java.io.ByteArrayOutputStream()
        q.write(byteArrayOf(0x51, 0x52, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        for (l in labels) { q.write(l.length); q.write(l.toByteArray()) }
        q.write(byteArrayOf(0, 0, 1, 0, 1))
        val b = q.toByteArray()
        DatagramSocket().use { s ->
            s.soTimeout = 4000
            repeat(3) {
                s.send(DatagramPacket(b, b.size, InetAddress.getByName(server), 53))
                val buf = ByteArray(1500)
                val p = DatagramPacket(buf, buf.size)
                try {
                    s.receive(p)
                    return buf.copyOf(p.length)
                } catch (_: java.net.SocketTimeoutException) {
                }
            }
        }
        return null
    }

    @Test fun t01_dnsIsLoggedAndAttributed() {
        val name = "e2e-${SystemClock.uptimeMillis()}.example.com"
        try { InetAddress.getAllByName(name) } catch (_: IOException) {} // NXDOMAIN is fine
        val s = waitSeen("DNS $name") { it.proto == "DNS" && it.host == name }
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            assertEquals("DNS query should be attributed to the asking app", myUid, s.uid)
        } else {
            // Android 10 sends lookups from the system resolver's own UID (1051, AID_DNS).
            assertTrue("DNS attributed to the app or the system resolver: ${s.uid}", s.uid == myUid || s.uid == 1051)
        }
        InetAddress.getAllByName("example.org")
        waitSeen("DNS example.org") { it.proto == "DNS" && it.host == "example.org" }
    }

    @Test fun t02_plainHttpThroughVpn() {
        val r = httpGet("example.com")
        assertTrue(r.take(100), r.startsWith("HTTP/1."))
        val s = waitSeen("TCP example.com:80") { it.proto == "TCP" && it.port == 80 && it.host == "example.com" && it.uid == myUid && it.rx > 0 }
        assertTrue(s.tx > 0)
    }

    @Test fun t03_httpsShowsSni() {
        val c = URL("https://www.google.com/generate_204").openConnection() as HttpsURLConnection
        c.setRequestProperty("Connection", "close")
        c.connectTimeout = 15_000
        c.readTimeout = 15_000
        assertEquals(204, c.responseCode)
        c.disconnect()
        waitSeen("TLS SNI www.google.com") { it.proto == "TCP" && it.port == 443 && it.host == "www.google.com" && it.uid == myUid }
    }

    @Test fun t04_udpThroughVpn() {
        val r = dnsQueryUdp("1.1.1.1", "example.com")
        assertTrue("UDP answer from 1.1.1.1", r != null && r.size > 12 && r[0] == 0x51.toByte())
        waitSeen("UDP 1.1.1.1:53") { it.proto == "UDP" && it.ip == "1.1.1.1" && it.port == 53 && it.uid == myUid && it.rx > 0 }
    }

    @Test fun t05_downloadSpeed() {
        val size = 5_000_000
        val t0 = SystemClock.uptimeMillis()
        val c = URL("https://speed.cloudflare.com/__down?bytes=$size").openConnection() as HttpsURLConnection
        c.connectTimeout = 15_000
        c.readTimeout = 30_000
        val n = c.inputStream.use { inp ->
            val b = ByteArray(65536)
            var total = 0L
            while (true) {
                val k = inp.read(b)
                if (k < 0) break
                total += k
            }
            total
        }
        val ms = SystemClock.uptimeMillis() - t0
        Log.i(TAG, "download $n bytes in $ms ms = ${n * 8 / 1000 / maxOf(ms, 1)} Mbit/s")
        assertEquals(size.toLong(), n)
        assertTrue((Live.stats[myUid]?.rx?.get() ?: 0L) >= size)
    }

    @Test fun t06_blockingAndUnblocking() {
        Rules.set(ctx.packageName, Rules.BLOCK_ALL)
        try {
            Thread.sleep(500)
            val start = SystemClock.uptimeMillis()
            val got = try { httpGet("example.com") } catch (e: IOException) { "" }
            assertEquals("blocked app must not get data", "", got)
            assertTrue("blocked quickly", SystemClock.uptimeMillis() - start < 10_000)
            waitSeen("blocked TCP") { it.blocked && it.proto == "TCP" && it.port == 80 && it.uid == myUid }
            assertEquals("blocked UDP gets no answer", null, dnsQueryUdp("8.8.8.8", "example.com"))
        } finally {
            // Later tests must not run blocked if an assertion above fails.
            Rules.set(ctx.packageName, 0)
        }
        Thread.sleep(500)
        assertTrue(httpGet("example.com").startsWith("HTTP/1."))
    }

    @Test fun t07_proxyChaining() {
        val svc = FirewallService.instance!!
        TestSocks({ svc.protect(it) }, { svc.protect(it) }, { svc.resolve(it) }).use { socks ->
            fun diag(): String = "\nsocks connects=${socks.connects} udp=${socks.udp}" +
                "\nupstream: proxyUid=${svc.upstream?.proxyUid} err=${svc.upstream?.lastError} udpUnsupported=${svc.upstream?.udpUnsupported}" +
                "\nrecent: " + seen().take(12).joinToString("\n  ") +
                "\nlogcat:\n" + shell("logcat -d -t 80 -s NetStrazh:V AndroidRuntime:E")
            try {
                Prefs.proxy = ProxyConfig(ProxyType.SOCKS5, "127.0.0.1", socks.port, dnsServer = "1.1.1.1")
                FirewallService.applyProxy()
                waitFor(5_000, "proxy applied") { svc.upstream?.cfg?.port == socks.port }

                val r = httpGet("example.net")
                assertTrue(r.take(100), r.startsWith("HTTP/1."))
                assertTrue("TCP went through the proxy: ${socks.connects}", socks.connects.any { it.endsWith(":80") })
                // The proxy got the host name the app asked for (HTTP Host), not just an IP.
                assertTrue("CONNECT by name: ${socks.connects}", socks.connects.contains("example.net:80"))
                assertTrue("DNS went through the proxy: ${socks.connects}", socks.connects.contains("1.1.1.1:53"))
                waitSeen("proxied TCP") { it.proto == "TCP" && it.port == 80 && it.via == VIA_PROXY && it.uid == myUid }

                val u = dnsQueryUdp("8.8.8.8", "example.com")
                assertTrue("UDP via SOCKS UDP ASSOCIATE", u != null)
                assertTrue("UDP went through the proxy: ${socks.udp}", socks.udp.contains("8.8.8.8:53"))

                // The proxy runs in our own process: it must not be mistaken for an external proxy app.
                assertEquals(Upstream.UID_NONE, svc.upstream?.proxyUid)

                // The "Проверить" button of the settings screen, end to end.
                val res = ProxyTester({ svc.protect(it) }, { svc.protect(it) })
                    .run(Prefs.proxy, InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), socks.port))
                Log.i(TAG, "proxy test: ${res.lines}")
                assertTrue(res.lines.joinToString(), res.ok)
                assertTrue(res.lines.joinToString(), res.lines.any { it.contains("выход в интернет") })
                assertTrue(res.lines.joinToString(), res.lines.any { it.startsWith("✓ DNS через прокси") })
                assertEquals(res.lines.joinToString(), true, res.udp)
            } catch (e: Throwable) {
                throw AssertionError("proxy chaining failed: $e" + diag(), e)
            } finally {
                Prefs.proxy = ProxyConfig.OFF
                FirewallService.applyProxy()
                waitFor(5_000, "proxy off") { svc.upstream?.cfg?.enabled == false }
            }
        }
        assertTrue(httpGet("example.com").startsWith("HTTP/1."))
    }

    @Test fun t08_systemTrafficStats() {
        assertTrue("usage access granted", SysStats.hasUsageAccess(ctx))
        val now = System.currentTimeMillis()
        val t = SysStats.traffic(ctx, now - 3_600_000L, now + 60_000L)
        Log.i(TAG, "system stats for us: rx=${t[myUid]?.rx} tx=${t[myUid]?.tx}, apps=${t.size}")
        assertTrue("system stats are readable", t.isNotEmpty())
    }

    @Test fun t09_screensOpen() {
        ActivityScenario.launch(MainActivity::class.java).use { sc ->
            for (i in 0..3) {
                sc.onActivity { it.select(i) }
                Thread.sleep(800)
            }
        }
        ActivityScenario.launch<AppActivity>(Intent(ctx, AppActivity::class.java).putExtra("uid", myUid)).use { Thread.sleep(1500) }
        ActivityScenario.launch(PickerActivity::class.java).use { Thread.sleep(2500) }
        ActivityScenario.launch(SettingsActivity::class.java).use { Thread.sleep(1500) }
        ActivityScenario.launch(HostsActivity::class.java).use { Thread.sleep(1000) }
    }

    private fun rcode(r: ByteArray?): Int = if (r == null || r.size < 12) -1 else r[3].toInt() and 0x0F

    /** "Block DNS too": lookups of a blocked app are refused at once, and resolve again after. */
    @Test fun t10_dnsBlockedWithTheApp() {
        Rules.set(ctx.packageName, Rules.BLOCK_ALL)
        Rules.setBlockDns(true)
        try {
            Thread.sleep(300)
            val r = dnsQueryUdp(TunConfig.DNS4, "dns-block-${SystemClock.uptimeMillis()}.example.com")
            assertEquals("REFUSED for the blocked app", 5, rcode(r))
            assertEquals("same query id", 0x51.toByte(), r!![0])
            waitSeen("blocked DNS") { it.proto == "DNS" && it.blocked && it.uid == myUid }
        } finally {
            Rules.setBlockDns(false)
            Rules.set(ctx.packageName, 0)
        }
        Thread.sleep(300)
        assertEquals("resolves again", 0, rcode(dnsQueryUdp(TunConfig.DNS4, "example.org")))
    }

    /** Host rules: DNS for the name is refused, TLS naming it is cut, other sites keep working. */
    @Test fun t11_hostRules() {
        Rules.setHostBlocked(Rules.ALL, "example.org", true)
        try {
            Thread.sleep(300)
            assertEquals("subdomain refused", 5, rcode(dnsQueryUdp(TunConfig.DNS4, "www.example.org")))
            // An app that skips our DNS still names the host in TLS: connect to some IP with that name.
            val ip = InetAddress.getByName("www.google.com")
            val f = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory
            try {
                (f.createSocket() as javax.net.ssl.SSLSocket).use { t ->
                    t.sslParameters = t.sslParameters.apply { serverNames = listOf(javax.net.ssl.SNIHostName("www.example.org")) }
                    t.connect(InetSocketAddress(ip, 443), 10_000)
                    t.soTimeout = 10_000
                    t.startHandshake()
                }
                fail("handshake with a blocked name went through")
            } catch (_: IOException) {
            }
            waitSeen("TLS to a blocked name cut") { it.proto == "TCP" && it.port == 443 && it.host == "www.example.org" && it.blocked && it.uid == myUid }
            val c = URL("https://www.google.com/generate_204").openConnection() as HttpsURLConnection
            c.connectTimeout = 15_000
            c.readTimeout = 15_000
            assertEquals("other sites work", 204, c.responseCode)
            c.disconnect()
        } finally {
            Rules.setHostBlocked(Rules.ALL, "example.org", false)
        }
        Thread.sleep(300)
        assertEquals("resolves after unblocking", 0, rcode(dnsQueryUdp(TunConfig.DNS4, "www.example.org")))
    }

    private fun dnsQuery(id: Int, name: String): ByteArray {
        val q = java.io.ByteArrayOutputStream()
        q.write(byteArrayOf((id ushr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        for (l in name.split('.')) { q.write(l.length); q.write(l.toByteArray()) }
        q.write(byteArrayOf(0, 0, 1, 0, 1))
        return q.toByteArray()
    }

    /** One query on an already open UDP socket; the answer or null. */
    private fun dnsOn(s: DatagramSocket, id: Int, name: String): ByteArray? {
        val b = dnsQuery(id, name)
        repeat(3) {
            s.send(DatagramPacket(b, b.size))
            val buf = ByteArray(1500)
            val p = DatagramPacket(buf, buf.size)
            try {
                s.receive(p)
                if (p.length >= 12 && buf[0] == b[0] && buf[1] == b[1]) return buf.copyOf(p.length)
            } catch (_: java.net.SocketTimeoutException) {
            }
        }
        return null
    }

    /** Host rules decide per query: a blocked name must not spoil the next query on the same socket. */
    @Test fun t12_hostRuleIsPerQueryOnOneDnsSocket() {
        Rules.setHostBlocked(Rules.ALL, "blocked.example.org", true)
        try {
            Thread.sleep(300)
            DatagramSocket().use { s ->
                s.soTimeout = 4000
                s.connect(InetSocketAddress(InetAddress.getByName(TunConfig.DNS4), 53))
                assertEquals("blocked name refused", 5, rcode(dnsOn(s, 0x6101, "www.blocked.example.org")))
                assertEquals("allowed name on the same socket resolves", 0, rcode(dnsOn(s, 0x6102, "example.org")))
                assertEquals("blocked again", 5, rcode(dnsOn(s, 0x6103, "blocked.example.org")))
            }
        } finally {
            Rules.setHostBlocked(Rules.ALL, "blocked.example.org", false)
        }
    }

    /** DNS over TCP to our resolver address gets the same per-query decisions as UDP. */
    @Test fun t13_dnsOverTcpHonorsHostRules() {
        Rules.setHostBlocked(Rules.ALL, "blocked.example.org", true)
        try {
            Thread.sleep(300)
            Socket().use { s ->
                s.connect(InetSocketAddress(InetAddress.getByName(TunConfig.DNS4), 53), 10_000)
                s.soTimeout = 10_000
                val o = java.io.DataOutputStream(s.getOutputStream())
                val i = java.io.DataInputStream(s.getInputStream())
                fun ask(id: Int, name: String): Int {
                    val q = dnsQuery(id, name)
                    o.writeShort(q.size); o.write(q); o.flush()
                    val r = ByteArray(i.readUnsignedShort()).also { i.readFully(it) }
                    assertEquals("same id", q[1], r[1])
                    return rcode(r)
                }
                assertEquals("blocked name refused over TCP", 5, ask(0x6201, "tcp.blocked.example.org"))
                assertEquals("allowed name on the same connection resolves", 0, ask(0x6202, "example.org"))
            }
            waitSeen("TCP DNS refusal logged") { it.proto == "DNS" && it.uid == myUid && it.host == "tcp.blocked.example.org" }
        } finally {
            Rules.setHostBlocked(Rules.ALL, "blocked.example.org", false)
        }
    }

    /**
     * A proxy app that is slow to accept (busy, or briefly frozen by the system) must still be told
     * apart: the proxy's end of a connection waiting in the accept queue is reported as owned by
     * root, the proxy's listening socket is not.
     */
    @Test fun t14_slowAcceptingProxyIsNotMistakenForRoot() {
        val svc = FirewallService.instance!!
        TestSocks({ svc.protect(it) }, { svc.protect(it) }, { svc.resolve(it) }, acceptDelayMs = 400).use { socks ->
            try {
                Prefs.proxy = ProxyConfig(ProxyType.SOCKS5, "127.0.0.1", socks.port, dnsServer = "1.1.1.1")
                FirewallService.applyProxy()
                waitFor(5_000, "proxy applied") { svc.upstream?.cfg?.port == socks.port }
                assertTrue(httpGet("example.com").startsWith("HTTP/1."))
                assertTrue("went through the slow proxy: ${socks.connects}", socks.connects.any { it.endsWith(":80") })
                // Our own process serves this proxy, so the right answer is "not another app" (never root).
                assertEquals("proxy owner", Upstream.UID_NONE, svc.upstream?.proxyUid)
            } finally {
                Prefs.proxy = ProxyConfig.OFF
                FirewallService.applyProxy()
                waitFor(5_000, "proxy off") { svc.upstream?.cfg?.enabled == false }
            }
        }
    }

    /** "Block DNS too" switched on and off while a DNS socket stays open: each next query follows. */
    @Test fun t15_dnsPolicyChangeAppliesToAnOpenSocket() {
        Rules.setHostBlocked(Rules.ALL, "blocked.example.org", true)
        try {
            Thread.sleep(300)
            DatagramSocket().use { s ->
                s.soTimeout = 4000
                s.connect(InetSocketAddress(InetAddress.getByName(TunConfig.DNS4), 53))
                // A refused first query leaves the flow open without a path.
                assertEquals(5, rcode(dnsOn(s, 0x6401, "x.blocked.example.org")))
                Rules.set(ctx.packageName, Rules.BLOCK_ALL)
                Rules.setBlockDns(true)
                Thread.sleep(300)
                assertEquals("blocked together with the app, on the same socket", 5, rcode(dnsOn(s, 0x6402, "example.org")))
                Rules.setBlockDns(false)
                Rules.set(ctx.packageName, 0)
                Thread.sleep(300)
                assertEquals("allowed again on the same socket", 0, rcode(dnsOn(s, 0x6403, "example.org")))
            }
        } finally {
            Rules.setBlockDns(false)
            Rules.set(ctx.packageName, 0)
            Rules.setHostBlocked(Rules.ALL, "blocked.example.org", false)
        }
    }

    /**
     * A proxy that greets at once but answers CONNECT only once it reached the server (Tor and the
     * like can take many seconds) works, and is not reported as a frozen proxy app.
     */
    @Test fun t16_slowConnectReplyIsNotAFrozenProxy() {
        val svc = FirewallService.instance!!
        TestSocks({ svc.protect(it) }, { svc.protect(it) }, { svc.resolve(it) }, connectReplyDelayMs = 7_500).use { socks ->
            try {
                Prefs.proxy = ProxyConfig(ProxyType.SOCKS5, "127.0.0.1", socks.port, dnsViaProxy = false)
                FirewallService.applyProxy()
                waitFor(5_000, "proxy applied") { svc.upstream?.cfg?.port == socks.port }
                val t0 = SystemClock.uptimeMillis()
                Socket().use { s ->
                    s.soTimeout = 20_000
                    s.connect(InetSocketAddress(InetAddress.getByName("example.com"), 80), 20_000)
                    s.getOutputStream().write("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".toByteArray())
                    val head = s.getInputStream().readBytes().toString(Charsets.ISO_8859_1)
                    assertTrue(head.take(80), head.startsWith("HTTP/1."))
                }
                assertTrue("the reply really waited", SystemClock.uptimeMillis() - t0 >= 7_000)
                val silent = svc.upstream!!.recentEvents().filter { it.msg.contains("не отвечает") }
                assertTrue("no frozen-proxy report: $silent", silent.isEmpty())
            } finally {
                Prefs.proxy = ProxyConfig.OFF
                FirewallService.applyProxy()
                waitFor(5_000, "proxy off") { svc.upstream?.cfg?.enabled == false }
            }
        }
    }

    /**
     * Rebuilding the interface while it runs (rule or IPv6 changes, and the capture check's repair)
     * closes the old interface right after the new one is up. Android then destroys every socket on
     * the VPN address; the engine's server socket must survive that, and traffic must keep flowing.
     */
    @Test fun t17_rebuildingTheInterfaceKeepsTrafficFlowing() {
        for (round in 1..3) {
            val t0 = System.currentTimeMillis()
            val watch = RouteWatch()
            try {
                watch.mark("rebuild")
                FirewallService.reconfigure()
                waitFor(15_000, "rebuilt interface verified (round $round)") { Live.startedAt >= t0 && FirewallService.captureVerifiedAt >= Live.startedAt }
            } finally {
                Log.i(TAG, "route timeline, rebuild in place (round $round): " + watch.finish())
            }
            val t1 = System.currentTimeMillis()
            assertTrue("TCP after rebuilding (round $round)", httpGet("example.com").startsWith("HTTP/1."))
            waitSeen("TCP captured after rebuilding (round $round)") { it.proto == "TCP" && it.port == 80 && it.uid == myUid && it.ts >= t1 }
        }
    }

    /**
     * Excluding an app from the VPN (the user's "мимо Стража", or the proxy app) changes the
     * interface's app list, and Android then replaces the whole VPN network instead of updating it in
     * place. Capture must come back by itself after every such change, in both directions, and the
     * log shows for how long fresh sockets went around the VPN meanwhile.
     */
    @Test fun t19_changingTheAppListKeepsCapture() {
        // Any installed package but ours: the test APK is one, and nothing runs under its UID.
        val other = InstrumentationRegistry.getInstrumentation().context.packageName
        assertTrue("need another package to exclude", other != ctx.packageName)
        val recoveriesBefore = FirewallService.captureRecoveries
        try {
            for (round in 1..2) for (exclude in listOf(true, false)) {
                val what = "round $round, " + if (exclude) "excluding an app" else "including it again"
                val t0 = System.currentTimeMillis()
                val watch = RouteWatch()
                var dumped = false
                try {
                    watch.mark(if (exclude) "exclude" else "include")
                    Rules.set(other, if (exclude) Rules.EXCLUDE else 0)
                    waitFor(30_000, "capture verified again ($what)") {
                        val ok = Live.startedAt >= t0 && FirewallService.captureVerifiedAt >= Live.startedAt
                        if (!ok && !dumped && System.currentTimeMillis() - t0 > 3_000) {
                            // Not back after three seconds: record what the system routes by right now.
                            dumped = true
                            Log.i(TAG, "still not captured ($what); ip rule:\n" + shell("ip rule") +
                                "\nroutes:\n" + shell("ip route show table all").lines().filter { "tun" in it }.joinToString("\n"))
                        }
                        ok
                    }
                } finally {
                    Log.i(TAG, "route timeline, app list changed ($what): " + watch.finish())
                }
                val t1 = System.currentTimeMillis()
                assertTrue("TCP after the app list changed ($what)", httpGet("example.com").startsWith("HTTP/1."))
                waitSeen("TCP captured after the app list changed ($what)") { it.proto == "TCP" && it.port == 80 && it.uid == myUid && it.ts >= t1 }
            }
        } finally {
            Rules.set(other, 0)
        }
        Log.i(TAG, "app list changes: capture losses detected and repaired by the probe: ${FirewallService.captureRecoveries - recoveriesBefore}")
    }

    /** Title of the service's notification as the system holds it now, or null. */
    private fun notificationTitle(): String? =
        ctx.getSystemService(android.app.NotificationManager::class.java).activeNotifications
            .firstOrNull { it.packageName == ctx.packageName }?.notification?.extras
            ?.getCharSequence(android.app.Notification.EXTRA_TITLE)?.toString()

    /** The SOCKS proxy in the test APK's own process ([OtherAppProxy]): a proxy app under another UID. */
    private class OtherApp(val pkg: String, val conn: android.content.ServiceConnection, private val binder: android.os.IBinder) {
        val port: Int get() = ask(OtherAppProxy.GET_PORT) { it.readInt() }
        val uid: Int get() = ask(OtherAppProxy.GET_UID) { it.readInt() }
        /** What it was asked to carry: "CONNECT host:port" and "UDP ip:port". */
        val log: List<String> get() = ask(OtherAppProxy.GET_LOG) { it.createStringArrayList() ?: ArrayList() }

        private fun <T> ask(code: Int, read: (android.os.Parcel) -> T): T {
            val data = android.os.Parcel.obtain()
            val reply = android.os.Parcel.obtain()
            try {
                assertTrue("the proxy app answers", binder.transact(code, data, reply, 0))
                return read(reply)
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
    }

    private fun startOtherApp(): OtherApp {
        val pkg = InstrumentationRegistry.getInstrumentation().context.packageName
        val got = java.util.concurrent.LinkedBlockingQueue<android.os.IBinder>()
        val conn = object : android.content.ServiceConnection {
            override fun onServiceConnected(name: android.content.ComponentName, service: android.os.IBinder) { got.offer(service) }
            override fun onServiceDisconnected(name: android.content.ComponentName) {}
        }
        assertTrue("bind the proxy app", ctx.bindService(Intent().setClassName(pkg, OtherAppProxy::class.java.name), conn, Context.BIND_AUTO_CREATE))
        val binder = got.poll(30, java.util.concurrent.TimeUnit.SECONDS) ?: throw AssertionError("the proxy app did not start")
        val app = OtherApp(pkg, conn, binder)
        assertTrue("the proxy app has a UID of its own: ${app.uid}", app.uid != myUid && app.uid >= 10000)
        return app
    }

    /** Every way the proxy app may have been asked for [host]:80 (by name, or by one of its addresses). */
    private fun connectsTo(app: OtherApp, host: String): List<String> {
        val wanted = HashSet<String>()
        wanted += "CONNECT $host:80"
        try { for (a in InetAddress.getAllByName(host)) wanted += "CONNECT ${a.hostAddress}:80" } catch (_: IOException) {}
        return app.log.filter { it in wanted }
    }

    private fun proxyDiag(app: OtherApp, svc: FirewallService): String =
        "\nproxy app uid=${app.uid} log=${app.log}" +
            "\nupstream: proxyUid=${svc.upstream?.proxyUid} err=${svc.upstream?.lastError} udpUnsupported=${svc.upstream?.udpUnsupported}" +
            "\nrecent: " + seen().take(14).joinToString("\n  ") +
            "\nlogcat:\n" + shell("logcat -d -t 80 -s NetStrazh:V AndroidRuntime:E")

    /**
     * The usual way to work with another VPN app: it serves a proxy from its own process and is kept
     * out of the VPN, so its own connections leave directly, while apps' traffic goes through it.
     * Switching this on and off changes the VPN's app list both times.
     */
    @Test fun t21_proxyAppOutsideTheVpn() {
        val svc = FirewallService.instance!!
        val app = startOtherApp()
        try {
            val t0 = System.currentTimeMillis()
            val watch = RouteWatch()
            try {
                watch.mark("proxy on, its app excluded")
                Prefs.proxy = ProxyConfig(ProxyType.SOCKS5, "127.0.0.1", app.port, dnsServer = "1.1.1.1", bypassApp = true, appPkg = app.pkg)
                FirewallService.applyProxy()
                waitFor(30_000, "capture verified with the proxy app excluded") {
                    Live.startedAt >= t0 && FirewallService.captureVerifiedAt >= Live.startedAt
                }
            } finally {
                Log.i(TAG, "route timeline, proxy app excluded: " + watch.finish())
            }
            assertEquals("proxy applied", app.port, svc.upstream?.cfg?.port)

            val t1 = System.currentTimeMillis()
            // A name nobody asked before, so the lookup cannot come from a cache.
            val name = "t21-${SystemClock.uptimeMillis()}.example.com"
            try { InetAddress.getAllByName(name) } catch (_: IOException) {} // NXDOMAIN is fine
            val dns = waitSeen("DNS through the proxy app") { it.proto == "DNS" && it.host == name }
            assertEquals("DNS went through the proxy", VIA_PROXY, dns.via)
            assertTrue("the proxy app carried the DNS: ${app.log}", app.log.contains("CONNECT 1.1.1.1:53"))

            val r = httpGet("example.net")
            assertTrue(r.take(100), r.startsWith("HTTP/1."))
            val tcp = waitSeen("own TCP through the proxy app") { it.proto == "TCP" && it.port == 80 && it.uid == myUid && it.ts >= t1 }
            assertEquals("TCP went through the proxy", VIA_PROXY, tcp.via)
            assertEquals("the proxy app carried it once: ${app.log}", 1, connectsTo(app, "example.net").size)

            assertTrue("UDP answer through the proxy app", dnsQueryUdp("8.8.8.8", "example.com") != null)
            val udp = waitSeen("own UDP through the proxy app") { it.proto == "UDP" && it.ip == "8.8.8.8" && it.uid == myUid && it.ts >= t1 }
            assertEquals("UDP went through the proxy", VIA_PROXY, udp.via)
            assertTrue("the proxy app carried the UDP: ${app.log}", app.log.contains("UDP 8.8.8.8:53"))

            // Outside the VPN: none of the proxy app's own connections comes through the engine.
            Db.sync()
            assertTrue("the proxy app's own traffic must not enter the VPN", seen().none { it.uid == app.uid && it.ts >= t1 })
        } catch (e: Throwable) {
            throw AssertionError("proxy app outside the VPN failed: $e" + proxyDiag(app, svc), e)
        } finally {
            val watch = RouteWatch()
            try {
                watch.mark("proxy off, its app included")
                Prefs.proxy = ProxyConfig.OFF
                FirewallService.applyProxy()
                waitFor(30_000, "proxy off and capture verified") {
                    svc.upstream?.cfg?.enabled == false && FirewallService.captureVerifiedAt >= Live.startedAt
                }
            } finally {
                Log.i(TAG, "route timeline, proxy app included again: " + watch.finish())
                ctx.unbindService(app.conn)
            }
        }
        assertTrue(httpGet("example.com").startsWith("HTTP/1."))
    }

    /**
     * Under Android's "block connections without VPN" the proxy app cannot be kept out of the VPN
     * (Android would cut it off), so it stays inside. Its connections then come through the engine
     * like any app's; they must be recognised by its UID and sent directly, not back into its own
     * proxy, while apps' traffic still goes through it.
     */
    @Test fun t22_proxyAppInsideTheVpn() {
        val svc = FirewallService.instance!!
        val app = startOtherApp()
        try {
            Prefs.proxy = ProxyConfig(ProxyType.SOCKS5, "127.0.0.1", app.port, dnsServer = "1.1.1.1", bypassApp = false)
            FirewallService.applyProxy()
            waitFor(5_000, "proxy applied") { svc.upstream?.cfg?.port == app.port }

            val t1 = System.currentTimeMillis()
            val r = httpGet("example.net")
            assertTrue(r.take(100), r.startsWith("HTTP/1."))
            val mine = waitSeen("own TCP through the proxy app") { it.proto == "TCP" && it.port == 80 && it.uid == myUid && it.ts >= t1 }
            assertEquals("TCP went through the proxy", VIA_PROXY, mine.via)
            assertEquals("proxy app recognised by its UID", app.uid, svc.upstream?.proxyUid)
            // Its own connection to the site came through the engine and left directly.
            val its = waitSeen("the proxy app's own TCP") { it.proto == "TCP" && it.port == 80 && it.uid == app.uid && it.ts >= t1 }
            assertEquals("the proxy app's traffic must leave directly, not through its own proxy", "", its.via)
            assertFalse("the proxy app's traffic is not blocked", its.blocked)
            assertEquals("no loop, one CONNECT for one request: ${app.log}", 1, connectsTo(app, "example.net").size)

            assertTrue("UDP answer through the proxy app", dnsQueryUdp("8.8.8.8", "example.com") != null)
            val udp = waitSeen("own UDP through the proxy app") { it.proto == "UDP" && it.ip == "8.8.8.8" && it.uid == myUid && it.ts >= t1 }
            assertEquals("UDP went through the proxy", VIA_PROXY, udp.via)
            val itsUdp = waitSeen("the proxy app's own UDP") { it.proto == "UDP" && it.ip == "8.8.8.8" && it.uid == app.uid && it.ts >= t1 }
            assertEquals("the proxy app's UDP must leave directly", "", itsUdp.via)
            // A query is repeated when its answer is slow; a loop would show as far more than that.
            assertTrue("no UDP loop: ${app.log}", app.log.count { it == "UDP 8.8.8.8:53" } in 1..3)
        } catch (e: Throwable) {
            throw AssertionError("proxy app inside the VPN failed: $e" + proxyDiag(app, svc), e)
        } finally {
            Prefs.proxy = ProxyConfig.OFF
            FirewallService.applyProxy()
            try {
                waitFor(5_000, "proxy off") { svc.upstream?.cfg?.enabled == false }
            } finally {
                ctx.unbindService(app.conn)
            }
        }
        assertTrue(httpGet("example.com").startsWith("HTTP/1."))
    }

    /**
     * Connections Android cannot attribute ("Неизвестно") can be blocked like an app, by their UID.
     * Known apps are not affected, and such a rule never becomes a VPN exclusion.
     */
    @Test fun t18_unknownOwnersCanBeBlocked() {
        val key = Rules.keyForUid(Rules.UNKNOWN_UID)
        Rules.set(key, Rules.BLOCK_ALL)
        try {
            assertTrue("unknown owner blocked on Wi-Fi", Rules.isBlocked(Rules.UNKNOWN_UID, NetType.WIFI))
            assertTrue("unknown owner blocked on mobile", Rules.isBlocked(Rules.UNKNOWN_UID, NetType.MOBILE))
            assertFalse("a UID rule is not an exclusion", key in Rules.excludedPackages())
            val t0 = System.currentTimeMillis()
            assertTrue("own TCP still flows", httpGet("example.com").startsWith("HTTP/1."))
            waitSeen("own TCP attributed and allowed") { it.proto == "TCP" && it.port == 80 && it.uid == myUid && it.ts >= t0 && !it.blocked }
            // The card of "Неизвестно" opens with its switches.
            ActivityScenario.launch<AppActivity>(Intent(ctx, AppActivity::class.java).putExtra("uid", Rules.UNKNOWN_UID)).use { Thread.sleep(1000) }
        } finally {
            Rules.set(key, 0)
        }
        assertFalse("unblocked again", Rules.isBlocked(Rules.UNKNOWN_UID, NetType.WIFI))
    }

    /**
     * A blocked address is listed with the app it is blocked for and the time it was blocked, counts
     * what it has stopped, and can be unblocked again. Rules made by a version that did not record
     * the time yet keep working and are listed too.
     */
    @Test fun t23_blockedAddressesAreListedAndCanBeUnblocked() {
        val pkg = ctx.packageName
        val host = "t23.example.org"
        val oldHost = "old.t23.example.org"
        val stored = ctx.getSharedPreferences("hostrules", Context.MODE_PRIVATE)
        val t0 = System.currentTimeMillis()
        Rules.setHostBlocked(pkg, host, true)
        try {
            val rule = Rules.hostRules().single { it.key == pkg && it.host == host }
            assertTrue("the time is recorded: ${rule.since}", rule.since in t0..System.currentTimeMillis())
            assertEquals("the rule is this app's", myUid % 100000, rule.appId)
            assertEquals("it covers a subdomain", listOf(host), Rules.hostRulesCovering(myUid, "www.$host").map { it.host })
            assertTrue("but not for another app", Rules.hostRulesCovering(2000, "www.$host").isEmpty())
            Thread.sleep(30)
            Rules.setHostBlocked(pkg, host, true)
            assertEquals("blocking again keeps the first time", rule.since, Rules.hostRules().single { it.key == pkg && it.host == host }.since)

            // A rule as versions before 3.5 stored it: the value "true", no time.
            assertTrue(stored.edit().putBoolean("${Rules.ALL}|$oldHost", true).commit())
            Rules.reload()
            assertEquals("an old rule has no time", 0L, Rules.hostRules().single { it.host == oldHost }.since)
            assertTrue("an old rule still blocks", Rules.hostBlocked(myUid, "a.$oldHost"))

            // An app naming the blocked host in TLS is cut, and the attempt is counted for the rule.
            val ip = InetAddress.getByName("www.google.com")
            val f = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory
            try {
                (f.createSocket() as javax.net.ssl.SSLSocket).use { t ->
                    t.sslParameters = t.sslParameters.apply { serverNames = listOf(javax.net.ssl.SNIHostName("www.$host")) }
                    t.connect(InetSocketAddress(ip, 443), 10_000)
                    t.soTimeout = 10_000
                    t.startHandshake()
                }
                fail("handshake with a blocked name went through")
            } catch (_: IOException) {
            }
            var item: HostsActivity.Item? = null
            waitFor(15_000, "the stopped attempt is counted for the rule") {
                item = HostsActivity.items(Rules.hostRules(), Db.stopped(Engine.NOTE_HOST_BLOCKED))
                    .firstOrNull { it.rule.key == pkg && it.rule.host == host }
                (item?.stopped ?: 0) >= 1
            }
            Log.i(TAG, "blocked address as listed: ${item!!.rule.host} ${item!!.who}, ${HostsActivity.details(item!!, ", ")}")
            assertTrue("the last attempt has a time", item!!.last >= t0)
            assertTrue("the app is named: ${item!!.who}", item!!.who.contains(ctx.getString(R.string.app_name)))
            assertEquals("the rule opens this app's card", myUid, item!!.uid)

            // The list of all blocked addresses, and the app's card with the same rules on top.
            ActivityScenario.launch(HostsActivity::class.java).use { Thread.sleep(1500) }
            ActivityScenario.launch<AppActivity>(Intent(ctx, AppActivity::class.java).putExtra("uid", myUid)).use { Thread.sleep(1500) }
        } finally {
            Rules.setHostBlocked(pkg, host, false)
            Rules.setHostBlocked(Rules.ALL, oldHost, false)
        }
        assertTrue("both rules are gone", Rules.hostRules().none { it.host == host || it.host == oldHost })
        assertFalse("unblocked", Rules.hostBlocked(myUid, "www.$host"))
        assertFalse("the old rule is unblocked too", Rules.hostBlocked(myUid, "a.$oldHost"))
    }

    /**
     * Runs last: the user's switch off and on again, three times. After every start, traffic must
     * really go through the VPN (an answer alone does not show that): the capture probe, this app's
     * TCP and UDP, and another app's TCP (the shell, uid 2000) are all checked, and every failure is
     * reported, not just the first.
     */
    @Test fun t30_powerSwitchOffAndOn() {
        val problems = ArrayList<String>()
        fun diag() = "\nip rule:\n" + shell("ip rule") + "\nrecent: " + seen().take(10).joinToString("\n  ")
        fun check(what: String, block: () -> Unit) {
            try { block() } catch (e: AssertionError) { problems += "$what: ${e.message}" } catch (e: Exception) { problems += "$what: $e" }
        }
        for (cycle in 1..3) {
            ActivityScenario.launch(MainActivity::class.java).use { sc ->
                sc.onActivity { it.onPowerToggle(false) }
                waitFor(10_000, "VPN stopped") { !FirewallService.running }
                if (cycle == 1) {
                    // Our own VPN network lingers for a moment after stopping: it is not "another VPN",
                    // and checking that must work on every API level (the header asks it right away).
                    val end = SystemClock.uptimeMillis() + 2_000
                    while (SystemClock.uptimeMillis() < end) {
                        assertFalse("own VPN network taken for another VPN", FirewallService.otherVpnActive(ctx))
                        Thread.sleep(100)
                    }
                }
                Thread.sleep(1_000) // header refresh while off
            }
            if (cycle == 1) ActivityScenario.launch(SettingsActivity::class.java).use { Thread.sleep(1500) }
            val tOn = System.currentTimeMillis()
            val watch = RouteWatch()
            ActivityScenario.launch(MainActivity::class.java).use { sc ->
                watch.mark("switch on")
                sc.onActivity { it.onPowerToggle(true) }
                waitFor(25_000, "VPN running again") { FirewallService.running }
                Thread.sleep(500)
            }
            check("cycle $cycle: capture probe") {
                try {
                    waitFor(15_000, "capture probe verified after switching on") { FirewallService.captureVerifiedAt >= tOn }
                } finally {
                    Log.i(TAG, "route timeline, switch on (cycle $cycle): " + watch.finish())
                }
            }
            check("cycle $cycle: notification") {
                // "Защита включена" only once the probe proved it; "checking" until then.
                waitFor(5_000, "notification says the protection is on") { notificationTitle() == ctx.getString(R.string.notif_on) }
            }
            val t0 = System.currentTimeMillis()
            check("cycle $cycle: own TCP") {
                assertTrue(httpGet("example.com").startsWith("HTTP/1."))
                waitSeen("own TCP captured") { it.proto == "TCP" && it.port == 80 && it.uid == myUid && it.ts >= t0 }
            }
            check("cycle $cycle: own UDP") {
                assertTrue("UDP answer", dnsQueryUdp("1.1.1.1", "example.org") != null)
                waitSeen("own UDP captured") { it.proto == "UDP" && it.ip == "1.1.1.1" && it.uid == myUid && it.ts >= t0 }
            }
            check("cycle $cycle: shell TCP") {
                val nc = shell("toybox nc -w 3 1.1.1.1 80")
                assertFalse("toybox nc is missing on this image: $nc", nc.contains("not found") || nc.contains("inaccessible"))
                waitSeen("shell TCP captured") { it.proto == "TCP" && it.port == 80 && it.uid == 2000 && it.ts >= t0 }
            }
            if (problems.isNotEmpty()) break
        }
        Log.i(TAG, "power cycles: capture losses detected and repaired by the probe: ${FirewallService.captureRecoveries}")
        if (problems.isNotEmpty()) throw AssertionError(problems.joinToString("\n") + diag())
    }
}
