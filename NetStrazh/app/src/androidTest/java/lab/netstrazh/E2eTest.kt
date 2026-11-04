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
import lab.netstrazh.ui.MainActivity
import lab.netstrazh.ui.PickerActivity
import lab.netstrazh.ui.SettingsActivity
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
            // Start like the app's own switch does: from a visible activity (FGS start from the
            // background is restricted, and the service needs BIND_VPN_SERVICE, which the shell lacks).
            ActivityScenario.launch(MainActivity::class.java).use { sc ->
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
        }

        @AfterClass @JvmStatic
        fun stopVpn() {
            Rules.set(ctx.packageName, 0)
            Prefs.proxy = ProxyConfig.OFF
            InstrumentationRegistry.getInstrumentation().runOnMainSync { FirewallService.stop(ctx) }
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
            FirewallService.reconfigure()
            waitFor(15_000, "rebuilt interface verified (round $round)") { FirewallService.captureVerifiedAt >= t0 }
            val t1 = System.currentTimeMillis()
            assertTrue("TCP after rebuilding (round $round)", httpGet("example.com").startsWith("HTTP/1."))
            waitSeen("TCP captured after rebuilding (round $round)") { it.proto == "TCP" && it.port == 80 && it.uid == myUid && it.ts >= t1 }
        }
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
     * Runs last: the user's switch off and on again, three times. After every start, traffic must
     * really go through the VPN (an answer alone does not show that): the capture probe, this app's
     * TCP and UDP, and another app's TCP (the shell, uid 2000) are all checked, and every failure is
     * reported, not just the first.
     */
    @Test fun t20_powerSwitchOffAndOn() {
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
            ActivityScenario.launch(MainActivity::class.java).use { sc ->
                sc.onActivity { it.onPowerToggle(true) }
                waitFor(25_000, "VPN running again") { FirewallService.running }
                Thread.sleep(500)
            }
            check("cycle $cycle: capture probe") {
                waitFor(15_000, "capture probe verified after switching on") { FirewallService.captureVerifiedAt >= tOn }
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
