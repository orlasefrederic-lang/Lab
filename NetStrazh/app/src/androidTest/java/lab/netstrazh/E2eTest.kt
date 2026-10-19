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
import lab.netstrazh.vpn.ProxyConfig
import lab.netstrazh.vpn.ProxyTester
import lab.netstrazh.vpn.ProxyType
import lab.netstrazh.vpn.Upstream
import lab.netstrazh.vpn.VIA_PROXY
import org.junit.AfterClass
import org.junit.Assert.assertEquals
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
                    val tx: Long, val rx: Long, val blocked: Boolean, val via: String)

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
        val live = Live.active.values.map { Seen(it.uid, it.proto, it.host, it.ip, it.port, it.tx, it.rx, it.blocked, it.via) }
        val db = Db.recent(Db.F_ALL, null, null, 1000).map { Seen(it.uid, it.proto, it.host, it.ip, it.port, it.tx, it.rx, it.blocked, it.via) }
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
        Thread.sleep(500)
        val start = SystemClock.uptimeMillis()
        val got = try { httpGet("example.com") } catch (e: IOException) { "" }
        assertEquals("blocked app must not get data", "", got)
        assertTrue("blocked quickly", SystemClock.uptimeMillis() - start < 10_000)
        waitSeen("blocked TCP") { it.blocked && it.proto == "TCP" && it.port == 80 && it.uid == myUid }
        assertEquals("blocked UDP gets no answer", null, dnsQueryUdp("8.8.8.8", "example.com"))

        Rules.set(ctx.packageName, 0)
        Thread.sleep(500)
        assertTrue(httpGet("example.com").startsWith("HTTP/1."))
    }

    @Test fun t07_proxyChaining() {
        val svc = FirewallService.instance!!
        TestSocks({ svc.protect(it) }, { svc.protect(it) }).use { socks ->
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
}
