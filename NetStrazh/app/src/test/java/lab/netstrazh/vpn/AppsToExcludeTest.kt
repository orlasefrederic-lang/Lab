package lab.netstrazh.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Which apps stay outside the VPN. Under Android's "block connections without VPN" an app outside
 * the VPN has no network at all, so the proxy app must never be among them there.
 */
class AppsToExcludeTest {
    private val self = "lab.netstrazh"
    private val v2ray = "com.v2ray.ang"
    private val bank = "com.example.bank"
    private val proxy = ProxyConfig(type = ProxyType.SOCKS5, host = "127.0.0.1", port = 10808, bypassApp = true, appPkg = v2ray)

    @Test
    fun withoutTheBlockTheProxyAppGoesAroundTheVpn() {
        assertEquals(setOf(bank, v2ray), appsToExclude(proxy, setOf(bank), lockdown = false, self = self))
        assertEquals(setOf(v2ray), appsToExclude(proxy, emptySet(), lockdown = false, self = self))
    }

    @Test
    fun underTheBlockTheProxyAppStaysInside() {
        assertEquals(setOf(bank), appsToExclude(proxy, setOf(bank), lockdown = true, self = self))
        assertEquals(emptySet<String>(), appsToExclude(proxy, emptySet(), lockdown = true, self = self))
    }

    @Test
    fun underTheBlockAProxyAppMarkedByHandStaysInsideToo() {
        // Marked "мимо Стража" by the user, with and without the proxy settings asking for the same.
        assertEquals(setOf(bank), appsToExclude(proxy, setOf(bank, v2ray), lockdown = true, self = self))
        assertEquals(setOf(bank), appsToExclude(proxy.copy(bypassApp = false), setOf(bank, v2ray), lockdown = true, self = self))
    }

    @Test
    fun withoutTheBlockTheUsersMarkIsKept() {
        assertEquals(setOf(bank, v2ray), appsToExclude(proxy.copy(bypassApp = false), setOf(bank, v2ray), lockdown = false, self = self))
        // And nothing is added when the proxy settings do not ask for it.
        assertEquals(setOf(bank), appsToExclude(proxy.copy(bypassApp = false), setOf(bank), lockdown = false, self = self))
    }

    @Test
    fun otherAppsTheUserMarkedAreNeverTouched() {
        // Under the block they lose the network (the app warns about it), but that is the user's call.
        for (lockdown in listOf(false, true)) {
            assertEquals(true, bank in appsToExclude(proxy, setOf(bank), lockdown, self))
        }
    }

    @Test
    fun aProxyThatIsOffOrUnknownChangesNothing() {
        val marked = setOf(bank, v2ray)
        for (lockdown in listOf(false, true)) {
            assertEquals("proxy switched off", marked, appsToExclude(proxy.copy(type = ProxyType.NONE), marked, lockdown, self))
            assertEquals("no port", marked, appsToExclude(proxy.copy(port = 0), marked, lockdown, self))
            assertEquals("proxy app not known", marked, appsToExclude(proxy.copy(appPkg = ""), marked, lockdown, self))
        }
    }

    @Test
    fun theAppItselfIsNeverExcluded() {
        val own = proxy.copy(appPkg = self)
        assertEquals(setOf(bank), appsToExclude(own, setOf(bank), lockdown = false, self = self))
        assertEquals(setOf(bank), appsToExclude(own, setOf(bank), lockdown = true, self = self))
    }
}
