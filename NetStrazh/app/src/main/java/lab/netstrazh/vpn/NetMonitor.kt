package lab.netstrazh.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

enum class NetType(val label: String) {
    WIFI("wifi"), MOBILE("mobile"), OTHER("other"), NONE("none")
}

/** Tracks the real (non-VPN) network the device is using. */
class NetMonitor(ctx: Context, private val onChange: () -> Unit) {
    private val cm = ctx.getSystemService(ConnectivityManager::class.java)
    private var registered = false

    @Volatile var best: Network? = null
        private set
    @Volatile var type: NetType = NetType.NONE
        private set
    @Volatile var dns: List<InetAddress> = emptyList()
        private set
    @Volatile var hasIpv6 = false
        private set

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = changed()
        override fun onLost(network: Network) = changed()
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = changed()
        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = changed()
    }

    private fun changed() {
        refresh()
        onChange()
    }

    fun start() {
        refresh()
        if (registered) return
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            cm.registerNetworkCallback(req, callback)
            registered = true
        } catch (_: Exception) {
        }
    }

    fun stop() {
        if (!registered) return
        try { cm.unregisterNetworkCallback(callback) } catch (_: Exception) {}
        registered = false
    }

    @Suppress("DEPRECATION")
    @Synchronized fun refresh() {
        var pick: Network? = null
        var pickCaps: NetworkCapabilities? = null
        var pickScore = -1
        for (n in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(n) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            var score = 0
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) score += 10
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) score += 5
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) score += 3
            if (score > pickScore) {
                pick = n
                pickCaps = caps
                pickScore = score
            }
        }
        best = pick
        type = when {
            pickCaps == null -> NetType.NONE
            pickCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetType.WIFI
            pickCaps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetType.MOBILE
            else -> NetType.OTHER
        }
        val lp = pick?.let { cm.getLinkProperties(it) }
        dns = lp?.dnsServers ?: emptyList()
        hasIpv6 = lp?.linkAddresses?.any { la ->
            val a = la.address
            a is Inet6Address && !a.isLinkLocalAddress && !a.isLoopbackAddress && !a.isSiteLocalAddress &&
                (a.address[0].toInt() and 0xFE) != 0xFC // not ULA
        } ?: false
    }

    /** DNS server to forward app queries to. Prefers IPv4 servers of the current network. */
    fun upstreamDns(): InetAddress {
        val list = dns
        return list.firstOrNull { it is Inet4Address } ?: list.firstOrNull() ?: FALLBACK_DNS
    }

    companion object {
        val FALLBACK_DNS: InetAddress = InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1))
    }
}
