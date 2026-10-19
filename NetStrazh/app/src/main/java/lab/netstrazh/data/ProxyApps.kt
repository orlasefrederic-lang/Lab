package lab.netstrazh.data

import android.content.Context
import lab.netstrazh.vpn.ProxyType

/** VPN/proxy clients that can run in "proxy only" mode, with their default local proxy port. */
object ProxyApps {
    class App(
        val packages: List<String>,
        val name: String,
        val type: ProxyType,
        val port: Int,
        val udp: Boolean,
        /** How to switch the app to proxy-only mode. */
        val howTo: String,
    )

    class Found(val app: App, val pkg: String, val label: String)

    val known = listOf(
        App(listOf("com.v2ray.ang"), "v2rayNG", ProxyType.SOCKS5, 10808, true,
            "Настройки → «Режим VPN/прокси» → «Только прокси», затем запустите подключение. Порт: Настройки → «Порт локального прокси» (по умолчанию 10808)."),
        App(listOf("moe.nb4a"), "NekoBox", ProxyType.SOCKS5, 2080, true,
            "Настройки → «Режим работы службы» → «Режим прокси». Порт смешанного прокси — в настройках (по умолчанию 2080)."),
        App(listOf("fr.husi"), "Husi", ProxyType.SOCKS5, 2080, true,
            "Настройки → «Режим работы службы» → «Режим прокси». Порт — в настройках (по умолчанию 2080)."),
        App(listOf("app.hiddify.com"), "Hiddify", ProxyType.SOCKS5, 12334, true,
            "Настройки → «Режим работы» (Service mode) → «Прокси». Порт смешанного прокси — в настройках конфигурации."),
        App(listOf("com.github.metacubex.clash.meta"), "Clash Meta", ProxyType.SOCKS5, 7890, true,
            "Настройки → Сеть → выключите «Маршрутизация системного трафика» (VPN). Порт — mixed-port из профиля (часто 7890)."),
        App(listOf("com.follow.clash"), "FlClash", ProxyType.SOCKS5, 7890, true,
            "Выключите режим TUN/VPN, оставьте прокси. Порт — в настройках (по умолчанию 7890)."),
        App(listOf("com.github.shadowsocks"), "Shadowsocks", ProxyType.SOCKS5, 1080, true,
            "Настройки профиля → «Режим маршрутизации службы» → «Только прокси». Порт SOCKS5 по умолчанию 1080."),
        App(listOf("org.torproject.android"), "Orbot (Tor)", ProxyType.SOCKS5, 9050, false,
            "Выключите режим VPN («Все приложения через Tor»), просто запустите Tor. SOCKS5 на порту 9050. Tor не передаёт UDP."),
        App(listOf("pan.alexander.tordnscrypt", "pan.alexander.tordnscrypt.gp", "pan.alexander.tordnscrypt.stable"), "InviZible Pro", ProxyType.SOCKS5, 9050, false,
            "Режим «Прокси» в главном меню, запустите Tor. SOCKS5 на порту 9050. Tor не передаёт UDP."),
    )

    /** Known proxy-capable apps that are installed on this phone. */
    fun installed(ctx: Context): List<Found> {
        val pm = ctx.packageManager
        val out = ArrayList<Found>()
        for (a in known) for (p in a.packages) {
            val label = try { pm.getApplicationInfo(p, 0).loadLabel(pm).toString() } catch (_: Exception) { continue }
            out += Found(a, p, label)
            break
        }
        return out
    }
}
