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
        App(listOf("com.v2ray.ang", "com.v2ray.ang.fdroid"), "v2rayNG", ProxyType.SOCKS5, 10808, true,
            "Настройки → «Режим» → «Прокси» (Proxy only), затем подключитесь. Порт 10808, если не включён «динамический порт». " +
                "Лучше задайте логин и пароль для локального прокси в настройках v2rayNG и введите их здесь."),
        App(listOf("com.happproxy"), "Happ", ProxyType.SOCKS5, 10808, true,
            "Включите режим «только прокси» в настройках, если он есть в вашей версии. SOCKS5-порт по умолчанию 10808 (Настройки → Inbounds)."),
        App(listOf("com.v2raytun.android"), "v2RayTun", ProxyType.SOCKS5, 10808, true,
            "Настройки трафика → «Режим» → «Прокси». Порт SOCKS5 обычно 10808; там же можно включить авторизацию SOCKS5."),
        App(listOf("app.hiddify.com"), "Hiddify", ProxyType.SOCKS5, 12334, true,
            "Настройки → «Входящие» → «Режим службы» → «Только прокси-служба». Порт 12334."),
        App(listOf("moe.nb4a"), "NekoBox", ProxyType.SOCKS5, 2080, true,
            "Настройки → «Сервисный режим» → «Только прокси». Порт 2080 (у копии-«двойника» он другой — посмотрите в настройках)."),
        App(listOf("fr.husi"), "Husi", ProxyType.SOCKS5, 2080, true,
            "Настройки → «Режим работы» → «Только прокси». Порт 2080 (у «двойника» другой)."),
        App(listOf("com.github.dyhkwong.sagernet"), "Exclave", ProxyType.SOCKS5, 2080, true,
            "Настройки → «Сервисный режим» → «Только прокси». Порт SOCKS 2080."),
        App(listOf("com.github.metacubex.clash.meta", "com.github.metacubex.clash.alpha"), "Clash Meta", ProxyType.SOCKS5, 7890, true,
            "Настройки → «Сеть» → выключите «Маршрутизировать системный трафик». Порт — mixed-port из профиля (обычно 7890)."),
        App(listOf("com.follow.clash"), "FlClash", ProxyType.SOCKS5, 7890, true,
            "В разделе VPN выключите «Включить» (останется только прокси). Порт 7890."),
        App(listOf("com.github.shadowsocks"), "Shadowsocks", ProxyType.SOCKS5, 1080, true,
            "Настройки → «Режим службы» → «Только прокси». Порт 1080. UDP работает, только если в профиле нет плагина."),
        App(listOf("io.github.romanvht.byedpi"), "ByeByeDPI", ProxyType.SOCKS5, 1080, true,
            "Настройки → «Режим» → «Прокси». Порт 1080. Это обход блокировок без VPN-сервера."),
        App(listOf("com.adguard.vpn"), "AdGuard VPN", ProxyType.SOCKS5, 1080, true,
            "Настройки → «Режим работы VPN» → «SOCKS5». Если приложение задало логин и пароль прокси, введите их здесь."),
        App(listOf("org.torproject.android"), "Orbot (Tor)", ProxyType.SOCKS5, 9050, false,
            "Включите «Режим опытного пользователя» (Power User Mode) и нажмите «Подключиться»: Tor запустится без VPN. Порт 9050. Tor не передаёт UDP."),
        App(listOf("pan.alexander.tordnscrypt", "pan.alexander.tordnscrypt.gp", "pan.alexander.tordnscrypt.stable"), "InviZible Pro", ProxyType.SOCKS5, 9050, false,
            "Меню → «Режим» → «Режим прокси», запустите Tor. Порт 9050. Tor не передаёт UDP."),
    )

    /** VPN apps that cannot work as a proxy on Android, with what to do instead. */
    val vpnOnly = mapOf(
        "org.outline.android.client" to "Outline",
        "org.amnezia.vpn" to "AmneziaVPN",
        "org.amnezia.awg" to "AmneziaWG",
        "com.wireguard.android" to "WireGuard",
        "com.psiphon3" to "Psiphon",
    )

    fun vpnOnlyInstalled(ctx: Context): List<String> {
        val pm = ctx.packageManager
        return vpnOnly.filter { (p, _) -> try { pm.getApplicationInfo(p, 0); true } catch (_: Exception) { false } }.values.toList()
    }

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
