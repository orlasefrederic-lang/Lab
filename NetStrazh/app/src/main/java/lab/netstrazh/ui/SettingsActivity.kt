package lab.netstrazh.ui

import android.app.Activity
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import lab.netstrazh.Prefs
import lab.netstrazh.data.Apps
import lab.netstrazh.data.ProxyApps
import lab.netstrazh.vpn.FirewallService
import lab.netstrazh.vpn.ProxyConfig
import lab.netstrazh.vpn.ProxyTester
import lab.netstrazh.vpn.ProxyType
import lab.netstrazh.vpn.Upstream
import java.net.InetAddress
import java.net.InetSocketAddress

/** "Работа с другим VPN": chaining NetStrazh through another VPN app's local proxy. */
class SettingsActivity : Activity() {
    private var type = ProxyType.NONE
    private val typePills = ArrayList<TextView>()
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var user: EditText
    private lateinit var pass: EditText
    private lateinit var dns: CheckBox
    private lateinit var dnsServer: EditText
    private lateinit var udpDirect: CheckBox
    private lateinit var directIfDown: CheckBox
    private lateinit var fields: LinearLayout
    private lateinit var status: TextView
    private lateinit var testOut: TextView
    private lateinit var otherVpn: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            renderStatus()
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Pal.init(this)
        MainActivity.styleWindow(this)
        val col = vbox().apply { setPadding(dp(16), dp(8), dp(16), dp(32)) }
        val scroll = ScrollView(this).apply {
            setBackgroundColor(Pal.bg)
            addView(col)
        }
        col.addView(text("←  Назад", 15f, Pal.accent, bold = true).apply {
            setPadding(dp(4), dp(10), dp(12), dp(10))
            setOnClickListener { finish() }
        }, lp(WRAP, WRAP))
        col.addView(text("Работа вместе с другим VPN", 20f, bold = true), lp().apply { bottomMargin = dp(10) })

        // --- explanation
        val intro = card()
        intro.addView(text(
            "Android разрешает только один VPN одновременно, поэтому Страж и ваш VPN не могут быть VPN-ами сразу.\n\n" +
                "Решение: переведите ваше VPN-приложение в режим «только прокси» (Proxy only). Тогда VPN-ом остаётся Страж: " +
                "он видит и фильтрует трафик, а наружу отправляет его через ваше VPN-приложение.",
            14f))
        otherVpn = text("", 13.5f, Pal.warn)
        intro.addView(otherVpn, lp().apply { topMargin = dp(8) })
        col.addView(intro)

        // --- detected apps
        val found = ProxyApps.installed(this)
        val appsCard = card()
        appsCard.addView(text(if (found.isEmpty()) "Известные VPN-приложения с режимом прокси не найдены" else "Найдены на телефоне", 16f, bold = true))
        if (found.isEmpty()) {
            appsCard.addView(text("Поддерживаются, например: v2rayNG, Hiddify, NekoBox, Husi, Clash Meta, FlClash, Shadowsocks, Orbot. " +
                "Если ваше приложение умеет режим прокси, укажите его адрес и порт ниже вручную.", 13f, Pal.sub))
        }
        for (a in found) appsCard.addView(appRow(a))
        col.addView(appsCard, lp().apply { topMargin = dp(12) })

        // --- proxy form
        val form = card()
        form.addView(text("Прокси", 16f, bold = true))
        val pills = hbox().apply { setPadding(0, dp(8), 0, dp(4)) }
        for ((t, label) in listOf(ProxyType.NONE to "Выключено", ProxyType.SOCKS5 to "SOCKS5", ProxyType.HTTP to "HTTP")) {
            val p = pill(label, 3) { setType(t) }
            p.tag = t
            typePills += p
            pills.addView(p, lp(WRAP, WRAP).apply { rightMargin = dp(8) })
        }
        form.addView(pills)
        fields = vbox()
        host = field(fields, "Адрес", "127.0.0.1", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        port = field(fields, "Порт", "например 10808", InputType.TYPE_CLASS_NUMBER)
        user = field(fields, "Логин (если нужен)", "", InputType.TYPE_CLASS_TEXT)
        pass = field(fields, "Пароль (если нужен)", "", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
        dns = check(fields, "DNS-запросы — тоже через прокси (рекомендуется: провайдер не увидит, какие сайты вы открываете)")
        dnsServer = field(fields, "DNS-сервер для запросов через прокси", "1.1.1.1", InputType.TYPE_CLASS_TEXT)
        udpDirect = check(fields, "Если прокси не передаёт UDP — пускать UDP напрямую, мимо прокси (иначе UDP блокируется)")
        directIfDown = check(fields, "Если прокси недоступен — пускать трафик напрямую (небезопасно: VPN тогда не защищает)")
        form.addView(fields)
        val buttons = hbox().apply { setPadding(0, dp(12), 0, 0) }
        buttons.addView(pill("Сохранить", 0) { save() }, lp(WRAP, WRAP).apply { rightMargin = dp(8) })
        buttons.addView(pill("Проверить", 1) { test() }, lp(WRAP, WRAP))
        form.addView(buttons)
        testOut = text("", 13.5f, Pal.text)
        form.addView(testOut, lp().apply { topMargin = dp(10) })
        col.addView(form, lp().apply { topMargin = dp(12) })

        // --- live status
        val st = card()
        st.addView(text("Состояние", 16f, bold = true))
        status = text("", 13.5f, Pal.sub)
        st.addView(status, lp().apply { topMargin = dp(4) })
        col.addView(st, lp().apply { topMargin = dp(12) })

        setContentView(scroll)
        load(Prefs.proxy)
    }

    override fun onResume() {
        super.onResume()
        handler.post(ticker)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    private fun field(parent: LinearLayout, label: String, hint: String, input: Int): EditText {
        parent.addView(text(label, 12.5f, Pal.sub), lp().apply { topMargin = dp(8) })
        val e = EditText(this).apply {
            this.hint = hint
            inputType = input
            textSize = 15f
            setSingleLine()
            setTextColor(Pal.text)
            setHintTextColor(Pal.sub)
            background = rounded(Pal.surface2, dpf(10f))
            setPadding(dp(12), dp(9), dp(12), dp(9))
        }
        parent.addView(e, lp().apply { topMargin = dp(2) })
        return e
    }

    private fun check(parent: LinearLayout, label: String): CheckBox {
        val c = CheckBox(this).apply {
            text = label
            textSize = 13.5f
            setTextColor(Pal.text)
        }
        parent.addView(c, lp().apply { topMargin = dp(6) })
        return c
    }

    private fun appRow(a: ProxyApps.Found): LinearLayout {
        val row = vbox().apply { setPadding(0, dp(10), 0, dp(4)) }
        val top = hbox()
        top.addView(ImageView(this).apply { setImageDrawable(Apps.icon(a.pkg) ?: getDrawable(android.R.drawable.sym_def_app_icon)) },
            lp(dp(32), dp(32)))
        val names = vbox()
        names.addView(text(a.label, 15f, bold = true))
        names.addView(text("${a.app.type.name} · порт ${a.app.port}" + if (a.app.udp) " · есть UDP" else " · без UDP", 12.5f, Pal.sub))
        top.addView(names, lp(0, WRAP, 1f).apply { leftMargin = dp(10) })
        top.addView(pill("Подставить", 1) {
            load(Prefs.proxy.let {
                ProxyConfig(a.app.type, "127.0.0.1", a.app.port, "", "", it.dnsViaProxy, it.dnsServer, it.udpDirect, it.directIfDown)
            })
            testOut.text = "Подставлено. Включите в ${a.label} режим прокси и нажмите «Сохранить»."
        }, lp(WRAP, WRAP))
        row.addView(top)
        row.addView(text(a.app.howTo, 12.5f, Pal.sub), lp().apply { topMargin = dp(4) })
        return row
    }

    private fun setType(t: ProxyType) {
        type = t
        for (p in typePills) stylePill(p, if (p.tag == t) 0 else 3)
        fields.alpha = if (t == ProxyType.NONE) 0.45f else 1f
        udpDirect.isEnabled = t != ProxyType.NONE
    }

    private fun load(c: ProxyConfig) {
        setType(c.type)
        host.setText(c.host)
        port.setText(if (c.port > 0) c.port.toString() else "")
        user.setText(c.user)
        pass.setText(c.pass)
        dns.isChecked = c.dnsViaProxy
        dnsServer.setText(c.dnsServer)
        udpDirect.isChecked = c.udpDirect
        directIfDown.isChecked = c.directIfDown
    }

    /** Reads the form; returns null (and explains) when it is invalid. */
    private fun read(): ProxyConfig? {
        val p = port.text.toString().trim().toIntOrNull() ?: 0
        val h = host.text.toString().trim().ifEmpty { "127.0.0.1" }
        val d = dnsServer.text.toString().trim().ifEmpty { "1.1.1.1" }
        if (type != ProxyType.NONE) {
            if (p !in 1..65535) {
                toast("Укажите порт прокси (1–65535)")
                return null
            }
            if (Upstream.ipOrNull(d) == null) {
                toast("DNS-сервер должен быть IP-адресом, например 1.1.1.1")
                return null
            }
        }
        return ProxyConfig(type, h, p, user.text.toString(), pass.text.toString(), dns.isChecked, d, udpDirect.isChecked, directIfDown.isChecked)
    }

    private fun save() {
        val c = read() ?: return
        Prefs.proxy = c
        FirewallService.applyProxy()
        toast(if (c.enabled) "Сохранено: трафик пойдёт через прокси" else "Сохранено: трафик идёт напрямую")
        renderStatus()
    }

    private fun test() {
        val c = read() ?: return
        if (c.type == ProxyType.NONE) {
            toast("Выберите тип прокси")
            return
        }
        testOut.setTextColor(Pal.sub)
        testOut.text = "Проверяю…"
        val svc = FirewallService.instance
        Bg.run({
            val addr = Upstream.ipOrNull(c.host) ?: if (c.host.equals("localhost", true)) InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            else svc?.resolve(c.host) ?: InetAddress.getByName(c.host)
            // While our VPN runs, test sockets must bypass it, exactly like the engine's own sockets.
            val t = ProxyTester({ s -> svc?.protect(s) ?: true }, { s -> svc?.protect(s) ?: true })
            t.run(c, InetSocketAddress(addr, c.port))
        }, { r ->
            testOut.setTextColor(if (r.ok) Pal.ok else Pal.danger)
            testOut.text = r.lines.joinToString("\n")
        }, {
            testOut.setTextColor(Pal.danger)
            testOut.text = "✗ не удалось проверить: адрес прокси не найден"
        })
    }

    private fun renderStatus() {
        val cfg = Prefs.proxy
        val up = FirewallService.instance?.upstream
        val sb = StringBuilder()
        when {
            !FirewallService.running -> sb.append("Защита выключена.")
            !cfg.enabled -> sb.append("Защита включена, трафик идёт напрямую.")
            else -> {
                sb.append("Защита включена, трафик идёт через ${cfg.type.name} ${cfg.host}:${cfg.port}.")
                if (up != null) {
                    val now = System.currentTimeMillis()
                    if (up.lastErrorAt > up.lastOkAt && now - up.lastErrorAt < 60_000) {
                        sb.append("\n⚠ ").append(up.lastError ?: "ошибка прокси")
                    } else if (up.lastOkAt > 0) {
                        sb.append("\n✓ прокси работает (последнее соединение ${Fmt.ago(up.lastOkAt)})")
                    }
                    if (up.proxyUid >= 0) {
                        sb.append("\nПрокси обслуживает «${Apps.forUid(up.proxyUid).label}»: его собственный трафик идёт напрямую, без петли.")
                    }
                    if (up.udpUnsupported) sb.append("\nПрокси не передаёт UDP" + if (cfg.udpDirect) " — UDP идёт напрямую." else " — UDP блокируется.")
                }
            }
        }
        status.text = sb.toString()
        otherVpn.text = if (!FirewallService.running && otherVpnActive()) "Сейчас включён другой VPN. Переведите его в режим прокси, " +
            "заполните настройки ниже и включите Стража." else ""
    }

    private fun otherVpnActive(): Boolean {
        val cm = getSystemService(ConnectivityManager::class.java)
        @Suppress("DEPRECATION")
        return cm.allNetworks.any { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()
}
