package lab.netstrazh.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import lab.netstrazh.data.Apps
import lab.netstrazh.data.Db
import lab.netstrazh.data.DestRow
import lab.netstrazh.data.LogRow
import lab.netstrazh.data.Rules
import lab.netstrazh.data.SysStats
import lab.netstrazh.vpn.FirewallService
import lab.netstrazh.vpn.Live

/** Everything about one app: firewall switches, traffic, where it connects to. */
class AppActivity : Activity() {
    private var uid = -1
    private lateinit var info: Apps.Info
    private lateinit var wifi: TextView
    private lateinit var mobile: TextView
    private lateinit var exclude: Switch
    private lateinit var ruleNote: TextView
    private lateinit var trafficBox: LinearLayout
    private lateinit var liveBox: LinearLayout
    private lateinit var destBox: LinearLayout
    private lateinit var hostsBox: LinearLayout
    private lateinit var dnsBox: LinearLayout
    private lateinit var recentBox: LinearLayout
    private var updating = false
    private val handler = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            renderLive()
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Pal.init(this)
        MainActivity.styleWindow(this)
        uid = intent.getIntExtra(EXTRA_UID, -1)
        info = Apps.forUid(uid)

        val col = vbox().apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        val scroll = ScrollView(this).apply {
            setBackgroundColor(Pal.bg)
            addView(col)
        }

        val back = text("←  Назад", 15f, Pal.accent, bold = true).apply {
            setPadding(dp(4), dp(10), dp(12), dp(10))
            setOnClickListener { finish() }
        }
        col.addView(back, lp(WRAP, WRAP))

        val head = hbox().apply { setPadding(0, dp(6), 0, dp(14)) }
        head.addView(ImageView(this).apply {
            setImageDrawable(Apps.icon(info.pkg) ?: getDrawable(android.R.drawable.sym_def_app_icon))
        }, lp(dp(56), dp(56)))
        val names = vbox()
        names.addView(text(info.label, 20f, bold = true))
        names.addView(text((info.pkg ?: "системный компонент") + " · UID $uid", 12.5f, Pal.sub))
        head.addView(names, lp(0, WRAP, 1f).apply { leftMargin = dp(14) })
        col.addView(head)

        // --- firewall
        val fw = card()
        fw.addView(text("Файрвол", 16f, bold = true))
        ruleNote = text("", 13f, Pal.sub)
        fw.addView(ruleNote, lp().apply { topMargin = dp(4) })
        val pills = hbox()
        wifi = pill("Wi-Fi", 3) { toggle(Rules.WIFI) }
        mobile = pill("Мобильный интернет", 3) { toggle(Rules.MOBILE) }
        pills.addView(wifi, lp(WRAP, WRAP).apply { rightMargin = dp(8) })
        pills.addView(mobile, lp(WRAP, WRAP))
        fw.addView(pills, lp().apply { topMargin = dp(10) })
        val exRow = hbox().apply { setPadding(0, dp(12), 0, 0) }
        val exText = vbox()
        exText.addView(text("Пускать мимо Стража", 14.5f, bold = true))
        exText.addView(text("Трафик приложения не проходит через Страж: не отслеживается и не блокируется. " +
            "Полезно, если приложение (например, банк) не работает с VPN.", 12.5f, Pal.sub))
        exRow.addView(exText, lp(0, WRAP, 1f))
        exclude = Switch(this).apply {
            setOnCheckedChangeListener { _, on -> if (!updating) setExclude(on) }
        }
        exRow.addView(exclude, lp(WRAP, WRAP).apply { leftMargin = dp(8) })
        fw.addView(exRow)
        col.addView(fw)

        trafficBox = section(col, "Трафик (данные Android)")
        liveBox = section(col, "Сейчас")
        destBox = section(col, "Куда подключалось")
        hostsBox = section(col, "Заблокированные адреса")
        dnsBox = section(col, "Какие адреса запрашивало (DNS)")
        recentBox = section(col, "Последние соединения")

        setContentView(scroll)
        renderRules()
        renderHosts()
    }

    override fun onResume() {
        super.onResume()
        renderRules()
        loadAll()
        handler.post(ticker)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    private fun section(col: LinearLayout, title: String): LinearLayout {
        val c = card()
        c.addView(text(title, 16f, bold = true))
        val body = vbox()
        c.addView(body, lp().apply { topMargin = dp(6) })
        col.addView(c, lp().apply { topMargin = dp(12) })
        return body
    }

    private fun line(box: LinearLayout, main: String, sub: String? = null, color: Int = Pal.text, subColor: Int = Pal.sub) {
        val v = vbox().apply { setPadding(0, dp(6), 0, dp(6)) }
        v.addView(text(main, 14f, color))
        if (!sub.isNullOrEmpty()) v.addView(text(sub, 12.5f, subColor))
        box.addView(v)
    }

    // ------------------------------------------------------------ firewall

    // System components share a UID (1000 runs dozens of services): they can be blocked too, as a whole.
    private val canRule: Boolean get() = info.pkg != null && uid != android.os.Process.myUid()
    private val systemUid: Boolean get() = uid % 100000 < 10000

    /** All packages of this UID; for "Система Android" Apps lists none, so ask the package manager. */
    private val uidPkgs: List<String> by lazy { info.pkgs.ifEmpty { Apps.packagesForUid(uid) } }

    private fun currentFlags(): Int = uidPkgs.fold(0) { a, p -> a or Rules.flags(p) }.let {
        if (uidPkgs.isEmpty()) Rules.flagsForUid(uid) else it
    }

    private fun setFlags(f: Int) {
        val pkg = info.pkg ?: return
        val adds = f and Rules.BLOCK_ALL and currentFlags().inv() != 0
        if (adds && systemUid) {
            confirmSystemBlock(this, info.label, uid, uidPkgs) { applyFlags(pkg, f) }
            return
        }
        applyFlags(pkg, f)
    }

    private fun applyFlags(pkg: String, f: Int) {
        // Shared-UID apps: keep the rule on the main package only.
        for (p in uidPkgs) if (p != pkg && Rules.flags(p) != 0) Rules.set(p, 0)
        Rules.set(pkg, f)
        renderRules()
    }

    private fun toggle(bit: Int) {
        if (!canRule) return
        setFlags((currentFlags() and Rules.EXCLUDE.inv()) xor bit)
    }

    private fun setExclude(on: Boolean) {
        if (!canRule) return
        setFlags(if (on) Rules.EXCLUDE else 0)
    }

    private fun renderRules() {
        val f = currentFlags()
        updating = true
        exclude.isChecked = f and Rules.EXCLUDE != 0
        updating = false
        stylePill(wifi, if (f and Rules.WIFI != 0) 4 else 3)
        stylePill(mobile, if (f and Rules.MOBILE != 0) 4 else 3)
        wifi.text = if (f and Rules.WIFI != 0) "⛔ Wi-Fi" else "Wi-Fi"
        mobile.text = if (f and Rules.MOBILE != 0) "⛔ Мобильный" else "Мобильный"
        val excluded = f and Rules.EXCLUDE != 0
        wifi.isEnabled = canRule && !excluded
        mobile.isEnabled = canRule && !excluded
        exclude.isEnabled = canRule
        wifi.alpha = if (wifi.isEnabled) 1f else 0.4f
        mobile.alpha = if (mobile.isEnabled) 1f else 0.4f
        ruleNote.text = when {
            !canRule -> if (info.pkg == null) "Это служба ядра Android без пакета — её блокировка не поддерживается."
                else "Это сам Сетевой страж."
            excluded -> "Приложение идёт мимо Стража."
            f and Rules.BLOCK_ALL == Rules.BLOCK_ALL -> "Интернет запрещён. Нажмите, чтобы разрешить."
            f and Rules.WIFI != 0 -> "Запрещён Wi-Fi. Мобильный интернет разрешён."
            f and Rules.MOBILE != 0 -> "Запрещён мобильный интернет. Wi-Fi разрешён."
            else -> "Доступ в интернет разрешён. Нажмите на сеть, чтобы запретить." +
                if (systemUid) "\nЭто системный UID: блокировка действует на все его службы сразу. " +
                    "Точнее — блокировать отдельные адреса в списке «Куда подключалось»." else ""
        } + if (!FirewallService.running && canRule) "\n⚠ Защита выключена — правила не действуют." else ""
    }

    // ------------------------------------------------------------ host rules

    private fun renderHosts() {
        hostsBox.removeAllViews()
        val pkg = info.pkg
        val own = if (pkg != null) Rules.blockedHosts(pkg) else emptySet()
        val all = Rules.blockedHosts(Rules.ALL)
        if (own.isEmpty() && all.isEmpty()) {
            line(hostsBox, "Нет", if (pkg != null) "Нажмите на адрес в списке «Куда подключалось» или «DNS», чтобы заблокировать его." else null)
            return
        }
        for (h in own.sorted()) hostLine(h, "для этого приложения · нажмите, чтобы разблокировать") { Rules.setHostBlocked(pkg!!, h, false) }
        for (h in all.sorted()) hostLine(h, "для всех приложений · нажмите, чтобы разблокировать") { Rules.setHostBlocked(Rules.ALL, h, false) }
    }

    private fun hostLine(host: String, sub: String, unblock: () -> Unit) {
        line(hostsBox, "⛔ $host", sub, subColor = Pal.danger)
        hostsBox.getChildAt(hostsBox.childCount - 1).setOnClickListener {
            unblock()
            renderHosts()
            toast("$host разблокирован")
        }
    }

    /** Offers to block a host this app talked to (the exact name, or its whole domain). */
    private fun askBlockHost(host: String?) {
        val h = host?.let { Rules.normalizeHost(it) }
        if (h.isNullOrEmpty() || lab.netstrazh.vpn.Engine.isIpLiteral(h)) {
            toast("Блокировать можно адрес с именем, а не голый IP")
            return
        }
        val pkg = info.pkg
        val parent = parentDomain(h)
        val labels = ArrayList<String>()
        val actions = ArrayList<() -> Unit>()
        if (pkg != null && Rules.hostBlocked(uid, h)) {
            toast("$h уже заблокирован")
            return
        }
        if (pkg != null) {
            labels += "$h — для «${info.label}»"
            actions += { Rules.setHostBlocked(pkg, h, true) }
            if (parent != null) {
                labels += "весь $parent — для «${info.label}»"
                actions += { Rules.setHostBlocked(pkg, parent, true) }
            }
        }
        labels += "$h — для всех приложений"
        actions += { Rules.setHostBlocked(Rules.ALL, h, true) }
        if (parent != null) {
            labels += "весь $parent — для всех приложений"
            actions += { Rules.setHostBlocked(Rules.ALL, parent, true) }
        }
        android.app.AlertDialog.Builder(this)
            .setTitle("Заблокировать адрес")
            .setItems(labels.toTypedArray()) { _, i ->
                actions[i]()
                renderHosts()
                toast("Заблокировано. Работает, пока включена защита.")
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    private fun toast(s: String) = android.widget.Toast.makeText(this, s, android.widget.Toast.LENGTH_SHORT).show()

    // ------------------------------------------------------------ data

    private fun loadAll() {
        if (SysStats.hasUsageAccess(this)) {
            Bg.run({
                val now = System.currentTimeMillis()
                val c = java.util.Calendar.getInstance().apply {
                    set(java.util.Calendar.HOUR_OF_DAY, 0); set(java.util.Calendar.MINUTE, 0)
                    set(java.util.Calendar.SECOND, 0); set(java.util.Calendar.MILLISECOND, 0)
                }
                val today = SysStats.traffic(this, c.timeInMillis, now)[uid]
                val month = SysStats.traffic(this, now - 30 * 86_400_000L, now)[uid]
                val states = SysStats.appStates(this)
                Triple(today ?: SysStats.Usage(uid), month ?: SysStats.Usage(uid), info.pkgs.mapNotNull { states[it] }.maxByOrNull { it.lastUsed })
            }) { (today, month, state) ->
                trafficBox.removeAllViews()
                line(trafficBox, "Сегодня: ↓ ${Fmt.bytes(today.rx)} ↑ ${Fmt.bytes(today.tx)}",
                    "Wi-Fi ${Fmt.bytes(today.rxWifi + today.txWifi)} · моб. ${Fmt.bytes(today.rxMobile + today.txMobile)}")
                line(trafficBox, "30 дней: ↓ ${Fmt.bytes(month.rx)} ↑ ${Fmt.bytes(month.tx)}",
                    "Wi-Fi ${Fmt.bytes(month.rxWifi + month.txWifi)} · моб. ${Fmt.bytes(month.rxMobile + month.txMobile)}")
                if (state != null) line(trafficBox, when {
                    state.onScreen -> "Сейчас на экране"
                    state.service -> "Работает в фоне"
                    state.lastUsed > 0 -> "Запускалось " + Fmt.ago(state.lastUsed)
                    else -> "Не запускалось последние 30 дней"
                })
            }
        } else {
            trafficBox.removeAllViews()
            line(trafficBox, "Нет доступа к истории использования", "Разрешите его на вкладке «Трафик».")
        }
        Bg.run({ Triple(Db.destinations(uid), Db.dnsNames(uid), Db.recentForUid(uid, 60)) }) { (dest, dns, recent) ->
            renderDest(dest)
            renderDns(dns)
            renderRecent(recent)
        }
    }

    private fun renderLive() {
        liveBox.removeAllViews()
        if (!FirewallService.running) {
            line(liveBox, "Защита выключена", "Включите её, чтобы видеть соединения в реальном времени.")
            return
        }
        val conns = Live.active.values.filter { it.uid == uid && it.proto != "DNS" }.sortedByDescending { it.start }
        val st = Live.stats[uid]
        if (st != null) line(liveBox, "С момента включения: ↓ ${Fmt.bytes(st.rx.get())} ↑ ${Fmt.bytes(st.tx.get())}",
            "соединений: ${st.conns.get()}" + if (st.blocked.get() > 0) " · заблокировано: ${st.blocked.get()}" else "")
        if (conns.isEmpty()) {
            line(liveBox, "Активных соединений нет")
            return
        }
        for (c in conns.take(30)) {
            if (c.blocked) {
                line(liveBox, Fmt.dest(c.host, c.ip, c.port) + " · " + c.proto, "⛔ заблокировано", subColor = Pal.danger)
            } else {
                line(liveBox, Fmt.dest(c.host, c.ip, c.port) + " · " + c.proto,
                    "↑ ${Fmt.bytes(c.tx)} ↓ ${Fmt.bytes(c.rx)} · ${Fmt.duration(System.currentTimeMillis() - c.start)}" +
                        if (c.via == lab.netstrazh.vpn.VIA_PROXY) " · через прокси" else "")
            }
        }
    }

    private fun renderDest(rows: List<DestRow>) {
        destBox.removeAllViews()
        if (rows.isEmpty()) {
            line(destBox, "Пока нет записей", "Записи появляются, когда защита включена.")
            return
        }
        for (r in rows.take(100)) {
            val main = Fmt.dest(r.host, r.ip, r.port) + " · " + r.proto
            val sub = buildString {
                if (!r.host.isNullOrEmpty() && r.host != r.ip) append(r.ip).append(" · ")
                append("раз: ").append(r.count)
                append(" · ↑ ").append(Fmt.bytes(r.tx)).append(" ↓ ").append(Fmt.bytes(r.rx))
                append(" · ").append(Fmt.ago(r.last))
                if (r.blocked > 0) append(" · ⛔ ").append(r.blocked)
            }
            line(destBox, main, sub, subColor = if (r.blocked > 0 && r.blocked == r.count) Pal.danger else Pal.sub)
            destBox.getChildAt(destBox.childCount - 1).setOnClickListener { askBlockHost(r.host) }
        }
    }

    private fun renderDns(rows: List<DestRow>) {
        dnsBox.removeAllViews()
        if (rows.isEmpty()) {
            line(dnsBox, "Пока нет записей")
            return
        }
        for (r in rows.take(100)) {
            line(dnsBox, r.host ?: "?", "раз: ${r.count} · ${Fmt.ago(r.last)}" + if (r.ip.isNotEmpty()) " · → ${r.ip}" else "")
            dnsBox.getChildAt(dnsBox.childCount - 1).setOnClickListener { askBlockHost(r.host) }
        }
    }

    private fun renderRecent(rows: List<LogRow>) {
        recentBox.removeAllViews()
        if (rows.isEmpty()) {
            line(recentBox, "Пока нет записей")
            return
        }
        for (r in rows) {
            val main = if (r.proto == "DNS") "DNS: ${r.host ?: "?"}" else Fmt.dest(r.host, r.ip, r.port) + " · " + r.proto
            val sub = Fmt.time(r.ts) + " · " + Fmt.net(r.net) + when {
                r.blocked -> " · ⛔ заблокировано"
                r.note != null && r.tx == 0L && r.rx == 0L -> " · ✗ ${r.note}"
                r.proto == "DNS" -> if (r.ip.isNotEmpty()) " · → ${r.ip}" else ""
                else -> " · ↑ ${Fmt.bytes(r.tx)} ↓ ${Fmt.bytes(r.rx)}"
            }
            line(recentBox, main, sub, subColor = if (r.blocked) Pal.danger else Pal.sub)
        }
    }

    companion object {
        private const val EXTRA_UID = "uid"

        /** "a.b.example.com" -> "example.com" ("x.co.uk" -> "x.co.uk"); null when [h] is that domain already. */
        fun parentDomain(h: String): String? {
            val parts = h.split('.')
            if (parts.size < 3) return null
            val tld = parts[parts.size - 1]
            val sld = parts[parts.size - 2]
            val keep = if (tld.length == 2 && sld.length <= 3 && parts.size >= 4) 3 else 2
            if (parts.size <= keep) return null
            return parts.takeLast(keep).joinToString(".")
        }

        /** Asks before blocking a system UID: all of its services lose the network at once. */
        fun confirmSystemBlock(ctx: Context, label: String, uid: Int, pkgs: List<String>, onYes: () -> Unit) {
            val names = pkgs.take(8).joinToString("\n") { "• $it" } + if (pkgs.size > 8) "\n• …и ещё ${pkgs.size - 8}" else ""
            android.app.AlertDialog.Builder(ctx)
                .setTitle("Заблокировать системный UID ${uid % 100000}?")
                .setMessage("«$label» — общий UID для системных служб" +
                    (if (pkgs.isNotEmpty()) ":\n$names" else ".") +
                    "\n\nБлокировка запретит сеть им всем сразу (у Xiaomi там обычно обновления системы, " +
                    "«Безопасность», «Найти устройство», облако). Что-то из этого может перестать работать. " +
                    "Снять блокировку можно в любой момент.\n\nТочнее — блокировать отдельные адреса: " +
                    "откройте «Система Android» и нажмите на адрес в списке «Куда подключалось».")
                .setPositiveButton("Заблокировать") { _, _ -> onYes() }
                .setNegativeButton("Отмена", null)
                .show()
        }

        fun open(ctx: Context, uid: Int) {
            ctx.startActivity(Intent(ctx, AppActivity::class.java).putExtra(EXTRA_UID, uid))
        }
    }
}
