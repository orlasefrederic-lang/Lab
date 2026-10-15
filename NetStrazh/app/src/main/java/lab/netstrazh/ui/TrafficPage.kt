package lab.netstrazh.ui

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.View
import android.widget.FrameLayout
import android.widget.ListView
import android.widget.TextView
import lab.netstrazh.Prefs
import lab.netstrazh.data.Apps
import lab.netstrazh.data.Rules
import lab.netstrazh.data.SysStats
import java.util.Calendar

/** "Трафик": per-app data usage from Android's own statistics (works even when protection is off). */
class TrafficPage(act: MainActivity) : Page(act) {
    private class Item(val usage: SysStats.Usage, val info: Apps.Info, val state: SysStats.AppState?)

    private val chips = ArrayList<TextView>()
    private val summary = act.text("", 13.5f, Pal.sub)
    private val list = ListView(act)
    private val adapter = ListAdapter<Item>({ RowView(act) }) { v, it, _ -> bind(v as RowView, it) }
    private val noAccess = act.placeholder(
        "Чтобы показать, сколько трафика потратило каждое приложение за день, неделю или месяц, " +
            "и когда приложения запускались, нужно разрешение «Доступ к истории использования».\n\n" +
            "Откроются настройки: найдите там «Сетевой страж» и включите доступ.",
        "Открыть настройки"
    ) { openUsageSettings() }
    private var ticks = 0
    private var loading = false

    override val view: View = act.vbox().apply {
        val bar = act.hbox().apply { setPadding(act.dp(16), 0, act.dp(16), act.dp(6)) }
        for ((i, n) in listOf("Сегодня", "7 дней", "30 дней").withIndex()) {
            val c = act.pill(n, if (i == Prefs.trafficPeriod) 0 else 3) { setPeriod(i) }
            c.tag = i
            chips += c
            bar.addView(c, lp(WRAP, WRAP).apply { rightMargin = act.dp(8) })
        }
        addView(bar)
        addView(summary, lp().apply { setMargins(act.dp(20), act.dp(2), act.dp(20), act.dp(8)) })
        list.divider = null
        list.adapter = adapter
        list.setOnItemClickListener { _, _, pos, _ -> AppActivity.open(act, adapter.items[pos].usage.uid) }
        val frame = FrameLayout(act)
        frame.addView(list)
        frame.addView(noAccess)
        addView(frame, lp(MATCH, 0, 1f))
    }

    private fun setPeriod(i: Int) {
        Prefs.trafficPeriod = i
        for (c in chips) act.stylePill(c, if (c.tag == i) 0 else 3)
        load()
    }

    override fun onShow() = load()

    override fun tick() {
        if (++ticks % 20 == 0) load()
    }

    private fun openUsageSettings() {
        val i = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
        try {
            act.startActivity(Intent(i).setData(Uri.parse("package:" + act.packageName)))
        } catch (_: Exception) {
            try { act.startActivity(i) } catch (_: Exception) {}
        }
    }

    private fun load() {
        val access = SysStats.hasUsageAccess(act)
        noAccess.visibility = if (access) View.GONE else View.VISIBLE
        summary.visibility = if (access) View.VISIBLE else View.GONE
        if (!access || loading) return
        loading = true
        val (start, end) = range(Prefs.trafficPeriod)
        Bg.run({
            val usage = SysStats.traffic(act, start, end)
            val states = SysStats.appStates(act)
            usage.values.filter { it.total > 0 }.map { u ->
                val info = Apps.forUid(u.uid)
                Item(u, info, info.pkgs.mapNotNull { states[it] }.maxByOrNull { it.lastUsed })
            }.sortedByDescending { it.usage.total }
        }, { items ->
            loading = false
            adapter.items = items
            var rx = 0L; var tx = 0L; var wifi = 0L; var mob = 0L
            for (it in items) {
                rx += it.usage.rx; tx += it.usage.tx
                wifi += it.usage.rxWifi + it.usage.txWifi
                mob += it.usage.rxMobile + it.usage.txMobile
            }
            summary.text = "Всего: ↓ ${Fmt.bytes(rx)} ↑ ${Fmt.bytes(tx)}\nWi-Fi: ${Fmt.bytes(wifi)} · мобильный интернет: ${Fmt.bytes(mob)}"
        }, { loading = false })
    }

    private fun range(period: Int): Pair<Long, Long> {
        val now = System.currentTimeMillis()
        return when (period) {
            0 -> {
                val c = Calendar.getInstance()
                c.set(Calendar.HOUR_OF_DAY, 0); c.set(Calendar.MINUTE, 0); c.set(Calendar.SECOND, 0); c.set(Calendar.MILLISECOND, 0)
                c.timeInMillis to now
            }
            1 -> now - 7 * 86_400_000L to now
            else -> now - 30 * 86_400_000L to now
        }
    }

    private fun bind(v: RowView, it: Item) {
        v.setApp(it.info)
        val u = it.usage
        v.right1.text = Fmt.bytes(u.total)
        v.right1.setTextColor(Pal.text)
        v.right2.text = if (Rules.flagsForUid(u.uid) and Rules.BLOCK_ALL != 0) "⛔ блок" else ""
        v.right2.setTextColor(Pal.danger)
        v.line2.text = "↓ ${Fmt.bytes(u.rx)} ↑ ${Fmt.bytes(u.tx)} · Wi-Fi ${Fmt.bytes(u.rxWifi + u.txWifi)} · моб. ${Fmt.bytes(u.rxMobile + u.txMobile)}"
        val s = it.state
        when {
            s == null -> v.setLine3(null)
            s.onScreen -> v.setLine3("● сейчас на экране", Pal.ok)
            s.service -> v.setLine3("● работает в фоне", Pal.ok)
            s.lastUsed > 0 -> v.setLine3("запускалось " + Fmt.ago(s.lastUsed))
            else -> v.setLine3(null)
        }
    }
}
