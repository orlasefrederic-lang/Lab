package lab.netstrazh.ui

import android.os.SystemClock
import android.view.View
import android.widget.FrameLayout
import android.widget.ListView
import lab.netstrazh.data.Apps
import lab.netstrazh.data.Rules
import lab.netstrazh.vpn.FirewallService
import lab.netstrazh.vpn.Live

/** "Сейчас": apps that use the network right now, with live speeds. */
class LivePage(act: MainActivity) : Page(act) {
    private class Item(
        val uid: Int,
        val active: Int,
        val tx: Long,
        val rx: Long,
        val up: Long,
        val down: Long,
        val blocked: Int,
        val lastActive: Long,
        val hosts: String,
    )

    private val summary = act.text("", 13.5f, Pal.sub)
    private val list = ListView(act)
    private val adapter = ListAdapter<Item>({ RowView(act) }) { v, it, _ -> bind(v as RowView, it) }
    private val off = act.placeholder(
        "Защита выключена.\n\nВключите её, чтобы видеть, какие приложения прямо сейчас ходят в интернет, куда и сколько передают.",
        "Включить защиту"
    ) { act.requestStart() }
    private val prev = HashMap<Int, LongArray>()
    private var prevTime = 0L

    override val view: View = FrameLayout(act).apply {
        val col = act.vbox()
        col.addView(summary, lp().apply { setMargins(act.dp(20), act.dp(2), act.dp(20), act.dp(8)) })
        list.divider = null
        list.adapter = adapter
        list.setOnItemClickListener { _, _, pos, _ -> AppActivity.open(act, adapter.items[pos].uid) }
        col.addView(list, lp(MATCH, 0, 1f))
        addView(col)
        addView(off)
    }

    override fun onShow() {
        prev.clear()
        prevTime = 0L
        refresh()
    }

    override fun tick() = refresh()

    private fun refresh() {
        val running = FirewallService.running
        off.visibility = if (running) View.GONE else View.VISIBLE
        if (!running) {
            adapter.items = emptyList()
            return
        }
        val now = SystemClock.elapsedRealtime()
        val dt = if (prevTime == 0L) 0.0 else (now - prevTime) / 1000.0
        val byUid = Live.active.values.groupBy { it.uid }
        var totalUp = 0L
        var totalDown = 0L
        var totalTx = 0L
        var totalRx = 0L
        var totalBlocked = 0
        val items = ArrayList<Item>()
        for ((uid, s) in Live.stats) {
            val tx = s.tx.get()
            val rx = s.rx.get()
            val p = prev[uid]
            val up = if (p != null && dt > 0) ((tx - p[0]) / dt).toLong().coerceAtLeast(0) else 0L
            val down = if (p != null && dt > 0) ((rx - p[1]) / dt).toLong().coerceAtLeast(0) else 0L
            prev[uid] = longArrayOf(tx, rx)
            val conns = byUid[uid].orEmpty()
            val active = conns.count { !it.blocked && it.proto != "DNS" }
            val hosts = conns.asSequence().filter { !it.blocked && it.proto != "DNS" }
                .map { it.host?.takeIf { h -> h.isNotEmpty() } ?: it.ip }.distinct().take(3).joinToString(", ")
            totalUp += up; totalDown += down; totalTx += tx; totalRx += rx
            totalBlocked += s.blocked.get()
            items += Item(uid, active, tx, rx, up, down, s.blocked.get(), s.lastActive, hosts)
        }
        prevTime = now
        items.sortWith(
            compareByDescending<Item> { it.up + it.down }
                .thenByDescending { it.active }
                .thenByDescending { it.lastActive }
        )
        adapter.items = items
        val activeCount = Live.active.values.count { !it.blocked && it.proto != "DNS" }
        summary.text = "Соединений: $activeCount · ↓ ${Fmt.speed(totalDown)} ↑ ${Fmt.speed(totalUp)}\n" +
            "С момента включения: ↓ ${Fmt.bytes(totalRx)} ↑ ${Fmt.bytes(totalTx)}" +
            (if (totalBlocked > 0) " · заблокировано: $totalBlocked" else "")
    }

    private fun bind(v: RowView, it: Item) {
        val info = Apps.forUid(it.uid)
        v.setApp(info)
        val inRules = Rules.flagsForUid(it.uid) and Rules.BLOCK_ALL != 0
        v.line2.text = buildString {
            append(if (it.active > 0) "соединений: ${it.active}" else "нет активных · ${Fmt.ago(it.lastActive)}")
            append(" · ↓ ").append(Fmt.bytes(it.rx)).append(" ↑ ").append(Fmt.bytes(it.tx))
        }
        when {
            it.blocked > 0 -> v.setLine3(
                (if (inRules) "⛔ в блок-листе · " else "") + "заблокировано попыток: ${it.blocked}", Pal.danger)
            it.hosts.isNotEmpty() -> v.setLine3(it.hosts)
            else -> v.setLine3(null)
        }
        v.right1.text = if (it.down > 0) "↓ " + Fmt.speed(it.down) else ""
        v.right1.setTextColor(Pal.accent)
        v.right2.text = if (it.up > 0) "↑ " + Fmt.speed(it.up) else ""
    }
}
