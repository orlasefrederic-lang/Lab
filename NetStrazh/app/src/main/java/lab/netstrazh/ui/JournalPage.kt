package lab.netstrazh.ui

import android.app.AlertDialog
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ListView
import android.widget.TextView
import lab.netstrazh.data.Apps
import lab.netstrazh.data.Db
import lab.netstrazh.data.LogRow
import lab.netstrazh.vpn.Conn
import lab.netstrazh.vpn.Live

/** "Журнал": every connection, DNS query and blocked attempt. */
class JournalPage(act: MainActivity) : Page(act) {
    private var filter = Db.F_ALL
    private val chips = ArrayList<TextView>()
    private val search = EditText(act)
    private val list = ListView(act)
    private val empty = act.placeholder("Журнал пуст.\n\nЗдесь появятся все соединения приложений, когда защита включена.")
    private val adapter = ListAdapter<LogRow>({ RowView(act) }) { v, r, _ -> bind(v as RowView, r) }
    private var ticks = 0
    private var loading = false
    private var dirty = false
    private var appIndex: List<Apps.Info>? = null

    override val view: View = act.vbox().apply {
        val bar = act.hbox().apply { setPadding(act.dp(16), 0, act.dp(16), act.dp(6)) }
        val names = listOf("Все" to Db.F_ALL, "Соединения" to Db.F_CONN, "Заблокировано" to Db.F_BLOCKED, "DNS" to Db.F_DNS)
        for ((n, f) in names) {
            val c = act.pill(n, if (f == filter) 0 else 3) { setFilter(f) }
            c.tag = f
            chips += c
            bar.addView(c, lp(WRAP, WRAP).apply { rightMargin = act.dp(8) })
        }
        bar.addView(act.pill("Очистить", 2) { confirmClear() }, lp(WRAP, WRAP))
        addView(HorizontalScrollView(act).apply {
            isHorizontalScrollBarEnabled = false
            addView(bar)
        })
        search.hint = "Поиск: приложение, сайт или IP"
        search.textSize = 14.5f
        search.setSingleLine()
        search.setTextColor(Pal.text)
        search.setHintTextColor(Pal.sub)
        search.background = rounded(Pal.surface, act.dpf(12f))
        search.setPadding(act.dp(14), act.dp(10), act.dp(14), act.dp(10))
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) {
                ticks = 0
                load()
            }
        })
        addView(search, lp().apply { setMargins(act.dp(16), act.dp(2), act.dp(16), act.dp(6)) })
        list.divider = null
        list.adapter = adapter
        list.setOnItemClickListener { _, _, pos, _ -> AppActivity.open(act, adapter.items[pos].uid) }
        val frame = FrameLayout(act)
        frame.addView(list)
        frame.addView(empty)
        addView(frame, lp(MATCH, 0, 1f))
    }

    private fun setFilter(f: Int) {
        filter = f
        for (c in chips) act.stylePill(c, if (c.tag == f) 0 else 3)
        load()
    }

    override fun onShow() = load()

    override fun tick() {
        if (++ticks % 3 == 0) load()
    }

    private fun load() {
        if (loading) {
            dirty = true
            return
        }
        loading = true
        dirty = false
        val f = filter
        val q = search.text.toString().trim()
        Bg.run({
            val uids = if (q.isEmpty()) null else {
                val idx = appIndex ?: Apps.installed().also { appIndex = it }
                idx.filter { it.label.contains(q, true) || (it.pkg?.contains(q, true) ?: false) }.map { it.uid }.toSet()
            }
            val live = Live.active.values.filter { c -> matches(c, f, q, uids) }
                .sortedByDescending { it.start }.map { toRow(it) }
            live + Db.recent(f, uids, q.ifEmpty { null })
        }, { rows ->
            loading = false
            adapter.items = rows
            empty.visibility = if (rows.isEmpty()) View.VISIBLE else View.GONE
            if (dirty) load()
        }, { loading = false })
    }

    private fun matches(c: Conn, f: Int, q: String, uids: Set<Int>?): Boolean {
        val okFilter = when (f) {
            Db.F_BLOCKED -> c.blocked
            Db.F_DNS -> c.proto == "DNS"
            Db.F_CONN -> c.proto != "DNS"
            else -> true
        }
        if (!okFilter) return false
        if (q.isEmpty()) return true
        return (c.host?.contains(q, true) ?: false) || c.ip.contains(q, true) || (uids?.contains(c.uid) ?: false)
    }

    private fun toRow(c: Conn) = LogRow(c.start, System.currentTimeMillis(), c.uid, c.proto, c.ip, c.port, c.host,
        c.tx, c.rx, c.blocked, c.net, active = true)

    private fun confirmClear() {
        AlertDialog.Builder(act)
            .setTitle("Очистить журнал?")
            .setMessage("Все записи о соединениях будут удалены. Статистика трафика Android не затрагивается.")
            .setPositiveButton("Очистить") { _, _ -> Bg.run({ Db.clear(); true }) { load() } }
            .setNegativeButton("Отмена", null)
            .show()
    }

    private fun bind(v: RowView, r: LogRow) {
        v.setApp(Apps.forUid(r.uid))
        v.right1.text = Fmt.time(r.ts)
        v.right1.setTextColor(Pal.sub)
        v.right2.text = r.proto
        if (r.proto == "DNS") {
            v.line2.text = "DNS: " + (r.host ?: "?") + if (r.ip.isNotEmpty()) " → " + r.ip else ""
        } else {
            v.line2.text = Fmt.dest(r.host, r.ip, r.port) + if (!r.host.isNullOrEmpty() && r.host != r.ip) " · " + r.ip else ""
        }
        when {
            r.blocked -> v.setLine3("⛔ ЗАБЛОКИРОВАНО · " + Fmt.net(r.net), Pal.danger)
            r.active -> v.setLine3("● активно · ↑ ${Fmt.bytes(r.tx)} ↓ ${Fmt.bytes(r.rx)} · ${Fmt.duration(r.te - r.ts)}", Pal.ok)
            r.proto == "DNS" -> v.setLine3(Fmt.net(r.net))
            else -> v.setLine3("↑ ${Fmt.bytes(r.tx)} ↓ ${Fmt.bytes(r.rx)} · ${Fmt.duration(r.te - r.ts)} · ${Fmt.net(r.net)}")
        }
    }
}
