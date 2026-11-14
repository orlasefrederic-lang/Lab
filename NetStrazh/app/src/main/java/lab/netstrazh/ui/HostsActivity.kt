package lab.netstrazh.ui

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.FrameLayout
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import lab.netstrazh.Prefs
import lab.netstrazh.R
import lab.netstrazh.data.Apps
import lab.netstrazh.data.Db
import lab.netstrazh.data.Rules
import lab.netstrazh.data.StoppedRow
import lab.netstrazh.vpn.Engine
import lab.netstrazh.vpn.FirewallService

/**
 * "Заблокированные адреса": every blocked address in one place: whom it is blocked for, since when
 * and what the block has stopped. A tap unblocks it.
 */
class HostsActivity : Activity() {
    /**
     * A rule as it is shown: [who] names the app in words, [pkg] gives its icon, [uid] opens its card
     * (both null when there is no single installed app behind the rule); [stopped] attempts were
     * stopped by it as far as the journal goes back (-1: not counted yet), the [last] one then.
     */
    class Item(val rule: Rules.HostRule, val who: String, val pkg: String?, val uid: Int?, val stopped: Int, val last: Long)

    private val adapter by lazy { ListAdapter<Item>({ RowView(this) }) { v, it, _ -> bind(v as RowView, it) } }
    private lateinit var empty: View
    private lateinit var warn: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Pal.init(this)
        MainActivity.styleWindow(this)
        val root = vbox().apply { setBackgroundColor(Pal.bg) }
        val head = hbox().apply { setPadding(dp(12), dp(8), dp(16), dp(4)) }
        head.addView(text("←", 22f, Pal.accent, bold = true).apply {
            setPadding(dp(8), dp(4), dp(16), dp(4))
            setOnClickListener { finish() }
        })
        head.addView(text("Заблокированные адреса", 19f, bold = true), lp(0, WRAP, 1f))
        root.addView(head)
        root.addView(text("Адрес закрыт вместе с поддоменами: правило google.com закрывает и www.google.com. " +
            "Нажмите на строку, чтобы разблокировать.", 13f, Pal.sub), lp().apply { setMargins(dp(20), dp(2), dp(20), dp(6)) })
        warn = text("⚠ Защита выключена — блокировка сейчас не действует.", 13f, Pal.danger)
        root.addView(warn, lp().apply { setMargins(dp(20), 0, dp(20), dp(6)) })

        val list = ListView(this).apply {
            divider = null
            adapter = this@HostsActivity.adapter
            setOnItemClickListener { _, _, pos, _ ->
                val it = this@HostsActivity.adapter.items[pos]
                confirmUnblock(this@HostsActivity, it, openApp = true) { load() }
            }
        }
        empty = placeholder("Заблокированных адресов нет.\n\nЧтобы заблокировать адрес, откройте приложение (нажмите на него " +
            "в любом списке) и нажмите на адрес в «Куда подключалось» или «Какие адреса запрашивало».")
        val frame = FrameLayout(this)
        frame.addView(list)
        frame.addView(empty)
        root.addView(frame, lp(MATCH, 0, 1f))
        setContentView(root)
    }

    override fun onResume() {
        super.onResume()
        load()
    }

    private fun load() {
        warn.visibility = if (FirewallService.running) View.GONE else View.VISIBLE
        val rules = Rules.hostRules()
        // Shown at once; what each rule has stopped is filled in when the journal has been read.
        show(items(rules, null))
        Bg.run({ items(rules, Db.stopped(Engine.NOTE_HOST_BLOCKED)) }) { if (!isDestroyed) show(it) }
    }

    private fun show(items: List<Item>) {
        adapter.items = items
        empty.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun bind(v: RowView, it: Item) {
        v.title.text = "⛔ " + it.rule.host
        v.icon.setImageDrawable(Apps.icon(it.pkg)
            ?: getDrawable(if (it.rule.key == Rules.ALL) R.mipmap.ic_launcher else android.R.drawable.sym_def_app_icon))
        v.line2.text = it.who
        v.setLine3(details(it, " · "))
        v.right1.text = "Снять"
        v.right1.setTextColor(Pal.accent)
        v.right2.text = ""
    }

    companion object {
        /**
         * The rules as shown, newest first; rules whose time was not recorded come last. [stopped] is
         * what the journal holds of attempts stopped by host rules, or null while it is being read.
         */
        fun items(rules: List<Rules.HostRule>, stopped: List<StoppedRow>?): List<Item> =
            rules.map { r ->
                val hits = stopped?.filter { (r.key == Rules.ALL || r.appId == it.appId) && r.covers(Rules.normalizeHost(it.host)) }
                val n = hits?.sumOf { it.count } ?: -1
                val last = hits?.maxOfOrNull { it.last } ?: 0L
                val uidKey = Rules.uidOfKey(r.key)
                val app = if (r.key == Rules.ALL || uidKey != null) null else Apps.forPackage(r.key)
                when {
                    r.key == Rules.ALL -> Item(r, "для всех приложений", null, null, n, last)
                    uidKey != null -> Item(r, "для «${Apps.forUid(uidKey).label}»", null, uidKey, n, last)
                    app != null -> Item(r, "для «${Apps.labelForPackage(r.key)}»", r.key, app.uid, n, last)
                    else -> Item(r, "для «${r.key}» (приложение удалено)", null, null, n, last)
                }
            }.sortedWith(compareByDescending<Item> { it.rule.since }.thenBy { it.rule.host }.thenBy { it.who })

        fun sinceText(r: Rules.HostRule): String =
            if (r.since > 0) "заблокирован " + Fmt.since(r.since) else "заблокирован до версии 3.5, время не записано"

        /** What the rule has stopped; empty while that is not counted yet. */
        fun stoppedText(it: Item): String = when {
            it.stopped < 0 -> ""
            it.stopped == 0 -> "попыток не было"
            else -> "остановлено попыток: ${it.stopped}, последняя ${Fmt.ago(it.last)}"
        }

        /** Since when the rule is there and what it has stopped, joined by [sep]. */
        fun details(it: Item, sep: String): String =
            listOf(sinceText(it.rule), stoppedText(it)).filter { s -> s.isNotEmpty() }.joinToString(sep)

        /** Asks, then removes the rule. [openApp] adds a button to the app's card (for the list of all rules). */
        fun confirmUnblock(ctx: Context, it: Item, openApp: Boolean, onDone: () -> Unit) {
            val stopped = stoppedText(it)
            val b = android.app.AlertDialog.Builder(ctx)
                .setTitle("Разблокировать ${it.rule.host}?")
                .setMessage("Сейчас этот адрес и его поддомены закрыты ${it.who}.\n\n" +
                    sinceText(it.rule).replaceFirstChar { c -> c.uppercase() } + "." +
                    if (stopped.isEmpty()) "" else "\n" + stopped.replaceFirstChar { c -> c.uppercase() } +
                        " (журнал хранит ${Prefs.logDays} дн.).")
                .setPositiveButton("Разблокировать") { _, _ ->
                    Rules.setHostBlocked(it.rule.key, it.rule.host, false)
                    Toast.makeText(ctx, "${it.rule.host} разблокирован", Toast.LENGTH_SHORT).show()
                    onDone()
                }
                .setNegativeButton("Отмена", null)
            val uid = it.uid
            if (openApp && uid != null) b.setNeutralButton("Приложение") { _, _ -> AppActivity.open(ctx, uid) }
            b.show()
        }
    }
}
