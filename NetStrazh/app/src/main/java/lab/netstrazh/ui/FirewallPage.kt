package lab.netstrazh.ui

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.Toast
import lab.netstrazh.Prefs
import lab.netstrazh.data.Apps
import lab.netstrazh.data.Rules
import lab.netstrazh.vpn.FirewallService

/** "Файрвол": the list of apps that are not allowed to use the internet. */
class FirewallPage(act: MainActivity) : Page(act) {
    private class Item(val pkg: String, val label: String, val flags: Int)

    private val warn = act.text("", 13.5f, Pal.danger)
    private val list = ListView(act)
    private val adapter = ListAdapter<Item>({ RuleRow(act) }) { v, it, _ -> (v as RuleRow).bind(it) }
    private val emptyText = act.text(
        "Список пуст. Нажмите «Добавить приложение» и выберите программы, которым нельзя выходить в интернет.",
        14f, Pal.sub
    ).apply { setPadding(act.dp(24), act.dp(24), act.dp(24), act.dp(24)); gravity = Gravity.CENTER }

    override val view: View = act.vbox().apply {
        val top = act.vbox().apply { setPadding(act.dp(16), 0, act.dp(16), act.dp(8)) }
        top.addView(act.text(
            "Приложения из списка не смогут ничего отправить или получить из сети. " +
                "Можно запретить отдельно Wi-Fi и мобильный интернет: нажмите на значок, чтобы переключить.",
            13.5f, Pal.sub))
        top.addView(warn, lp().apply { topMargin = act.dp(6) })
        val buttons = act.hbox()
        buttons.addView(act.pill("+ Добавить приложение", 0) { act.startActivity(Intent(act, PickerActivity::class.java)) },
            lp(WRAP, WRAP).apply { rightMargin = act.dp(8) })
        buttons.addView(act.pill("Если отключается…", 3) { showBatteryHelp() }, lp(WRAP, WRAP))
        top.addView(buttons, lp().apply { topMargin = act.dp(10) })
        addView(top)
        list.divider = null
        list.adapter = adapter
        list.emptyView = emptyText
        list.setOnItemClickListener { _, _, pos, _ ->
            Apps.forPackage(adapter.items[pos].pkg)?.let { AppActivity.open(act, it.uid) }
        }
        addView(list, lp(MATCH, 0, 1f))
        addView(emptyText, lp(MATCH, WRAP))
        addView(android.widget.CheckBox(act).apply {
            text = "IPv6 через Стража (экспериментально). Если выключено, приложения работают по IPv4."
            textSize = 12.5f
            setTextColor(Pal.sub)
            isChecked = Prefs.ipv6
            setOnCheckedChangeListener { _, on ->
                Prefs.ipv6 = on
                FirewallService.reconfigure()
            }
        }, lp().apply { setMargins(act.dp(12), act.dp(4), act.dp(16), act.dp(8)) })
    }

    override fun onShow() = load()

    override fun tick() {
        warn.visibility = if (FirewallService.running) View.GONE else View.VISIBLE
    }

    private fun load() {
        tick()
        warn.text = "⚠ Защита выключена — блокировка сейчас не действует. Включите переключатель вверху."
        val items = Rules.all().map { (pkg, f) -> Item(pkg, Apps.labelForPackage(pkg), f) }
            .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
        adapter.items = items
    }

    private fun showBatteryHelp() {
        android.app.AlertDialog.Builder(act)
            .setTitle("Чтобы защиту не выключала система")
            .setMessage(
                "На Xiaomi / HyperOS система может закрывать фоновые приложения.\n\n" +
                    "1. Настройки приложения → «Автозапуск» — включить.\n" +
                    "2. «Контроль активности» (батарея) → «Нет ограничений».\n" +
                    "3. В меню недавних приложений потяните карточку «Сетевого стража» вниз, чтобы закрепить.\n\n" +
                    "Дополнительно: Настройки → Подключения → VPN → «Сетевой страж» → «Постоянная VPN»."
            )
            .setPositiveButton("Настройки приложения") { _, _ ->
                try {
                    act.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + act.packageName)))
                } catch (_: Exception) {}
            }
            .setNegativeButton("Закрыть", null)
            .show()
    }

    private inner class RuleRow(ctx: MainActivity) : LinearLayout(ctx) {
        val icon = android.widget.ImageView(ctx)
        val title = ctx.text("", 15f, bold = true, lines = 1)
        val sub = ctx.text("", 12.5f, Pal.sub, lines = 1)
        val wifi = ctx.pill("Wi-Fi", 3)
        val mobile = ctx.pill("Моб.", 3)
        val remove = ctx.pill("✕", 3)
        var item: Item? = null

        init {
            orientation = HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(ctx.dp(16), ctx.dp(8), ctx.dp(12), ctx.dp(8))
            addView(icon, LayoutParams(ctx.dp(36), ctx.dp(36)))
            val mid = ctx.vbox()
            mid.addView(title)
            mid.addView(sub)
            addView(mid, LayoutParams(0, WRAP, 1f).apply { leftMargin = ctx.dp(12); rightMargin = ctx.dp(6) })
            for (b in listOf(wifi, mobile, remove)) {
                b.setPadding(ctx.dp(10), ctx.dp(7), ctx.dp(10), ctx.dp(7))
                addView(b, LayoutParams(WRAP, WRAP).apply { leftMargin = ctx.dp(5) })
            }
            wifi.setOnClickListener { toggle(Rules.WIFI) }
            mobile.setOnClickListener { toggle(Rules.MOBILE) }
            remove.setOnClickListener {
                val it = item ?: return@setOnClickListener
                Rules.set(it.pkg, 0)
                Toast.makeText(act, "«${it.label}» убрано из списка", Toast.LENGTH_SHORT).show()
                load()
            }
        }

        private fun toggle(bit: Int) {
            val it = item ?: return
            val nf = it.flags xor bit
            Rules.set(it.pkg, nf)
            if (nf == 0) Toast.makeText(act, "«${it.label}» убрано из списка", Toast.LENGTH_SHORT).show()
            load()
        }

        fun bind(it: Item) {
            item = it
            title.text = it.label
            icon.setImageDrawable(Apps.icon(it.pkg) ?: context.getDrawable(android.R.drawable.sym_def_app_icon))
            val f = it.flags
            sub.text = when {
                f and Rules.EXCLUDE != 0 -> "мимо Стража: не отслеживается и не блокируется"
                f and Rules.BLOCK_ALL == Rules.BLOCK_ALL -> "интернет запрещён полностью"
                f and Rules.WIFI != 0 -> "запрещён Wi-Fi, мобильный разрешён"
                f and Rules.MOBILE != 0 -> "запрещён мобильный, Wi-Fi разрешён"
                else -> it.pkg
            }
            sub.setTextColor(if (f and Rules.BLOCK_ALL != 0) Pal.danger else Pal.sub)
            context.stylePill(wifi, if (f and Rules.WIFI != 0) 4 else 3)
            context.stylePill(mobile, if (f and Rules.MOBILE != 0) 4 else 3)
            val excluded = f and Rules.EXCLUDE != 0
            wifi.visibility = if (excluded) GONE else VISIBLE
            mobile.visibility = if (excluded) GONE else VISIBLE
        }
    }
}
