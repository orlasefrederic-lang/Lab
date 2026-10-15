package lab.netstrazh.ui

import android.app.Activity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ListView
import lab.netstrazh.Prefs
import lab.netstrazh.data.Apps
import lab.netstrazh.data.Rules

/** Pick apps to add to / remove from the block list. */
class PickerActivity : Activity() {
    private var all: List<Apps.Info> = emptyList()
    private val adapter by lazy { ListAdapter<Apps.Info>({ RowView(this) }) { v, it, _ -> bind(v as RowView, it) } }
    private lateinit var search: EditText
    private lateinit var sys: CheckBox
    private lateinit var loading: View

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
        head.addView(text("Выберите приложения", 19f, bold = true), lp(0, WRAP, 1f))
        head.addView(pill("Готово", 0) { finish() }, lp(WRAP, WRAP))
        root.addView(head)
        root.addView(text("Нажмите на приложение, чтобы запретить или снова разрешить ему интернет.", 13f, Pal.sub),
            lp().apply { setMargins(dp(20), dp(2), dp(20), dp(8)) })

        search = EditText(this).apply {
            hint = "Поиск"
            textSize = 14.5f
            setSingleLine()
            setTextColor(Pal.text)
            setHintTextColor(Pal.sub)
            background = rounded(Pal.surface, dpf(12f))
            setPadding(dp(14), dp(10), dp(14), dp(10))
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun afterTextChanged(s: Editable?) = applyFilter()
            })
        }
        root.addView(search, lp().apply { setMargins(dp(16), 0, dp(16), dp(4)) })
        sys = CheckBox(this).apply {
            text = "Показывать системные приложения"
            setTextColor(Pal.sub)
            isChecked = Prefs.showSystemApps
            setOnCheckedChangeListener { _, on ->
                Prefs.showSystemApps = on
                applyFilter()
            }
        }
        root.addView(sys, lp().apply { setMargins(dp(12), 0, dp(16), dp(4)) })

        val list = ListView(this).apply {
            divider = null
            adapter = this@PickerActivity.adapter
            setOnItemClickListener { _, _, pos, _ -> toggle(this@PickerActivity.adapter.items[pos]) }
        }
        loading = placeholder("Загружаю список приложений…")
        val frame = FrameLayout(this)
        frame.addView(list)
        frame.addView(loading)
        root.addView(frame, lp(MATCH, 0, 1f))
        setContentView(root)

        Bg.run({ Apps.installed().filter { it.hasInternet && it.pkg != packageName } }) {
            all = it
            loading.visibility = View.GONE
            applyFilter()
        }
    }

    private fun applyFilter() {
        val q = search.text.toString().trim()
        val showSys = sys.isChecked
        adapter.items = all.filter { a ->
            val pkg = a.pkg ?: return@filter false
            val blocked = Rules.flags(pkg) != 0
            (showSys || !a.system || blocked) &&
                (q.isEmpty() || a.label.contains(q, true) || pkg.contains(q, true))
        }.sortedWith(compareByDescending<Apps.Info> { Rules.flags(it.pkg!!) != 0 }.thenBy(String.CASE_INSENSITIVE_ORDER) { it.label })
    }

    private fun toggle(a: Apps.Info) {
        val pkg = a.pkg ?: return
        val f = Rules.flags(pkg)
        Rules.set(pkg, if (f and Rules.BLOCK_ALL != 0) f and Rules.BLOCK_ALL.inv() else (f and Rules.EXCLUDE.inv()) or Rules.BLOCK_ALL)
        adapter.notifyDataSetChanged()
    }

    private fun bind(v: RowView, a: Apps.Info) {
        v.title.text = a.label
        v.icon.setImageDrawable(Apps.icon(a.pkg) ?: getDrawable(android.R.drawable.sym_def_app_icon))
        v.line2.text = a.pkg + if (a.system) " · системное" else ""
        val f = Rules.flags(a.pkg!!)
        when {
            f and Rules.BLOCK_ALL != 0 -> {
                v.setLine3(null)
                v.right1.text = "⛔ запрещено"
                v.right1.setTextColor(Pal.danger)
            }
            f and Rules.EXCLUDE != 0 -> {
                v.setLine3(null)
                v.right1.text = "мимо Стража"
                v.right1.setTextColor(Pal.sub)
            }
            else -> {
                v.setLine3(null)
                v.right1.text = "разрешено"
                v.right1.setTextColor(Pal.ok)
            }
        }
        v.right2.text = ""
    }
}
