package lab.netstrazh.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import lab.netstrazh.Prefs
import lab.netstrazh.vpn.FirewallService
import lab.netstrazh.vpn.Live

abstract class Page(val act: MainActivity) {
    abstract val view: View
    open fun onShow() {}
    open fun onHide() {}
    /** Called every second while the page is visible. */
    open fun tick() {}
}

class MainActivity : Activity() {
    private lateinit var content: FrameLayout
    private lateinit var pages: List<Page>
    private val tabTexts = ArrayList<TextView>()
    private val tabBars = ArrayList<View>()
    private var current = -1
    private lateinit var power: Switch
    private lateinit var status: TextView
    private var updatingSwitch = false
    private var resumed = false
    private val handler = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            updateHeader()
            if (current >= 0) pages[current].tick()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Pal.init(this)
        styleWindow(this)

        val root = vbox().apply { setBackgroundColor(Pal.bg) }

        val header = hbox().apply { setPadding(dp(20), dp(14), dp(12), dp(10)) }
        val titles = vbox()
        titles.addView(text("Сетевой страж", 22f, bold = true))
        status = text("", 13f, Pal.sub)
        titles.addView(status)
        header.addView(titles, lp(0, WRAP, 1f))
        power = Switch(this).apply {
            scaleX = 1.15f
            scaleY = 1.15f
            setOnCheckedChangeListener { _, on -> if (!updatingSwitch) onPowerToggle(on) }
        }
        header.addView(power, lp(WRAP, WRAP))
        root.addView(header)

        content = FrameLayout(this)
        root.addView(content, lp(MATCH, 0, 1f))
        root.addView(divider())

        val nav = hbox().apply { setBackgroundColor(Pal.surface) }
        val names = listOf("Сейчас", "Журнал", "Трафик", "Файрвол")
        for ((i, n) in names.withIndex()) {
            val cell = vbox().apply {
                gravity = Gravity.CENTER_HORIZONTAL
                background = ripple(null)
                setOnClickListener { select(i) }
            }
            val bar = View(this)
            cell.addView(bar, lp(dp(28), dp(3)).apply { gravity = Gravity.CENTER_HORIZONTAL })
            val t = text(n, 14f, Pal.sub, bold = true).apply {
                gravity = Gravity.CENTER
                setPadding(0, dp(10), 0, dp(14))
            }
            cell.addView(t, lp(MATCH, WRAP))
            tabBars += bar
            tabTexts += t
            nav.addView(cell, lp(0, WRAP, 1f))
        }
        root.addView(nav)
        setContentView(root)

        pages = listOf(LivePage(this), JournalPage(this), TrafficPage(this), FirewallPage(this))
        select(intent?.getIntExtra(EXTRA_TAB, -1)?.takeIf { it >= 0 } ?: Prefs.lastTab)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.getIntExtra(EXTRA_TAB, -1)?.takeIf { it >= 0 }?.let { select(it) }
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        updateHeader()
        if (current >= 0) pages[current].onShow()
        handler.removeCallbacks(ticker)
        handler.postDelayed(ticker, 1000)
    }

    override fun onPause() {
        super.onPause()
        resumed = false
        handler.removeCallbacks(ticker)
        if (current >= 0) pages[current].onHide()
    }

    fun select(i: Int) {
        val idx = i.coerceIn(0, pages.size - 1)
        if (idx == current) return
        if (current >= 0) pages[current].onHide()
        current = idx
        Prefs.lastTab = idx
        content.removeAllViews()
        content.addView(pages[idx].view, FrameLayout.LayoutParams(MATCH, MATCH))
        for ((j, t) in tabTexts.withIndex()) {
            t.setTextColor(if (j == idx) Pal.accent else Pal.sub)
            tabBars[j].background = if (j == idx) rounded(Pal.accent, dpf(2f)) else null
        }
        if (resumed) pages[idx].onShow()
    }

    private fun updateHeader() {
        val on = FirewallService.running
        if (pendingStart && System.currentTimeMillis() - pendingSince > 8000) pendingStart = false
        updatingSwitch = true
        power.isChecked = on || pendingStart
        updatingSwitch = false
        status.text = if (on) {
            "Защита включена · соединений: ${Live.active.size}"
        } else if (pendingStart) {
            "Включаю…"
        } else {
            "Защита выключена"
        }
        status.setTextColor(if (on) Pal.ok else Pal.sub)
        if (on) pendingStart = false
    }

    // ------------------------------------------------------------ start / stop

    private var pendingStart = false
    private var pendingSince = 0L

    private fun onPowerToggle(on: Boolean) {
        if (on) requestStart() else {
            pendingStart = false
            FirewallService.stop(this)
            updateHeader()
            pages.getOrNull(current)?.onShow()
        }
    }

    fun requestStart() {
        pendingStart = true
        pendingSince = System.currentTimeMillis()
        updateHeader()
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
            !askedNotif
        ) {
            askedNotif = true
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
            return
        }
        continueStart()
    }

    private var askedNotif = false

    private fun continueStart() {
        val i = try { VpnService.prepare(this) } catch (e: Exception) { null }
        if (i != null) {
            try {
                startActivityForResult(i, REQ_VPN)
            } catch (e: Exception) {
                failStart("Не удалось запросить разрешение VPN")
            }
        } else {
            FirewallService.start(this)
            handler.postDelayed({ updateHeader(); pages.getOrNull(current)?.onShow() }, 700)
        }
    }

    private fun failStart(msg: String) {
        pendingStart = false
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
        updateHeader()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIF) continueStart()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                pendingStart = true
                pendingSince = System.currentTimeMillis()
                FirewallService.start(this)
                handler.postDelayed({ updateHeader(); pages.getOrNull(current)?.onShow() }, 700)
            } else {
                failStart("Без разрешения на VPN защита работать не может")
            }
        }
    }

    companion object {
        const val EXTRA_TAB = "tab"
        private const val REQ_VPN = 1
        private const val REQ_NOTIF = 2

        fun styleWindow(a: Activity) {
            @Suppress("DEPRECATION")
            a.window.statusBarColor = Pal.bg
            @Suppress("DEPRECATION")
            a.window.navigationBarColor = Pal.surface
            if (!Pal.night) {
                @Suppress("DEPRECATION")
                a.window.decorView.systemUiVisibility =
                    View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
            }
        }
    }
}

/** Centered placeholder with a message and an optional action. */
fun Activity.placeholder(msg: String, action: String? = null, onAction: (() -> Unit)? = null): LinearLayout =
    vbox().apply {
        gravity = Gravity.CENTER
        setPadding(dp(32), dp(32), dp(32), dp(32))
        addView(text(msg, 15f, Pal.sub).apply { gravity = Gravity.CENTER })
        if (action != null) addView(pill(action, 0, onAction), lp(WRAP, WRAP).apply {
            topMargin = dp(16)
            gravity = Gravity.CENTER_HORIZONTAL
        })
    }
