package lab.netstrazh.ui

import android.content.Context
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.os.Handler
import android.os.Looper
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import lab.netstrazh.data.Apps
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/** Colour palette for light/dark mode. */
object Pal {
    var night = false
    var bg = 0; var surface = 0; var surface2 = 0; var text = 0; var sub = 0
    var accent = 0; var onAccent = 0; var accentSoft = 0
    var danger = 0; var dangerSoft = 0; var ok = 0; var warn = 0; var divider = 0

    fun init(ctx: Context) {
        night = (ctx.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        if (night) {
            bg = 0xFF0F1215.toInt(); surface = 0xFF181C21.toInt(); surface2 = 0xFF222830.toInt()
            text = 0xFFE8EAED.toInt(); sub = 0xFF9AA4AF.toInt()
            accent = 0xFF7AA7FF.toInt(); onAccent = 0xFF0B1A33.toInt(); accentSoft = 0xFF1E2C47.toInt()
            danger = 0xFFFF6B5E.toInt(); dangerSoft = 0xFF3A1D1B.toInt(); ok = 0xFF5BD08A.toInt(); warn = 0xFFFFB74D.toInt()
            divider = 0xFF2A2F36.toInt()
        } else {
            bg = 0xFFF4F6F9.toInt(); surface = 0xFFFFFFFF.toInt(); surface2 = 0xFFEBEEF2.toInt()
            text = 0xFF1B1F24.toInt(); sub = 0xFF5F6B7A.toInt()
            accent = 0xFF2F6FEB.toInt(); onAccent = 0xFFFFFFFF.toInt(); accentSoft = 0xFFE3ECFD.toInt()
            danger = 0xFFD93025.toInt(); dangerSoft = 0xFFFCE8E6.toInt(); ok = 0xFF188038.toInt(); warn = 0xFFB06000.toInt()
            divider = 0xFFE3E6EA.toInt()
        }
    }
}

// ------------------------------------------------------------------ formatting

object Fmt {
    private val ru = Locale("ru")

    fun bytes(n: Long): String {
        if (n < 1024) return "$n Б"
        val units = arrayOf("КБ", "МБ", "ГБ", "ТБ")
        var v = n / 1024.0
        var i = 0
        while (v >= 1024 && i < units.size - 1) { v /= 1024; i++ }
        return if (v < 10) String.format(ru, "%.1f %s", v, units[i]) else String.format(ru, "%.0f %s", v, units[i])
    }

    fun speed(bps: Long): String = if (bps <= 0) "0" else bytes(bps) + "/с"

    fun ago(ts: Long): String {
        if (ts <= 0) return "—"
        val d = System.currentTimeMillis() - ts
        return when {
            d < 60_000 -> "только что"
            d < 3_600_000 -> "${d / 60_000} мин назад"
            d < 86_400_000 -> "${d / 3_600_000} ч назад"
            d < 7 * 86_400_000L -> "${d / 86_400_000} дн назад"
            else -> SimpleDateFormat("d MMM", ru).format(Date(ts))
        }
    }

    fun time(ts: Long): String {
        val c = Calendar.getInstance()
        val today = c.get(Calendar.DAY_OF_YEAR) to c.get(Calendar.YEAR)
        c.timeInMillis = ts
        val same = (c.get(Calendar.DAY_OF_YEAR) to c.get(Calendar.YEAR)) == today
        return SimpleDateFormat(if (same) "HH:mm:ss" else "d MMM HH:mm", ru).format(Date(ts))
    }

    fun duration(ms: Long): String = when {
        ms < 1000 -> String.format(ru, "%.1f с", ms / 1000.0)
        ms < 60_000 -> "${ms / 1000} с"
        ms < 3_600_000 -> "${ms / 60_000} мин"
        else -> "${ms / 3_600_000} ч ${(ms % 3_600_000) / 60_000} мин"
    }

    fun net(n: String): String = when (n) {
        "wifi" -> "Wi-Fi"
        "mobile" -> "моб. сеть"
        "other" -> "другая сеть"
        else -> "нет сети"
    }

    fun dest(host: String?, ip: String, port: Int): String {
        val h = if (!host.isNullOrEmpty()) host else ip
        return if (h.contains(':') && !h.contains('.')) "[$h]:$port" else "$h:$port"
    }
}

// ------------------------------------------------------------------ view helpers

fun Context.dp(v: Int): Int = (v * resources.displayMetrics.density + 0.5f).toInt()
fun Context.dpf(v: Float): Float = v * resources.displayMetrics.density

fun lp(w: Int = ViewGroup.LayoutParams.MATCH_PARENT, h: Int = ViewGroup.LayoutParams.WRAP_CONTENT, weight: Float = 0f) =
    LinearLayout.LayoutParams(w, h, weight)

const val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT

fun <T : View> T.margins(l: Int = 0, t: Int = 0, r: Int = 0, b: Int = 0): T {
    val p = layoutParams as? ViewGroup.MarginLayoutParams ?: lp()
    p.setMargins(l, t, r, b)
    layoutParams = p
    return this
}

fun rounded(color: Int, radius: Float, stroke: Int = 0, strokeWidth: Int = 0): GradientDrawable =
    GradientDrawable().apply {
        setColor(color)
        cornerRadius = radius
        if (strokeWidth > 0) setStroke(strokeWidth, stroke)
    }

fun Context.ripple(content: Drawable?, radius: Float = 0f): Drawable {
    val c = if (Pal.night) 0x33FFFFFF else 0x22000000
    val mask = if (radius > 0) rounded(0xFFFFFFFF.toInt(), radius) else GradientDrawable().apply { setColor(0xFFFFFFFF.toInt()) }
    return RippleDrawable(ColorStateList.valueOf(c), content, mask)
}

fun Context.text(s: CharSequence = "", size: Float = 15f, color: Int = Pal.text, bold: Boolean = false, lines: Int = 0): TextView =
    TextView(this).apply {
        text = s
        textSize = size
        setTextColor(color)
        if (bold) typeface = Typeface.DEFAULT_BOLD
        if (lines > 0) {
            maxLines = lines
            ellipsize = TextUtils.TruncateAt.END
        }
    }

fun Context.vbox(): LinearLayout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

fun Context.hbox(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
}

fun Context.card(): LinearLayout = vbox().apply {
    background = rounded(Pal.surface, dpf(16f))
    setPadding(dp(16), dp(14), dp(16), dp(14))
}

/** Pill-shaped button. [style]: 0 = filled accent, 1 = soft, 2 = danger soft, 3 = outline. */
fun Context.pill(label: String, style: Int = 0, onClick: (() -> Unit)? = null): TextView =
    text(label, 14f, bold = true).apply {
        gravity = Gravity.CENTER
        setPadding(dp(14), dp(8), dp(14), dp(8))
        stylePill(this, style)
        if (onClick != null) setOnClickListener { onClick() }
    }

fun Context.stylePill(v: TextView, style: Int) {
    val r = dpf(20f)
    val (bg, fg, stroke) = when (style) {
        0 -> Triple(Pal.accent, Pal.onAccent, 0)
        1 -> Triple(Pal.accentSoft, Pal.accent, 0)
        2 -> Triple(Pal.dangerSoft, Pal.danger, 0)
        4 -> Triple(Pal.danger, 0xFFFFFFFF.toInt(), 0)
        else -> Triple(Pal.surface, Pal.sub, Pal.divider)
    }
    v.setTextColor(fg)
    v.background = ripple(rounded(bg, r, stroke, if (stroke != 0) dp(1) else 0), r)
}

fun Context.divider(): View = View(this).apply {
    setBackgroundColor(Pal.divider)
    layoutParams = lp(MATCH, maxOf(1, dp(1) / 2))
}

/** A list row with icon, three text lines and a right-hand column. */
class RowView(ctx: Context) : LinearLayout(ctx) {
    val icon = ImageView(ctx)
    val title = ctx.text("", 15.5f, bold = true, lines = 1)
    val line2 = ctx.text("", 13f, Pal.sub, lines = 1)
    val line3 = ctx.text("", 13f, Pal.sub, lines = 2)
    val right1 = ctx.text("", 13.5f, Pal.text, bold = true)
    val right2 = ctx.text("", 12.5f, Pal.sub)

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(ctx.dp(16), ctx.dp(10), ctx.dp(16), ctx.dp(10))
        background = ctx.ripple(null)
        addView(icon, LayoutParams(ctx.dp(40), ctx.dp(40)))
        val mid = ctx.vbox()
        mid.addView(title)
        mid.addView(line2)
        mid.addView(line3)
        addView(mid, LayoutParams(0, WRAP, 1f).apply { leftMargin = ctx.dp(14); rightMargin = ctx.dp(8) })
        val right = ctx.vbox().apply { gravity = Gravity.END }
        right1.gravity = Gravity.END
        right2.gravity = Gravity.END
        right.addView(right1)
        right.addView(right2)
        addView(right, LayoutParams(WRAP, WRAP))
    }

    fun setApp(info: Apps.Info) {
        title.text = info.label
        icon.setImageDrawable(Apps.icon(info.pkg) ?: context.getDrawable(android.R.drawable.sym_def_app_icon))
    }

    fun setLine3(s: CharSequence?, color: Int = Pal.sub) {
        line3.visibility = if (s.isNullOrEmpty()) GONE else VISIBLE
        line3.text = s
        line3.setTextColor(color)
    }
}

/** Minimal adapter for ListView. */
class ListAdapter<T>(private val make: () -> View, private val bind: (View, T, Int) -> Unit) : BaseAdapter() {
    var items: List<T> = emptyList()
        set(v) {
            field = v
            notifyDataSetChanged()
        }

    override fun getCount() = items.size
    override fun getItem(position: Int): Any? = items[position]
    override fun getItemId(position: Int) = position.toLong()
    override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
        val v = convertView ?: make()
        bind(v, items[position], position)
        return v
    }
}

/** Runs [work] on a background thread and delivers the result on the main thread. */
object Bg {
    private val pool = Executors.newFixedThreadPool(3)
    private val main = Handler(Looper.getMainLooper())

    fun <T> run(work: () -> T, done: (T) -> Unit) = run(work, done, null)

    fun <T> run(work: () -> T, done: (T) -> Unit, failed: (() -> Unit)?) {
        pool.execute {
            try {
                val r = work()
                main.post { done(r) }
            } catch (e: Exception) {
                android.util.Log.w("NetStrazh", "background task failed", e)
                if (failed != null) main.post { failed() }
            }
        }
    }
}
