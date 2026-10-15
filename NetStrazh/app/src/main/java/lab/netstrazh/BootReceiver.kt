package lab.netstrazh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import lab.netstrazh.vpn.FirewallService

/** Restores protection after a reboot or an app update if it was on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val a = intent.action
        if (a != Intent.ACTION_BOOT_COMPLETED && a != Intent.ACTION_MY_PACKAGE_REPLACED &&
            a != "android.intent.action.QUICKBOOT_POWERON") return
        if (!Prefs.enabled) return
        if (VpnService.prepare(ctx) != null) return
        try {
            FirewallService.start(ctx)
        } catch (_: Exception) {
        }
    }
}
