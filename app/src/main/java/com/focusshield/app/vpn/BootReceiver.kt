package com.focusshield.app.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat

/**
 * Restarts protection automatically after a reboot. Without this, a
 * reboot would silently leave the device unprotected until the app is
 * manually reopened — a gap that defeats the point.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        // Only restart automatically if VPN permission was already granted
        // previously (VpnService.prepare returns null once granted).
        if (VpnService.prepare(context) == null) {
            val serviceIntent = Intent(context, FilterVpnService::class.java).apply {
                action = FilterVpnService.ACTION_START
            }
            ContextCompat.startForegroundService(context, serviceIntent)
        }
    }
}
