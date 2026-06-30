package com.focusshield.app.admin

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.UserManager

/**
 * Device Admin / Device Owner receiver for FocusShield.
 *
 * Device Owner status must be granted once, before any user account is
 * added to the device, via:
 *
 *   adb shell dpm set-device-owner com.focusshield.app/.admin.FocusShieldAdminReceiver
 *
 * This typically requires a factory reset first if the device already has
 * accounts configured, since Android will not allow Device Owner
 * provisioning on a device with an existing Google account.
 *
 * Once granted, onEnabled() below applies the user restrictions that make
 * the protections persistent at the OS policy level rather than the app
 * level, so they survive attempts to reconfigure settings, boot into safe
 * mode, or remove the app through normal channels.
 */
class FocusShieldAdminReceiver : DeviceAdminReceiver() {

    companion object {
        fun componentName(context: Context): ComponentName =
            ComponentName(context.applicationContext, FocusShieldAdminReceiver::class.java)
    }

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        applyLockdownPolicies(context)
    }

    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        super.onProfileProvisioningComplete(context, intent)
        applyLockdownPolicies(context)
    }

    private fun applyLockdownPolicies(context: Context) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = componentName(context)

        if (!dpm.isDeviceOwnerApp(context.packageName)) {
            // Without Device Owner status these restrictions cannot be set;
            // the app falls back to app-level protections only (see
            // FilterVpnService / AppGuardAccessibilityService).
            return
        }

        val restrictions = listOf(
            UserManager.DISALLOW_CONFIG_VPN,
            UserManager.DISALLOW_UNINSTALL_APPS,
            UserManager.DISALLOW_SAFE_BOOT,
            UserManager.DISALLOW_FACTORY_RESET,
            UserManager.DISALLOW_DEBUGGING_FEATURES,
            UserManager.DISALLOW_APPS_CONTROL // blocks force-stop/uninstall via app info screen
        )

        restrictions.forEach { restriction ->
            dpm.addUserRestriction(admin, restriction)
        }

        // Play Store is intentionally left untouched so app installs/updates
        // keep working normally — only VPN config and uninstall/safe-boot
        // paths are restricted above.
    }

    /**
     * Removes all restrictions. Only ever called from the time-locked
     * disable flow in DisableRequestActivity, never directly from a menu.
     */
    fun releaseLockdownPolicies(context: Context) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = componentName(context)
        if (!dpm.isDeviceOwnerApp(context.packageName)) return

        listOf(
            UserManager.DISALLOW_CONFIG_VPN,
            UserManager.DISALLOW_UNINSTALL_APPS,
            UserManager.DISALLOW_SAFE_BOOT,
            UserManager.DISALLOW_FACTORY_RESET,
            UserManager.DISALLOW_DEBUGGING_FEATURES,
            UserManager.DISALLOW_APPS_CONTROL
        ).forEach { dpm.clearUserRestriction(admin, it) }
    }
}
