package com.focusshield.app.vpn

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.view.accessibility.AccessibilityEvent
import com.focusshield.app.data.BlocklistRepository
import com.focusshield.app.ui.MainActivity

/**
 * Secondary detection layer. The VPN/DNS layer catches browser-based
 * access; this catches native apps (e.g. a gambling app installed
 * directly from an APK or a regional Play Store listing) by watching
 * foreground app changes and comparing the package/app name against the
 * same keyword heuristics used for domains.
 *
 * On detection, it does not attempt to force-close the app directly
 * (Accessibility services have limited, fragile control over that) —
 * instead it brings FocusShield to the foreground with an interstitial,
 * which is more reliable across Android versions.
 */
class AppGuardAccessibilityService : AccessibilityService() {

    private lateinit var blocklist: BlocklistRepository
    private val flaggedKeywords = listOf(
        "bet", "casino", "wager", "poker", "slots", "gambl", "jackpot", "roulette"
    )

    override fun onServiceConnected() {
        super.onServiceConnected()
        blocklist = BlocklistRepository(applicationContext)
        blocklist.loadBlocklists()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        val packageName = event?.packageName?.toString() ?: return
        if (packageName == applicationContext.packageName) return

        val flagged = flaggedKeywords.any { packageName.lowercase().contains(it) }
        if (flagged) {
            launchInterstitial()
        }
    }

    private fun launchInterstitial() {
        val intent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            putExtra(MainActivity.EXTRA_SHOW_BLOCK_INTERSTITIAL, true)
        }
        startActivity(intent)
    }

    override fun onInterrupt() {}
}
