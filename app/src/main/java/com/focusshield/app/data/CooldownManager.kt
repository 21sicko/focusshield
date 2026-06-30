package com.focusshield.app.data

import android.content.Context
import java.util.concurrent.TimeUnit

/**
 * Enforces a mandatory cooldown between requesting to disable FocusShield
 * and actually being able to do so. This is the part that makes the app
 * meaningfully different from just toggling a setting off — a blocker you
 * can switch off the moment you want to gamble isn't a blocker.
 *
 * Default cooldown is 72 hours. Optionally a trusted contact PIN can be
 * required in addition to the wait, set up during onboarding.
 */
class CooldownManager(context: Context) {

    private val prefs = context.getSharedPreferences("focusshield_cooldown", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_REQUEST_TIME = "disable_requested_at"
        private const val KEY_TRUSTED_PIN_HASH = "trusted_pin_hash"
        val COOLDOWN_DURATION_MS: Long = TimeUnit.HOURS.toMillis(72)
    }

    fun requestDisable() {
        if (prefs.getLong(KEY_REQUEST_TIME, -1L) == -1L) {
            prefs.edit().putLong(KEY_REQUEST_TIME, System.currentTimeMillis()).apply()
        }
    }

    fun cancelDisableRequest() {
        prefs.edit().remove(KEY_REQUEST_TIME).apply()
    }

    fun isDisableRequestPending(): Boolean =
        prefs.getLong(KEY_REQUEST_TIME, -1L) != -1L

    fun remainingCooldownMs(): Long {
        val requestedAt = prefs.getLong(KEY_REQUEST_TIME, -1L)
        if (requestedAt == -1L) return COOLDOWN_DURATION_MS
        val elapsed = System.currentTimeMillis() - requestedAt
        return (COOLDOWN_DURATION_MS - elapsed).coerceAtLeast(0L)
    }

    fun canDisableNow(): Boolean =
        isDisableRequestPending() && remainingCooldownMs() <= 0L

    fun hasTrustedContact(): Boolean =
        prefs.contains(KEY_TRUSTED_PIN_HASH)

    fun setTrustedContactPin(pin: String) {
        prefs.edit().putString(KEY_TRUSTED_PIN_HASH, hashPin(pin)).apply()
    }

    fun verifyTrustedContactPin(pin: String): Boolean =
        prefs.getString(KEY_TRUSTED_PIN_HASH, null) == hashPin(pin)

    private fun hashPin(pin: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        return digest.digest(pin.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
