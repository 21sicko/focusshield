package com.focusshield.app.ui

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.focusshield.app.R
import com.focusshield.app.admin.FocusShieldAdminReceiver
import com.focusshield.app.data.CooldownManager
import java.util.concurrent.TimeUnit

/**
 * The only path to disabling FocusShield. There is deliberately no quick
 * toggle anywhere else in the app — every disable attempt goes through
 * this screen, which enforces the cooldown set up in CooldownManager.
 */
class DisableRequestActivity : AppCompatActivity() {

    private lateinit var cooldownManager: CooldownManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_disable_request)
        cooldownManager = CooldownManager(this)

        renderState()

        findViewById<android.widget.Button>(R.id.btnRequestOrConfirm)?.setOnClickListener {
            onPrimaryButtonClicked()
        }

        findViewById<android.widget.Button>(R.id.btnCancelRequest)?.setOnClickListener {
            cooldownManager.cancelDisableRequest()
            Toast.makeText(this, "Disable request cancelled", Toast.LENGTH_SHORT).show()
            renderState()
        }
    }

    private fun onPrimaryButtonClicked() {
        when {
            !cooldownManager.isDisableRequestPending() -> {
                cooldownManager.requestDisable()
                Toast.makeText(
                    this,
                    "Disable requested. Available in 72 hours.",
                    Toast.LENGTH_LONG
                ).show()
            }
            cooldownManager.canDisableNow() -> {
                if (cooldownManager.hasTrustedContact()) {
                    promptForTrustedPin()
                } else {
                    finalizeDisable()
                }
            }
            else -> {
                Toast.makeText(this, "Still in cooldown period.", Toast.LENGTH_SHORT).show()
            }
        }
        renderState()
    }

    private fun promptForTrustedPin() {
        // In a full implementation this opens a PIN entry dialog and calls
        // cooldownManager.verifyTrustedContactPin(pin) before proceeding.
        // Left as a hook here since the PIN holder/UI flow is something
        // you'd want to customize (e.g. who the trusted contact is).
    }

    private fun finalizeDisable() {
        val admin = FocusShieldAdminReceiver()
        admin.releaseLockdownPolicies(this)
        cooldownManager.cancelDisableRequest()
        Toast.makeText(this, "Protections released. You may now uninstall.", Toast.LENGTH_LONG).show()
        finish()
    }

    private fun renderState() {
        val statusView = findViewById<android.widget.TextView>(R.id.tvCooldownStatus)
        val primaryButton = findViewById<android.widget.Button>(R.id.btnRequestOrConfirm)
        val cancelButton = findViewById<android.widget.Button>(R.id.btnCancelRequest)

        when {
            !cooldownManager.isDisableRequestPending() -> {
                statusView?.text = "No disable request active."
                primaryButton?.text = "Request to disable"
                cancelButton?.isEnabled = false
            }
            cooldownManager.canDisableNow() -> {
                statusView?.text = "Cooldown complete. You can disable now."
                primaryButton?.text = "Confirm disable"
                cancelButton?.isEnabled = true
            }
            else -> {
                val hoursLeft = TimeUnit.MILLISECONDS.toHours(cooldownManager.remainingCooldownMs())
                statusView?.text = "Cooldown active: ~$hoursLeft hours remaining."
                primaryButton?.text = "Waiting..."
                primaryButton?.isEnabled = false
                cancelButton?.isEnabled = true
            }
        }
    }
}
