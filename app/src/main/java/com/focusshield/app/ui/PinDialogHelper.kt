package com.focusshield.app.ui

import android.app.AlertDialog
import android.content.Context
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import com.focusshield.app.R
import com.focusshield.app.data.CooldownManager

/**
 * Wraps the trusted-contact PIN flows: setting one up, and verifying it
 * before a disable request can be finalized. The PIN is meant to be held
 * by someone other than the person trying to disable the app (a partner,
 * accountability buddy, sponsor, etc.) — entering it is a deliberate
 * "ask someone else" step on top of the time cooldown.
 */
object PinDialogHelper {

    fun showSetupDialog(context: Context, cooldownManager: CooldownManager) {
        val view = android.view.LayoutInflater.from(context)
            .inflate(R.layout.dialog_pin_entry, null)
        val message = view.findViewById<TextView>(R.id.tvPinDialogMessage)
        val input = view.findViewById<EditText>(R.id.etPin)
        message.text = "Set a PIN that only your trusted contact will know. " +
            "You'll need it from them (not yourself) to disable FocusShield later."

        AlertDialog.Builder(context)
            .setTitle("Set trusted-contact PIN")
            .setView(view)
            .setPositiveButton("Save") { _, _ ->
                val pin = input.text.toString().trim()
                if (pin.length < 4) {
                    Toast.makeText(context, "PIN must be at least 4 digits", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                cooldownManager.setTrustedContactPin(pin)
                Toast.makeText(context, "Trusted-contact PIN saved", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    fun showVerifyDialog(
        context: Context,
        cooldownManager: CooldownManager,
        onVerified: () -> Unit
    ) {
        val view = android.view.LayoutInflater.from(context)
            .inflate(R.layout.dialog_pin_entry, null)
        val message = view.findViewById<TextView>(R.id.tvPinDialogMessage)
        val input = view.findViewById<EditText>(R.id.etPin)
        message.text = "Ask your trusted contact to enter the PIN to confirm disabling FocusShield."

        AlertDialog.Builder(context)
            .setTitle("Confirm with trusted contact")
            .setView(view)
            .setCancelable(false)
            .setPositiveButton("Confirm") { _, _ ->
                val pin = input.text.toString().trim()
                if (cooldownManager.verifyTrustedContactPin(pin)) {
                    onVerified()
                } else {
                    Toast.makeText(context, "Incorrect PIN", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
}
