package com.focusshield.app.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.focusshield.app.R
import com.focusshield.app.vpn.FilterVpnService

class MainActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_SHOW_BLOCK_INTERSTITIAL = "show_block_interstitial"
        private const val REQUEST_VPN_PERMISSION = 100
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        if (intent.getBooleanExtra(EXTRA_SHOW_BLOCK_INTERSTITIAL, false)) {
            showBlockInterstitial()
            return
        }

        findViewById<android.widget.Button>(R.id.btnEnableProtection)?.setOnClickListener {
            requestVpnPermissionAndStart()
        }

        findViewById<android.widget.Button>(R.id.btnSetPin)?.setOnClickListener {
            PinDialogHelper.showSetupDialog(this, com.focusshield.app.data.CooldownManager(this))
        }

        findViewById<android.widget.Button>(R.id.btnRequestDisable)?.setOnClickListener {
            startActivity(Intent(this, DisableRequestActivity::class.java))
        }
    }

    private fun requestVpnPermissionAndStart() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            startActivityForResult(prepareIntent, REQUEST_VPN_PERMISSION)
        } else {
            startVpnService()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_PERMISSION && resultCode == Activity.RESULT_OK) {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, FilterVpnService::class.java).apply {
            action = FilterVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun showBlockInterstitial() {
        setContentView(R.layout.activity_block_interstitial)
        findViewById<android.widget.Button>(R.id.btnClose)?.setOnClickListener {
            // Sends the user home rather than back to the flagged app.
            val homeIntent = Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_HOME)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(homeIntent)
            finish()
        }
    }
}
