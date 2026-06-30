package com.focusshield.app.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.focusshield.app.R
import com.focusshield.app.data.BlocklistRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

/**
 * Local-only VpnService. This does NOT route traffic through any remote
 * server — it's purely a mechanism for intercepting DNS queries on-device
 * so they can be checked against the blocklist before being forwarded to
 * a real upstream DNS resolver. No traffic ever leaves the device through
 * a third party. This is the same approach apps like Gamban/NetNanny use.
 *
 * This is a simplified reference implementation of the packet loop: a
 * production build needs a proper IP/UDP/TCP parser (e.g. adapting the
 * approach from open-source projects like dns66 or AdAway's VPN module)
 * to parse DNS queries out of raw packets reliably. The structure below
 * is intentionally laid out so that parsing logic can be dropped into
 * handlePacket() without restructuring the service.
 */
class FilterVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val job = Job()
    private val scope = CoroutineScope(Dispatchers.IO + job)
    private lateinit var blocklist: BlocklistRepository

    companion object {
        const val CHANNEL_ID = "focusshield_vpn"
        const val NOTIFICATION_ID = 1001
        const val ACTION_START = "com.focusshield.app.action.START_VPN"
        const val ACTION_STOP = "com.focusshield.app.action.STOP_VPN"
    }

    override fun onCreate() {
        super.onCreate()
        blocklist = BlocklistRepository(applicationContext)
        blocklist.loadBlocklists()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("FocusShield")
            .addAddress("10.111.222.1", 32)
            .addDnsServer("10.111.222.2") // virtual DNS server we intercept locally
            .addRoute("0.0.0.0", 0)
            .setBlocking(true)

        vpnInterface = builder.establish()

        scope.launch {
            runPacketLoop()
        }
    }

    private fun runPacketLoop() {
        val iface = vpnInterface ?: return
        val input = FileInputStream(iface.fileDescriptor)
        val output = FileOutputStream(iface.fileDescriptor)
        val buffer = ByteBuffer.allocate(32767)

        while (vpnInterface != null) {
            buffer.clear()
            val length = input.read(buffer.array())
            if (length <= 0) continue
            buffer.limit(length)

            // handlePacket parses the packet, extracts any embedded DNS
            // query, checks the queried hostname against blocklist, and
            // either forwards it to a real upstream resolver (allowed)
            // or returns NXDOMAIN / a blocked-page response (blocked).
            handlePacket(buffer, output, blocklist)
        }
    }

    private fun handlePacket(
        buffer: ByteBuffer,
        output: FileOutputStream,
        blocklist: BlocklistRepository
    ) {
        // Placeholder for full IP/UDP/DNS parsing — see class doc comment.
        // Real implementation forwards non-DNS traffic untouched, and for
        // DNS queries: extracts hostname, calls blocklist.isBlocked(host),
        // and either proxies to upstream DNS or synthesizes a block
        // response.
    }

    private fun stopVpn() {
        job.cancel()
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        // Called if the user revokes VPN permission from system Settings.
        // Device Owner's DISALLOW_CONFIG_VPN restriction prevents this
        // path when active; this is the fallback for non-Device-Owner mode.
        stopVpn()
        super.onRevoke()
    }

    private fun buildNotification(): android.app.Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("FocusShield is active")
            .setContentText("Blocking gambling and adult content")
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "FocusShield Protection",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }
}
