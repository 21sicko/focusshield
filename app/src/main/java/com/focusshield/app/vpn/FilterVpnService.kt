package com.focusshield.app.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.focusshield.app.R
import com.focusshield.app.data.BlocklistRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Local-only VpnService that intercepts DNS only — NOT all device
 * traffic. The tun interface's route is scoped to just the virtual DNS
 * server address (10.111.222.2), so Android sends DNS lookups through it
 * but everything else (already-established connections, non-DNS traffic)
 * flows normally outside the VPN. This keeps the implementation tractable
 * (no need to build a full user-space NAT for arbitrary TCP/UDP traffic)
 * while still controlling every plain DNS lookup the device makes.
 *
 * Known limitation: DNS-over-HTTPS/TLS bypasses this since it isn't
 * plain port-53 UDP — see DnsPacketProcessor's doc comment.
 */
class FilterVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val job = Job()
    private val scope = CoroutineScope(Dispatchers.IO + job)
    private lateinit var blocklist: BlocklistRepository
    private lateinit var processor: DnsPacketProcessor

    companion object {
        const val CHANNEL_ID = "focusshield_vpn"
        const val NOTIFICATION_ID = 1001
        const val ACTION_START = "com.focusshield.app.action.START_VPN"
        const val ACTION_STOP = "com.focusshield.app.action.STOP_VPN"
        private const val VPN_ADDRESS = "10.111.222.1"
        private const val DNS_ADDRESS = "10.111.222.2"
        private const val UPSTREAM_DNS = "1.1.1.1" // Cloudflare; swap for any resolver you trust
    }

    override fun onCreate() {
        super.onCreate()
        blocklist = BlocklistRepository(applicationContext)
        blocklist.loadBlocklists()
        processor = DnsPacketProcessor(
            blocklist = blocklist,
            protectSocket = { socket: DatagramSocket -> protect(socket) },
            upstreamDns = InetAddress.getByName(UPSTREAM_DNS)
        )
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
        if (vpnInterface != null) return // already running

        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("FocusShield")
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(DNS_ADDRESS)
            // Only route traffic destined for the virtual DNS server through
            // the tun — NOT addRoute("0.0.0.0", 0). This is what keeps the
            // implementation to "DNS filtering" rather than "full traffic
            // proxy," and avoids needing to relay every app's general
            // network traffic through user-space code.
            .addRoute(DNS_ADDRESS, 32)
            .setBlocking(true)

        vpnInterface = builder.establish() ?: run {
            stopVpn()
            return
        }

        scope.launch { runPacketLoop() }
    }

    private fun runPacketLoop() {
        val iface = vpnInterface ?: return
        val input = FileInputStream(iface.fileDescriptor)
        val output = FileOutputStream(iface.fileDescriptor)
        val buffer = ByteArray(32767)

        while (vpnInterface != null) {
            val length = try {
                input.read(buffer)
            } catch (e: Exception) {
                break
            }
            if (length <= 0) continue

            val response = try {
                processor.process(buffer, length)
            } catch (e: Exception) {
                null
            }

            if (response != null) {
                try {
                    output.write(response)
                } catch (e: Exception) {
                    // tun closed mid-write; loop condition will exit next pass
                }
            }
        }
    }

    private fun stopVpn() {
        job.cancel()
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            // already closed
        }
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        // Fallback path if VPN permission is revoked from Settings — only
        // reachable when not running under Device Owner's
        // DISALLOW_CONFIG_VPN restriction.
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
