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
import java.net.Socket

/**
 * Full-traffic VpnService. Routes ALL device traffic through the tun
 * (0.0.0.0/1 + 128.0.0.0/1, the standard "default route" split that
 * avoids some OEM edge cases with a single 0.0.0.0/0 route) so that
 * Android's "Block connections without VPN" kill switch can be used for
 * tamper resistance without taking down the whole connection.
 *
 * Every packet is demuxed by protocol:
 *  - UDP port 53           -> DnsPacketProcessor (blocklist-aware, can
 *                              reply locally with NXDOMAIN)
 *  - any other UDP         -> UdpRelay (generic NAT relay over a real,
 *                              protected DatagramSocket per session)
 *  - TCP                   -> TcpRelay (userspace TCP splice over a real,
 *                              protected Socket per session)
 *  - anything else (ICMP etc.) -> dropped
 *
 * Known limitation: this is NOT a production-grade TCP/IP stack. See
 * TcpRelay's doc comment for what it deliberately does not implement.
 */
class FilterVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val job = Job()
    private val scope = CoroutineScope(Dispatchers.IO + job)
    private lateinit var blocklist: BlocklistRepository
    private lateinit var dnsProcessor: DnsPacketProcessor
    private lateinit var udpRelay: UdpRelay
    private lateinit var tcpRelay: TcpRelay

    private var tunOutput: FileOutputStream? = null
    private val writeLock = Any()

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

        dnsProcessor = DnsPacketProcessor(
            blocklist = blocklist,
            protectSocket = { socket: DatagramSocket -> protect(socket) },
            upstreamDns = InetAddress.getByName(UPSTREAM_DNS)
        )
        udpRelay = UdpRelay(
            protectSocket = { socket: DatagramSocket -> protect(socket) },
            writeToTun = { packet -> writeToTun(packet) }
        )
        tcpRelay = TcpRelay(
            protectSocket = { socket: Socket -> protect(socket) },
            writeToTun = { packet -> writeToTun(packet) }
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
        com.focusshield.app.vpn.DebugLog.start(applicationContext)
        if (vpnInterface != null) return // already running

        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("FocusShield")
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(DNS_ADDRESS)
            // Full default-route split. Everything goes through the tun now,
            // not just DNS - that's the whole point of this version: it lets
            // the system "Block connections without VPN" switch work without
            // killing all traffic, because now all traffic legitimately is
            // VPN traffic.
            .addRoute("0.0.0.0", 1)
            .addRoute("128.0.0.0", 1)
            .setBlocking(true)
            .setMtu(1500)

        vpnInterface = builder.establish() ?: run {
            stopVpn()
            return
        }

        tunOutput = FileOutputStream(vpnInterface!!.fileDescriptor)
        scope.launch { runPacketLoop() }
    }

    private fun runPacketLoop() {
        val iface = vpnInterface ?: return
        val input = FileInputStream(iface.fileDescriptor)
        val buffer = ByteArray(32767)

        while (vpnInterface != null) {
            val length = try {
                input.read(buffer)
            } catch (e: Exception) {
                break
            }
            if (length <= 0) continue

            try {
                demux(buffer, length)
            } catch (e: Exception) {
                // malformed/unsupported packet - drop and keep going
            }
        }
    }

    /** Looks at the IP header to decide which handler owns this packet. */
    private fun demux(buffer: ByteArray, length: Int) {
        if (length < 20) return
        val ipVersion = (buffer[0].toInt() shr 4) and 0xF
        if (ipVersion != 4) return // IPv6 not handled in this minimal version

        val protocol = buffer[9].toInt() and 0xFF
        when (protocol) {
            17 -> { // UDP
                val ihl = (buffer[0].toInt() and 0xF) * 4
                val dstPort = ((buffer[ihl + 2].toInt() and 0xFF) shl 8) or (buffer[ihl + 3].toInt() and 0xFF)
                if (dstPort == 53) {
                    val response = dnsProcessor.process(buffer, length)
                    if (response != null) writeToTun(response)
                } else {
                    routeUdpToRelay(buffer, length, ihl)
                }
            }
            6 -> { // TCP
                tcpRelay.handle(buffer.copyOf(length), length)
            }
            else -> {
                // ICMP and anything else: not relayed in this minimal version.
            }
        }
    }

    private fun routeUdpToRelay(buffer: ByteArray, length: Int, ihl: Int) {
        val srcIp = buffer.copyOfRange(12, 16)
        val dstIp = buffer.copyOfRange(16, 20)
        val srcPort = ((buffer[ihl].toInt() and 0xFF) shl 8) or (buffer[ihl + 1].toInt() and 0xFF)
        val dstPort = ((buffer[ihl + 2].toInt() and 0xFF) shl 8) or (buffer[ihl + 3].toInt() and 0xFF)
        val udpLength = ((buffer[ihl + 4].toInt() and 0xFF) shl 8) or (buffer[ihl + 5].toInt() and 0xFF)
        val payloadStart = ihl + 8
        val payloadLength = udpLength - 8
        if (payloadLength <= 0 || payloadStart + payloadLength > length) return
        val payload = buffer.copyOfRange(payloadStart, payloadStart + payloadLength)
        udpRelay.handle(srcIp, srcPort, dstIp, dstPort, payload)
    }

    /** All reply paths (main loop, UDP relay reader threads, TCP relay reader threads) funnel through here. */
    private fun writeToTun(packet: ByteArray) {
        synchronized(writeLock) {
            try {
                tunOutput?.write(packet)
            } catch (e: Exception) {
                // tun closed mid-write; safe to ignore, loop/session will exit
            }
        }
    }

    private fun stopVpn() {
        job.cancel()
        udpRelay.closeAll()
        tcpRelay.closeAll()
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            // already closed
        }
        vpnInterface = null
        tunOutput = null
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
