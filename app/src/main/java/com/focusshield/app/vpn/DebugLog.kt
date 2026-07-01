package com.focusshield.app.vpn

import android.content.ContentValues
import android.content.Context
import android.os.Environment
import android.provider.MediaStore
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object DebugLog {
    private var outputStream: OutputStream? = null
    private val lock = Any()
    private val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    fun start(context: Context) {
        synchronized(lock) {
            try {
                outputStream?.close()
                val resolver = context.applicationContext.contentResolver
                val fileName = "focusshield_debug_${System.currentTimeMillis()}.txt"
                val values = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                outputStream = uri?.let { resolver.openOutputStream(it, "w") }
                log("=== FocusShield debug session started ===")
            } catch (e: Exception) {
            }
        }
    }

    fun log(message: String) {
        synchronized(lock) {
            try {
                val line = "[${timeFormat.format(Date())}] $message\n"
                outputStream?.write(line.toByteArray())
                outputStream?.flush()
            } catch (e: Exception) {
            }
        }
    }

    fun stop() {
        synchronized(lock) {
            try {
                log("=== session ended ===")
                outputStream?.close()
            } catch (e: Exception) {
            }
            outputStream = null
        }
    }
}
