package com.focusshield.app

import android.app.Application
import android.content.ContentValues
import android.provider.MediaStore
import android.os.Environment
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class FocusShieldApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        val previousHandler = Thread.getDefaultUncaughtExceptionHandler()

        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                writeCrashToDownloads(thread, throwable)
            } catch (e: Exception) {
                // don't let a logging failure mask the real crash
            }
            previousHandler?.uncaughtException(thread, throwable)
        }
    }

    private fun writeCrashToDownloads(thread: Thread, throwable: Throwable) {
        val sw = StringWriter()
        throwable.printStackTrace(PrintWriter(sw))
        val timestamp = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date())
        val entry = "=== CRASH at $timestamp ===\nThread: ${thread.name}\n${sw}\n"

        val resolver = applicationContext.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, "focusshield_crash_$timestamp.txt")
            put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
        }
        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
        uri?.let {
            resolver.openOutputStream(it)?.use { os -> os.write(entry.toByteArray()) }
        }
    }
}
