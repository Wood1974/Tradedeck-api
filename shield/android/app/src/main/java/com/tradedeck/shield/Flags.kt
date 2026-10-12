package com.tradedeck.shield

import android.app.Activity
import android.os.Build
import android.os.Debug
import java.io.File

/**
 * Bits in the capture record. They are facts beside the photo. They do
 * not change SEALED, UNVERIFIED TIME, or DEVICE CLOCK MISMATCH.
 *
 * Root detection is best-effort and known to be incomplete. A hit sets the
 * root-traces bit. A miss means nothing. Key Attestation is what refuses an
 * unlocked bootloader. This bit is not that check.
 */
object CaptureFlag {
    const val SCREEN_CAPTURED = 1 shl 0
    const val DEBUGGER = 1 shl 1
    const val MOCK_LOCATION = 1 shl 2
    const val ROOT_TRACES = 1 shl 3

    fun bits(activity: Activity, locationSimulated: Boolean?): Int {
        var value = 0
        if (screenCaptured(activity)) value = value or SCREEN_CAPTURED
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) value = value or DEBUGGER
        if (locationSimulated == true) value = value or MOCK_LOCATION
        if (rootTraces()) value = value or ROOT_TRACES
        return value
    }

    /**
     * API 34 reports a capture that starts while the callback is registered.
     * A capture that was already running when the screen opened can be missed.
     * That miss does not change a label.
     */
    @Volatile
    var screenCaptureSeen: Boolean = false

    private var watching = false

    fun watchScreenCapture(activity: Activity) {
        if (watching || Build.VERSION.SDK_INT < 34) return
        watching = true
        activity.registerScreenCaptureCallback(activity.mainExecutor) {
            screenCaptureSeen = true
        }
    }

    private fun screenCaptured(activity: Activity): Boolean {
        watchScreenCapture(activity)
        return screenCaptureSeen
    }

    fun rootTraces(): Boolean {
        val paths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/app/Superuser.apk",
        )
        if (paths.any { File(it).exists() }) return true
        val tags = android.os.Build.TAGS ?: return false
        return tags.contains("test-keys")
    }
}
