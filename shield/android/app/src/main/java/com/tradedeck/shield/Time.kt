package com.tradedeck.shield

import android.content.Context
import android.location.GnssClock
import android.location.Location
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import org.json.JSONObject
import kotlin.math.roundToLong

/**
 * The clocks a capture record and a job ticket are signed over.
 *
 * wall_time_ms is the wall clock, Unix milliseconds, a whole number.
 * monotonic_ms is elapsedRealtime(), which is already milliseconds and
 * includes sleep. It does not jump when the user sets the time. It does
 * reset on a reboot, which is why boot_count is Settings.Global.BOOT_COUNT.
 * A new boot is a new count, and the time rules then say UNVERIFIED TIME.
 *
 * GNSS time comes from GnssClock when a measurement is already in hand.
 * It is omitted when there is no clock. A missing reading is not a zero.
 * The conversion below has not been run on a device.
 */
data class PhoneClock(
    val wallTimeMs: Long,
    val monotonicMs: Long,
    val bootCount: Long?,
    val gnssTimeMs: Long?,
    val locationSimulated: Boolean?,
) {
    fun ticketClock(): JSONObject {
        val body = JSONObject()
        body.put("wall_time_ms", wallTimeMs)
        body.put("monotonic_ms", monotonicMs)
        if (bootCount != null) body.put("boot_count", bootCount)
        return body
    }

    fun canonicalClock(): ByteArray {
        val fields = linkedMapOf<String, Canon>(
            "wall_time_ms" to Canon.Num(wallTimeMs),
            "monotonic_ms" to Canon.Num(monotonicMs),
        )
        if (bootCount != null) fields["boot_count"] = Canon.Num(bootCount)
        return CanonicalJson.bytes(Canon.Obj(fields))
    }

    companion object {
        fun read(context: Context, location: Location?, gnss: GnssClock?): PhoneClock {
            val wall = System.currentTimeMillis()
            val mono = SystemClock.elapsedRealtime()
            val boot = bootCount(context)
            val simulated = location?.let { mock(it) }
            return PhoneClock(
                wallTimeMs = wall,
                monotonicMs = mono,
                bootCount = boot,
                gnssTimeMs = gnss?.let { gnssUnixMs(it) },
                locationSimulated = simulated,
            )
        }

        fun bootCount(context: Context): Long? {
            return try {
                val n = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT)
                if (n < 0) null else n.toLong()
            } catch (_: Settings.SettingNotFoundException) {
                null
            }
        }

        fun mock(location: Location): Boolean {
            return if (Build.VERSION.SDK_INT >= 31) location.isMock else location.isFromMockProvider
        }

        /**
         * GnssClock to Unix milliseconds.
         *
         * Android documents fullBiasNanos as the difference between the
         * receiver clock and true GPS time since 6 Jan 1980. Subtracting it
         * from timeNanos yields GPS-epoch nanoseconds. 315964800 seconds
         * separate that epoch from Unix. Leap seconds, when the clock
         * reports them, are taken off. biasNanos is a double on the
         * platform; it is rounded to a whole nanosecond here, and only the
         * resulting millisecond enters the record.
         *
         * Not run on a device. A wrong epoch offset would move every GNSS
         * reading by a constant, and the time rules would call that a
         * device-clock mismatch.
         */
        fun gnssUnixMs(clock: GnssClock): Long? {
            if (!clock.hasFullBiasNanos()) return null
            val bias = if (clock.hasBiasNanos()) clock.biasNanos.roundToLong() else 0L
            val gpsNanos = clock.timeNanos - clock.fullBiasNanos - bias
            val leapSec = if (clock.hasLeapSecond()) clock.leapSecond.toLong() else 18L
            val gpsEpochOffsetMs = 315964800_000L
            return roundNanosToMs(gpsNanos) + gpsEpochOffsetMs - leapSec * 1000L
        }

        private fun roundNanosToMs(nanos: Long): Long {
            val ms = nanos / 1_000_000L
            val rem = nanos % 1_000_000L
            return if (nanos >= 0) {
                if (rem >= 500_000L) ms + 1 else ms
            } else {
                if (rem <= -500_000L) ms - 1 else ms
            }
        }
    }
}
