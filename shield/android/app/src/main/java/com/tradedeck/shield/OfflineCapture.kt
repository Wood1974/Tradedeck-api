package com.tradedeck.shield

import android.app.Activity
import android.location.Location

/**
 * One offline photograph: hash the JPEG, build the record, sign the record
 * hash, append it. Uploading is Outbox.flush, on reconnect.
 *
 * The signature is SHA256withECDSA over
 * "shield-capture-v1" || raw record hash. It is not pre-hashed.
 */
object OfflineCapture {
    fun store(
        activity: Activity,
        frame: CapturedFrame,
        recordId: String,
        checkpointId: String,
        location: Location?,
    ): String {
        val outbox = Outbox(activity)
        val ticket = outbox.ticketHash(recordId)
        val prev = outbox.chainHead(recordId)
        val clock = PhoneClock.read(activity, location, GnssHold.clock)
        val flags = CaptureFlag.bits(activity, clock.locationSimulated)
        val body = CaptureRecordBody(
            checkpointId = checkpointId,
            photoSha256 = frame.sha256Hex,
            ticketId = ticket,
            wallTimeMs = clock.wallTimeMs,
            monotonicMs = clock.monotonicMs,
            flags = flags,
            bootCount = clock.bootCount,
            gnssTimeMs = clock.gnssTimeMs,
            locationSimulated = clock.locationSimulated,
            sensorHash = SensorHold.reader?.snapshotHash(),
            depthHash = frame.depthHash,
            depthPresent = frame.depthPresent,
        )
        val (json, recordHash) = body.seal(prev)
        val raw = Digests.hexBytes(recordHash)
            ?: throw IllegalStateException("The capture record hash was not 32 bytes.")
        val (_, signature) = Attestor.sign(
            activity, Attestor.clientData("shield-capture-v1", raw))
        outbox.enqueue(
            recordId = recordId,
            record = body.payload(prev, recordHash),
            recordJson = json,
            recordHash = recordHash,
            assertion = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP),
            jpeg = frame.jpeg,
        )
        return recordHash
    }
}

data class CapturedFrame(
    val jpeg: ByteArray,
    val sha256Hex: String,
    val depthPresent: Boolean,
    val depthHash: String?,
)

/** The latest GNSS clock and sensor reader, filled by the activity. */
object GnssHold {
    @Volatile var clock: android.location.GnssClock? = null
}

object SensorHold {
    @Volatile var reader: SensorReader? = null
}

object CaptureHold {
    @Volatile var frame: CapturedFrame? = null
}
