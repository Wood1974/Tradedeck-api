package com.tradedeck.shield

import org.json.JSONObject

/**
 * One on-phone capture record. The bytes are capture_record.py's bytes:
 * version 1, whole numbers, sorted keys, nulls omitted. prev_hash and
 * record_hash sit beside the signed fields. The first record's prev_hash
 * is the job-ticket hash.
 *
 * Android reports boot_count (Settings.Global.BOOT_COUNT), not an iOS boot
 * id. The fixture strings below are what Python emits for the same fields.
 * tests/test_android_record_bytes.py fails if they drift. This file has
 * been compiled by CI when the Android workflow runs. It has not been run
 * on a device.
 */
class CaptureRecordBody(
    val checkpointId: String,
    val photoSha256: String,
    val ticketId: String,
    val wallTimeMs: Long,
    val monotonicMs: Long,
    val flags: Int,
    val bootCount: Long? = null,
    val gnssTimeMs: Long? = null,
    val locationSimulated: Boolean? = null,
    val sensorHash: String? = null,
    val depthHash: String? = null,
    val depthPresent: Boolean? = null,
) {
    fun canon(): Canon {
        val fields = linkedMapOf<String, Canon>(
            "version" to Canon.Num(1),
            "checkpoint_id" to Canon.Str(checkpointId),
            "photo_sha256" to Canon.Str(photoSha256),
            "ticket_id" to Canon.Str(ticketId),
            "wall_time_ms" to Canon.Num(wallTimeMs),
            "monotonic_ms" to Canon.Num(monotonicMs),
            "flags" to Canon.Num(flags.toLong()),
        )
        bootCount?.let { fields["boot_count"] = Canon.Num(it) }
        gnssTimeMs?.let { fields["gnss_time_ms"] = Canon.Num(it) }
        locationSimulated?.let { fields["location_simulated"] = Canon.Bool(it) }
        sensorHash?.let { fields["sensor_hash"] = Canon.Str(it) }
        depthHash?.let { fields["depth_hash"] = Canon.Str(it) }
        depthPresent?.let { fields["depth_present"] = Canon.Bool(it) }
        return Canon.Obj(fields)
    }

    /** The signed JSON, then SHA256(json || "|" || prevHash). */
    fun seal(prevHash: String): Pair<ByteArray, String> {
        val json = CanonicalJson.bytes(canon())
        val linked = json + ("|$prevHash").toByteArray(Charsets.UTF_8)
        return json to Digests.sha256Hex(linked)
    }

    /** The object the queue route re-reads. Chain links are not inside the hash. */
    fun payload(prevHash: String, recordHash: String): JSONObject {
        val body = JSONObject()
        body.put("version", 1)
        body.put("checkpoint_id", checkpointId)
        body.put("photo_sha256", photoSha256)
        body.put("ticket_id", ticketId)
        body.put("wall_time_ms", wallTimeMs)
        body.put("monotonic_ms", monotonicMs)
        body.put("flags", flags)
        body.put("prev_hash", prevHash)
        body.put("record_hash", recordHash)
        bootCount?.let { body.put("boot_count", it) }
        gnssTimeMs?.let { body.put("gnss_time_ms", it) }
        locationSimulated?.let { body.put("location_simulated", it) }
        sensorHash?.let { body.put("sensor_hash", it) }
        depthHash?.let { body.put("depth_hash", it) }
        depthPresent?.let { body.put("depth_present", it) }
        return body
    }
}

/**
 * Golden bytes. Python is the writer of these strings; this file only holds
 * them so a test can see that the contract copied here has not been edited
 * into something else.
 */
object CaptureRecordFixtures {
    const val plainCanonical =
        """{"boot_count":4,"checkpoint_id":"cp-1","flags":0,"monotonic_ms":5000000,"photo_sha256":"abababababababababababababababababababababababababababababababab","ticket_id":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","version":1,"wall_time_ms":1700000000000}"""
    const val plainPrev = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    const val plainHash = "8e3a9f90f7aeb6624f2478aa8b1545463631af8f3db98532608b916453416217"

    const val flaggedCanonical =
        """{"boot_count":7,"checkpoint_id":"cp-2","depth_present":false,"flags":15,"gnss_time_ms":1700000010050,"location_simulated":false,"monotonic_ms":5010000,"photo_sha256":"1111111111111111111111111111111111111111111111111111111111111111","sensor_hash":"2222222222222222222222222222222222222222222222222222222222222222","ticket_id":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","version":1,"wall_time_ms":1700000010000}"""
    const val flaggedPrev = "abababababababababababababababababababababababababababababababab"
    const val flaggedHash = "9491051b3ae2ad1309a712a64789e28951b3b0c76f8e954945606d8264d3dc10"

    const val sensorCanonical =
        """{"accel_milli_g":[0,0,1000],"baro_pa":101325,"gyro_milli_rad_s":[1,-2,3]}"""
    const val sensorHash = "e64c6df1f825c2ffd0bd83a5f803336a60bd123ede140d28ef744d8364c2b0a9"

    const val clockCanonical =
        """{"boot_count":4,"monotonic_ms":5000000,"wall_time_ms":1700000000000}"""
}
