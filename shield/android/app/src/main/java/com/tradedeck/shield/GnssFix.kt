package com.tradedeck.shield

/**
 * Opt-in extras. All off unless whoami.opt_in says otherwise. A capture
 * that leaves these null is the capture this app already seals. None of
 * them is required for SEALED.
 *
 * Compiled with the app. Not run on a device.
 */
object GnssFix {
    fun hash(timeMs: Long, satCount: Long, accuracyMm: Long, mock: Boolean): String {
        val json = CanonicalJson.bytes(Canon.Obj(mapOf(
            "accuracy_mm" to Canon.Num(accuracyMm),
            "mock" to Canon.Bool(mock),
            "sat_count" to Canon.Num(satCount),
            "time_ms" to Canon.Num(timeMs),
        )))
        return Digests.sha256Hex(json)
    }

    fun clipSha256(data: ByteArray): String = Digests.sha256Hex(data)

    /**
     * What the second phone signs: the countersign challenge followed by
     * the raw record hash. Pass the result to Attestor.sign. The server
     * accepts that signature only from a different attested key of the
     * same tenant. Scanning the QR is a device step this build does not do.
     */
    fun countersignClientData(recordHash: ByteArray): ByteArray =
        Attestor.clientData("shield-countersign-v1", recordHash)
}
