package com.tradedeck.shield

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * The API. It sends bytes and a signature, and it derives nothing the
 * server is supposed to derive.
 *
 * The one hash computed here is the commitment the keystore signs. The
 * server recomputes it from the bytes that arrived.
 *
 * Play Integrity is requested once, at genesis, and the decoded token body
 * is sent along. This server release does not call Google, so a body that
 * arrives is stored as unverifiable, not as a pass. If Play returns nothing
 * the field is omitted, and the server stores absent, which is not a failure.
 *
 * Not run on a device.
 */
class ShieldClient(
    private val context: Context,
    private val base: String,
    private val token: String,
) {
    class HttpException(val code: Int, message: String, val reattest: Boolean = false) :
        Exception(message)

    fun establishTicket(recordId: String, clock: PhoneClock, cloudProjectNumber: Long?): String {
        val offer = postJson("records/$recordId/genesis", JSONObject().put("platform", "android"))
        if (offer.optBoolean("stored", true)) {
            throw HttpException(0, "The job ticket offer could not be read.")
        }
        val ticket = offer.optJSONObject("ticket")
            ?: throw HttpException(0, "The job ticket offer could not be read.")
        val ticketHash = offer.optString("ticket_hash")
        val serverSignature = offer.optString("server_signature")
        val raw = Digests.hexBytes(ticketHash)
            ?: throw HttpException(0, "The job ticket hash was not 32 bytes.")
        val clockJson = clock.canonicalClock()
        val payload = Digests.sha256(raw + clockJson)
        val clientData = Attestor.clientData("shield-genesis-v1", payload)
        val (alias, signature) = Attestor.sign(context, clientData)
        val body = JSONObject()
            .put("platform", "android")
            .put("ticket", ticket)
            .put("ticket_clock", clock.ticketClock())
            .put("server_signature", serverSignature)
            .put("assertion", Base64.encodeToString(signature, Base64.NO_WRAP))
            .put("attestation_key_id", Attestor.keyId(context))
        val play = playIntegrityBody(ticketHash, cloudProjectNumber)
        if (play != null) body.put("play_integrity", play)
        val sealed = postJson("records/$recordId/genesis", body)
        if (sealed.optBoolean("stored") != true && sealed.optString("ticket_hash").isEmpty()) {
            throw HttpException(0, "The job ticket was not stored.")
        }
        val storedHash = sealed.optString("ticket_hash", ticketHash)
        Outbox(context).rememberTicket(recordId, storedHash)
        // alias is unused beyond the sign call; the key id is what the server stores.
        if (alias.isEmpty()) throw IllegalStateException("no key")
        return storedHash
    }

    fun uploadBatch(recordId: String, captures: List<QueuedCapture>, phoneChainHead: String): JSONObject {
        val list = JSONArray()
        for (item in captures) {
            list.put(JSONObject()
                .put("photo_b64", Base64.encodeToString(item.photo, Base64.NO_WRAP))
                .put("record", item.record)
                .put("assertion", item.assertion))
        }
        return postJson("records/$recordId/queue", JSONObject()
            .put("platform", "android")
            .put("attestation_key_id", Attestor.keyId(context))
            .put("phone_chain_head", phoneChainHead)
            .put("captures", list))
    }

    /**
     * Online photograph. First capture on this install attests a new key.
     * A 422 with reattest deletes that key and tries once more.
     */
    fun uploadPhoto(recordId: String, checkpointId: String, jpeg: ByteArray): JSONObject {
        return try {
            attemptPhoto(recordId, checkpointId, jpeg)
        } catch (err: HttpException) {
            if (!err.reattest) throw err
            Attestor.forget(context)
            attemptPhoto(recordId, checkpointId, jpeg)
        }
    }

    private fun attemptPhoto(recordId: String, checkpointId: String, jpeg: ByteArray): JSONObject {
        val issued = postJson("records/$recordId/capture-challenge", JSONObject())
        val challenge = issued.optString("challenge")
        if (challenge.isEmpty()) throw HttpException(0, "Shield did not issue a challenge.")
        val photoHash = Digests.sha256(jpeg)
        val clientData = Attestor.clientData(challenge, photoHash)
        val fields = linkedMapOf(
            "checkpoint_id" to checkpointId,
            "attestation_challenge" to challenge,
            "attestation_platform" to "android",
        )
        if (Attestor.registeredAlias(context) == null) {
            val (alias, chain) = Attestor.attest(context, clientData)
            // The alias is kept only after the server says it stored the key.
            pendingAlias = alias
            fields["attestation"] = chain
            fields["attestation_key_id"] = keyIdForAlias(alias)
        } else {
            val (_, sig) = Attestor.sign(context, clientData)
            fields["assertion"] = Base64.encodeToString(sig, Base64.NO_WRAP)
            fields["attestation_key_id"] = Attestor.keyId(context)
        }
        val out = multipart("records/$recordId/photos", fields, jpeg)
        if (out.optBoolean("attestation_key_registered") && pendingAlias != null) {
            Attestor.keep(context, pendingAlias!!)
        }
        pendingAlias = null
        return out
    }

    private var pendingAlias: String? = null

    private fun keyIdForAlias(alias: String): String {
        // The key exists in the keystore even before we remember the alias.
        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val cert = ks.getCertificate(alias)
            ?: throw IllegalStateException("The new key has no certificate.")
        val point = Attestor.uncompressed(cert.publicKey as java.security.interfaces.ECPublicKey)
        return android.util.Base64.encodeToString(Digests.sha256(point), android.util.Base64.NO_WRAP)
    }

    /**
     * One Play Integrity token for this job. The nonce is the ticket hash,
     * URL-safe base64 with no padding, which is the shape Play requires.
     * The decoded body is what the server stores. A failure here is an
     * absent reading, not a refused ticket.
     */
    private fun playIntegrityBody(ticketHash: String, cloudProjectNumber: Long?): JSONObject? {
        return try {
            val raw = Digests.hexBytes(ticketHash) ?: return null
            val nonce = Base64.encodeToString(
                raw, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            val manager = IntegrityManagerFactory.create(context)
            val request = IntegrityTokenRequest.builder().setNonce(nonce).apply {
                if (cloudProjectNumber != null) setCloudProjectNumber(cloudProjectNumber)
            }.build()
            val token = com.google.android.gms.tasks.Tasks.await(
                manager.requestIntegrityToken(request), 20, TimeUnit.SECONDS)
            decodeJwtPayload(token.token())
        } catch (_: Exception) {
            null
        }
    }

    private fun decodeJwtPayload(token: String): JSONObject? {
        val parts = token.split('.')
        if (parts.size < 2) return null
        val body = parts[1]
        val pad = (4 - body.length % 4) % 4
        val bytes = Base64.decode(body + "=".repeat(pad), Base64.URL_SAFE)
        return JSONObject(String(bytes, Charsets.UTF_8))
    }

    private fun postJson(path: String, body: JSONObject): JSONObject {
        val conn = open(path, "POST")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.doOutput = true
        conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
        return read(conn)
    }

    private fun multipart(path: String, fields: Map<String, String>, jpeg: ByteArray): JSONObject {
        val boundary = "shield." + java.util.UUID.randomUUID()
        val conn = open(path, "POST")
        conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
        conn.doOutput = true
        conn.outputStream.use { out ->
            for ((name, value) in fields) {
                writeText(out, "--$boundary\r\n")
                writeText(out, "Content-Disposition: form-data; name=\"$name\"\r\n\r\n")
                writeText(out, "$value\r\n")
            }
            writeText(out, "--$boundary\r\n")
            writeText(out, "Content-Disposition: form-data; name=\"file\"; filename=\"capture.jpg\"\r\n")
            writeText(out, "Content-Type: image/jpeg\r\n\r\n")
            out.write(jpeg)
            writeText(out, "\r\n--$boundary--\r\n")
        }
        return read(conn)
    }

    private fun open(path: String, method: String): HttpURLConnection {
        val root = if (base.endsWith("/")) base else "$base/"
        val url = URL(root + "shield/v2/" + path)
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = method
        conn.setRequestProperty("Authorization", "Bearer $token")
        conn.connectTimeout = 30_000
        conn.readTimeout = 60_000
        return conn
    }

    private fun read(conn: HttpURLConnection): JSONObject {
        val code = conn.responseCode
        val stream = if (code in 200..299) conn.inputStream else conn.errorStream
        val text = stream?.bufferedReader()?.readText().orEmpty()
        if (code !in 200..299) {
            val obj = try { JSONObject(text) } catch (_: Exception) { null }
            val message = obj?.optString("error").orEmpty().ifEmpty { "Shield returned $code." }
            throw HttpException(code, message, obj?.optBoolean("reattest") == true)
        }
        return JSONObject(text)
    }

    private fun writeText(out: OutputStream, text: String) {
        out.write(text.toByteArray(Charsets.UTF_8))
    }
}
