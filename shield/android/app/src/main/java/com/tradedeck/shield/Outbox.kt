package com.tradedeck.shield

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKeys
import org.json.JSONObject
import java.io.File

/**
 * Photographs taken with no signal. One encrypted file per capture, plus a
 * manifest that only grows. A line is appended. A line is not rewritten and
 * not deleted.
 *
 * The photograph and the record are encrypted with a Keystore AES key
 * (EncryptedFile). The manifest is an append-only list of hashes in the
 * app's private directory, which is not shared storage. When the phone has
 * a signal again, the first captures that have not been acknowledged go up
 * in a batch of at most 8.
 *
 * Compiled when the Android workflow runs. Not run on a device.
 */
class Outbox(private val context: Context) {
    private val genesis = "shield-outbox-v1".toByteArray(Charsets.UTF_8)

    fun rememberTicket(recordId: String, ticketHash: String) {
        val file = ticketFile(recordId)
        if (file.exists()) {
            val existing = JSONObject(file.readText())
            if (existing.optString("ticket_hash") != ticketHash) {
                throw IllegalStateException(
                    "This phone already stored a different job ticket for this record.")
            }
            return
        }
        file.parentFile?.mkdirs()
        writeEncrypted(file, JSONObject()
            .put("record_id", recordId)
            .put("ticket_hash", ticketHash)
            .toString().toByteArray(Charsets.UTF_8))
    }

    fun ticketHash(recordId: String): String {
        val file = ticketFile(recordId)
        if (!file.exists()) {
            throw IllegalStateException(
                "This record has no job ticket on this phone yet. " +
                    "Ask for one while the phone still has a signal.")
        }
        val obj = JSONObject(String(readEncrypted(file), Charsets.UTF_8))
        return obj.getString("ticket_hash")
    }

    fun hasTicket(recordId: String): Boolean = ticketFile(recordId).exists()

    fun enqueue(
        recordId: String,
        record: JSONObject,
        recordJson: ByteArray,
        recordHash: String,
        assertion: String,
        jpeg: ByteArray,
    ) {
        val dir = directory(recordId)
        writeEncrypted(File(dir, "photos/$recordHash.jpg.enc"), jpeg)
        val item = JSONObject().put("record", record).put("assertion", assertion)
        writeEncrypted(File(dir, "items/$recordHash.json.enc"), item.toString().toByteArray(Charsets.UTF_8))
        writeEncrypted(File(dir, "items/$recordHash.canonical.json.enc"), recordJson)
        val prev = lastManifestHash(recordId)
        val line = CanonicalJson.bytes(Canon.Obj(mapOf(
            "kind" to Canon.Str("capture"),
            "prev" to Canon.Str(prev),
            "record_hash" to Canon.Str(recordHash),
        )))
        append(line, recordId)
    }

    fun pending(recordId: String, limit: Int = 8): List<QueuedCapture> {
        val lines = readLines(recordId)
        var expected = Digests.sha256Hex(genesis)
        val acked = mutableSetOf<String>()
        val waiting = mutableListOf<String>()
        for (line in lines) {
            val hash = Digests.sha256Hex(line)
            val obj = JSONObject(String(line, Charsets.UTF_8))
            val prev = obj.optString("prev")
            if (prev != expected) {
                throw IllegalStateException(
                    "The outbox manifest does not chain. Nothing will be uploaded past the break.")
            }
            expected = hash
            when (obj.optString("kind")) {
                "capture" -> waiting.add(obj.getString("record_hash"))
                "ack" -> {
                    val through = obj.optString("through")
                    val end = waiting.indexOf(through)
                    if (end >= 0) acked.addAll(waiting.subList(0, end + 1))
                }
            }
        }
        val dir = directory(recordId)
        val out = mutableListOf<QueuedCapture>()
        for (recordHash in waiting) {
            if (recordHash in acked) continue
            if (out.size == limit) break
            val item = JSONObject(String(
                readEncrypted(File(dir, "items/$recordHash.json.enc")), Charsets.UTF_8))
            out.add(QueuedCapture(
                record = item.getJSONObject("record"),
                assertion = item.getString("assertion"),
                photo = readEncrypted(File(dir, "photos/$recordHash.jpg.enc")),
                recordHash = recordHash,
            ))
        }
        return out
    }

    fun acknowledge(recordId: String, through: String) {
        val prev = lastManifestHash(recordId)
        val line = CanonicalJson.bytes(Canon.Obj(mapOf(
            "kind" to Canon.Str("ack"),
            "prev" to Canon.Str(prev),
            "through" to Canon.Str(through),
        )))
        append(line, recordId)
    }

    fun chainHead(recordId: String): String {
        var head = ticketHash(recordId)
        var expected = Digests.sha256Hex(genesis)
        for (line in readLines(recordId)) {
            val obj = JSONObject(String(line, Charsets.UTF_8))
            if (obj.optString("prev") != expected) break
            expected = Digests.sha256Hex(line)
            if (obj.optString("kind") == "capture") head = obj.getString("record_hash")
        }
        return head
    }

    /**
     * Send at most 8, then the next 8, until the queue is empty or the
     * server refuses. A refusal leaves the files where they are.
     */
    fun flush(client: ShieldClient, recordId: String): JSONObject? {
        var last: JSONObject? = null
        while (true) {
            val batch = pending(recordId, 8)
            if (batch.isEmpty()) return last
            val reply = client.uploadBatch(recordId, batch, batch.last().recordHash)
            acknowledge(recordId, batch.last().recordHash)
            last = reply
        }
    }

    private fun directory(recordId: String): File {
        val dir = File(context.filesDir, "shield-outbox/$recordId")
        File(dir, "photos").mkdirs()
        File(dir, "items").mkdirs()
        return dir
    }

    private fun ticketFile(recordId: String): File =
        File(directory(recordId), "ticket.json.enc")

    private fun manifestFile(recordId: String): File =
        File(directory(recordId), "manifest.jsonl")

    private fun lastManifestHash(recordId: String): String {
        val lines = readLines(recordId)
        val last = lines.lastOrNull() ?: return Digests.sha256Hex(genesis)
        return Digests.sha256Hex(last)
    }

    private fun readLines(recordId: String): List<ByteArray> {
        val file = manifestFile(recordId)
        if (!file.exists()) return emptyList()
        val text = file.readBytes()
        val lines = mutableListOf<ByteArray>()
        var start = 0
        for (i in text.indices) {
            if (text[i] == 0x0A.toByte()) {
                if (i > start) lines.add(text.copyOfRange(start, i))
                start = i + 1
            }
        }
        if (start < text.size) lines.add(text.copyOfRange(start, text.size))
        return lines
    }

    private fun append(json: ByteArray, recordId: String) {
        val file = manifestFile(recordId)
        file.parentFile?.mkdirs()
        file.appendBytes(json + byteArrayOf(0x0A))
    }

    private fun masterAlias(): String =
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

    private fun writeEncrypted(file: File, bytes: ByteArray) {
        file.parentFile?.mkdirs()
        if (file.exists()) return
        val encrypted = EncryptedFile.Builder(
            file,
            context,
            masterAlias(),
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build()
        encrypted.openFileOutput().use { it.write(bytes) }
    }

    private fun readEncrypted(file: File): ByteArray {
        val encrypted = EncryptedFile.Builder(
            file,
            context,
            masterAlias(),
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build()
        return encrypted.openFileInput().use { it.readBytes() }
    }
}

data class QueuedCapture(
    val record: JSONObject,
    val assertion: String,
    val photo: ByteArray,
    val recordHash: String,
)
