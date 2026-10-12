package com.tradedeck.shield

import java.security.MessageDigest

/**
 * The byte rules in capture_record.py. Keys sorted, separators tight, nulls
 * omitted from objects, UTF-8. A float is not a case here: the caller
 * converts to a whole number first.
 *
 * Non-ASCII is escaped as \uXXXX, including a surrogate pair past U+FFFF,
 * because that is what Python json.dumps does. The fixture strings in
 * CaptureRecord.kt are what capture_record.py emits. tests/test_android_record_bytes.py
 * reads them back. This file has not been executed on a device.
 */
sealed class Canon {
    data class Obj(val fields: Map<String, Canon>) : Canon()
    data class Arr(val items: List<Canon>) : Canon()
    data class Str(val value: String) : Canon()
    data class Num(val value: Long) : Canon()
    data class Bool(val value: Boolean) : Canon()
    data object Null : Canon()
}

object CanonicalJson {
    fun bytes(value: Canon): ByteArray = text(value).toByteArray(Charsets.UTF_8)

    fun text(value: Canon): String = when (value) {
        is Canon.Null -> "null"
        is Canon.Bool -> if (value.value) "true" else "false"
        is Canon.Num -> value.value.toString()
        is Canon.Str -> escape(value.value)
        is Canon.Arr -> value.items.joinToString(separator = ",", prefix = "[", postfix = "]") { text(it) }
        is Canon.Obj -> {
            val parts = value.fields.keys.sorted().mapNotNull { key ->
                val item = value.fields[key] ?: return@mapNotNull null
                if (item is Canon.Null) return@mapNotNull null
                escape(key) + ":" + text(item)
            }
            parts.joinToString(separator = ",", prefix = "{", postfix = "}")
        }
    }

    /** Python json.dumps, ensure_ascii=True, without escaping solidus. */
    fun escape(string: String): String {
        val out = StringBuilder("\"")
        val points = string.codePoints().iterator()
        while (points.hasNext()) {
            val code = points.nextInt()
            when (code) {
                0x22 -> out.append("\\\"")
                0x5C -> out.append("\\\\")
                0x08 -> out.append("\\b")
                0x0C -> out.append("\\f")
                0x0A -> out.append("\\n")
                0x0D -> out.append("\\r")
                0x09 -> out.append("\\t")
                in 0x00..0x1F, in 0x80..0xFFFF -> out.append("\\u%04x".format(code))
                in 0x10000..Int.MAX_VALUE -> {
                    val shifted = code - 0x10000
                    val high = 0xD800 + (shifted shr 10)
                    val low = 0xDC00 + (shifted and 0x3FF)
                    out.append("\\u%04x\\u%04x".format(high, low))
                }
                else -> out.appendCodePoint(code)
            }
        }
        out.append('"')
        return out.toString()
    }
}

object Digests {
    fun sha256(data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val chunk = 64 * 1024
        var offset = 0
        while (offset < data.size) {
            val end = minOf(offset + chunk, data.size)
            md.update(data, offset, end - offset)
            offset = end
        }
        return md.digest()
    }

    fun sha256Hex(data: ByteArray): String =
        sha256(data).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    fun hexBytes(hex: String): ByteArray? {
        if (hex.length != 64 || hex.any { it !in '0'..'9' && it !in 'a'..'f' }) return null
        val out = ByteArray(32)
        var i = 0
        while (i < 32) {
            val byte = hex.substring(i * 2, i * 2 + 2).toIntOrNull(16) ?: return null
            out[i] = byte.toByte()
            i++
        }
        return out
    }
}
