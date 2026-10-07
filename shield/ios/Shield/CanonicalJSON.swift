//  CanonicalJSON.swift
//
//  The byte rules in capture_record.py, for the values a phone actually
//  signs. Keys sorted, separators tight, nulls omitted from objects, UTF-8.
//  A float is not a case here: the caller converts to a whole number first.
//  Two encodings of the same reading would be two different records.
//
//  Non-ASCII is escaped as \uXXXX, including a surrogate pair past U+FFFF,
//  because that is what Python json.dumps does and the server hashes those
//  bytes. The fixtures in this file are the strings capture_record.py emits.
//  tests/test_ios_record_bytes.py reads them back.

import CryptoKit
import Foundation

enum Canon {
    case object([String: Canon])
    case array([Canon])
    case string(String)
    case int(Int)
    case bool(Bool)
    case null
}

enum CanonicalJSON {
    static func data(_ value: Canon) -> Data {
        Data(text(value).utf8)
    }

    static func text(_ value: Canon) -> String {
        switch value {
        case .null:
            return "null"
        case .bool(let flag):
            return flag ? "true" : "false"
        case .int(let number):
            return String(number)
        case .string(let string):
            return escape(string)
        case .array(let items):
            return "[" + items.map(text).joined(separator: ",") + "]"
        case .object(let fields):
            let parts = fields.keys.sorted().compactMap { key -> String? in
                guard let item = fields[key], !isNull(item) else { return nil }
                return escape(key) + ":" + text(item)
            }
            return "{" + parts.joined(separator: ",") + "}"
        }
    }

    private static func isNull(_ value: Canon) -> Bool {
        if case .null = value { return true }
        return false
    }

    /// Python json.dumps, ensure_ascii=True, without escaping solidus.
    static func escape(_ string: String) -> String {
        var out = "\""
        for scalar in string.unicodeScalars {
            let code = scalar.value
            switch code {
            case 0x22: out += "\\\""
            case 0x5C: out += "\\\\"
            case 0x08: out += "\\b"
            case 0x0C: out += "\\f"
            case 0x0A: out += "\\n"
            case 0x0D: out += "\\r"
            case 0x09: out += "\\t"
            case 0x00...0x1F:
                out += String(format: "\\u%04x", code)
            case 0x80...0xFFFF:
                out += String(format: "\\u%04x", code)
            case 0x10000...:
                let shifted = code - 0x10000
                let high = 0xD800 + (shifted >> 10)
                let low = 0xDC00 + (shifted & 0x3FF)
                out += String(format: "\\u%04x\\u%04x", high, low)
            default:
                out.unicodeScalars.append(scalar)
            }
        }
        out += "\""
        return out
    }
}

enum Digests {
    static func sha256(_ data: Data) -> Data {
        var hasher = SHA256()
        let chunk = 64 * 1024
        var offset = 0
        while offset < data.count {
            let end = min(offset + chunk, data.count)
            hasher.update(data: data.subdata(in: offset..<end))
            offset = end
        }
        return Data(hasher.finalize())
    }

    static func sha256Hex(_ data: Data) -> String {
        sha256(data).map { String(format: "%02x", $0) }.joined()
    }

    static func hexBytes(_ hex: String) -> Data? {
        guard hex.count == 64, hex.utf8.allSatisfy({
            (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
        }) else { return nil }
        var out = Data(capacity: 32)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        return out
    }
}
