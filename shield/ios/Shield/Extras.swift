//  Extras.swift
//
//  Opt-in extras. All off unless the tenant turns one on. whoami.opt_in
//  is the switch. A capture that leaves these nil is the capture this app
//  already seals. None of them is required for SEALED.
//
//  Compiled in CI. Not run on a device.

import Foundation

enum Extras {
    /// Canonical GNSS fix: time, satellite count, accuracy in millimetres,
    /// and the mock flag. The hex is what gnss_fix_hash on the record holds.
    static func gnssFixHash(timeMs: Int, satCount: Int, accuracyMm: Int,
                            mock: Bool) -> String {
        let json = CanonicalJSON.data(.object([
            "accuracy_mm": .int(accuracyMm),
            "mock": .bool(mock),
            "sat_count": .int(satCount),
            "time_ms": .int(timeMs),
        ]))
        return Digests.sha256Hex(json)
    }

    /// SHA-256 hex of a short clip. The bytes themselves are uploaded
    /// separately and stored under a clip path, not as the photograph.
    static func clipSHA256(_ data: Data) -> String {
        Digests.sha256Hex(data)
    }
}
