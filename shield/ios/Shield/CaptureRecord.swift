//  CaptureRecord.swift
//
//  One on-phone capture record. The bytes are capture_record.py's bytes:
//  version 1, whole numbers, sorted keys, nulls omitted. prev_hash and
//  record_hash sit beside the signed fields. The first record's prev_hash
//  is the job-ticket hash.
//
//  The fixture strings below are what Python emits for the same fields.
//  They are not an example of the style. tests/test_ios_record_bytes.py
//  fails if they drift from capture_record.py. CI compiles this file. It
//  does not run it.

import Foundation

struct CaptureRecordBody {
    var checkpointID: String
    var photoSHA256: String
    var ticketID: String
    var wallTimeMs: Int
    var monotonicMs: Int
    var flags: Int
    var bootID: String?
    var gnssTimeMs: Int?
    var locationSimulated: Bool?
    var sensorHash: String?
    var depthHash: String?
    var depthPresent: Bool?
    /// Set only when the tenant opted in. Nil leaves the field out of the record.
    var gnssFixHash: String?
    var clipSHA256: String?

    func canon() -> Canon {
        var fields: [String: Canon] = [
            "version": .int(1),
            "checkpoint_id": .string(checkpointID),
            "photo_sha256": .string(photoSHA256),
            "ticket_id": .string(ticketID),
            "wall_time_ms": .int(wallTimeMs),
            "monotonic_ms": .int(monotonicMs),
            "flags": .int(flags),
        ]
        if let bootID { fields["boot_id"] = .string(bootID) }
        if let gnssTimeMs { fields["gnss_time_ms"] = .int(gnssTimeMs) }
        if let locationSimulated { fields["location_simulated"] = .bool(locationSimulated) }
        if let sensorHash { fields["sensor_hash"] = .string(sensorHash) }
        if let depthHash { fields["depth_hash"] = .string(depthHash) }
        if let depthPresent { fields["depth_present"] = .bool(depthPresent) }
        if let gnssFixHash { fields["gnss_fix_hash"] = .string(gnssFixHash) }
        if let clipSHA256 { fields["clip_sha256"] = .string(clipSHA256) }
        return .object(fields)
    }

    /// The signed JSON, then SHA256(json || "|" || prevHash).
    func seal(prevHash: String) -> (json: Data, recordHash: String) {
        let json = CanonicalJSON.data(canon())
        var linked = json
        linked.append(contentsOf: ("|" + prevHash).utf8)
        return (json, Digests.sha256Hex(linked))
    }

    /// The object the queue route re-reads. Same fields the hash covers,
    /// plus the chain links, which are not inside the hash.
    func payload(prevHash: String, recordHash: String) -> [String: Any] {
        var body: [String: Any] = [
            "version": 1,
            "checkpoint_id": checkpointID,
            "photo_sha256": photoSHA256,
            "ticket_id": ticketID,
            "wall_time_ms": wallTimeMs,
            "monotonic_ms": monotonicMs,
            "flags": flags,
            "prev_hash": prevHash,
            "record_hash": recordHash,
        ]
        if let bootID { body["boot_id"] = bootID }
        if let gnssTimeMs { body["gnss_time_ms"] = gnssTimeMs }
        if let locationSimulated { body["location_simulated"] = locationSimulated }
        if let sensorHash { body["sensor_hash"] = sensorHash }
        if let depthHash { body["depth_hash"] = depthHash }
        if let depthPresent { body["depth_present"] = depthPresent }
        if let gnssFixHash { body["gnss_fix_hash"] = gnssFixHash }
        if let clipSHA256 { body["clip_sha256"] = clipSHA256 }
        return body
    }
}

/// Golden bytes. Python is the writer of these strings; this file only holds
/// them so a test can see that the contract copied here has not been edited
/// into something else.
enum CaptureRecordFixtures {
    static let plainCanonical = #"{"boot_id":"BOOT-UUID","checkpoint_id":"cp-1","flags":0,"monotonic_ms":5000000,"photo_sha256":"abababababababababababababababababababababababababababababababab","ticket_id":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","version":1,"wall_time_ms":1700000000000}"#
    static let plainPrev = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    static let plainHash = "aff1fc7750cce11e1b603ffac3a6517df478d7265018d7977a86db323211b2cd"

    static let flaggedCanonical = #"{"boot_id":"BOOT-UUID","checkpoint_id":"cp-2","depth_present":false,"flags":15,"gnss_time_ms":1700000010050,"location_simulated":false,"monotonic_ms":5010000,"photo_sha256":"1111111111111111111111111111111111111111111111111111111111111111","sensor_hash":"2222222222222222222222222222222222222222222222222222222222222222","ticket_id":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","version":1,"wall_time_ms":1700000010000}"#
    static let flaggedPrev = "abababababababababababababababababababababababababababababababab"
    static let flaggedHash = "2d378c221eb5fe52ca43a5e32a5e89f3fd256b993a5b78a2dd9a7101b7f014e8"

    static let sensorCanonical = #"{"accel_milli_g":[0,0,1000],"baro_pa":101325,"gyro_milli_rad_s":[1,-2,3]}"#
    static let sensorHash = "e64c6df1f825c2ffd0bd83a5f803336a60bd123ede140d28ef744d8364c2b0a9"

    static let clockCanonical = #"{"boot_id":"BOOT-UUID","monotonic_ms":5000000,"wall_time_ms":1700000000000}"#
}
