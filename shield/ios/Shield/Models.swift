//  Models.swift
//
//  What the API returns. Nothing here is computed by the client, and that is
//  a rule rather than an accident: `original_hash`, `verdict`,
//  `attestation_tier`, `site_distance_m` and `has_exif` are all derived on the
//  server from the bytes that arrived. The app displays them. If it ever
//  computes one, the value on screen becomes indistinguishable from one the
//  server stood behind, which is the confusion Shield exists to remove.

import Foundation

struct Tenant: Decodable {
    let id: String
    let name: String
}

struct WhoAmI: Decodable {
    let tenant: Tenant
    let credential: String
    let role: String?
    let chain_version: Int?
}

struct Record: Decodable, Identifiable {
    let id: String
    let external_ref: String
    let trade: String?
    let site_address: String?
    let status: String?
    let checkpoints_locked_at: String?

    var isLocked: Bool { checkpoints_locked_at != nil }
}

struct Checkpoint: Decodable, Identifiable {
    let id: String
    let label: String
    let point_number: Int?
    let must_show: String?
}

struct Challenge: Decodable {
    let challenge: String
    let expires_in_s: Int?
}

/// The server's answer to one upload. `attestation_tier` is the server's
/// reading of the attestation this app produced — shown back so the person
/// holding the phone sees what was actually recorded rather than what the app
/// hoped for.
struct StoredPhoto: Decodable {
    let id: String
    let original_hash: String?
    let attestation_tier: String?
    let has_exif: Bool?
    let site_distance_m: Double?
}

struct APIError: Decodable {
    let error: String
}

/// Wrappers for the shapes the API returns.
struct RecordList: Decodable { let records: [Record] }
struct RecordResponse: Decodable { let record: Record }
struct CheckpointList: Decodable { let checkpoints: [Checkpoint] }
struct PhotoResponse: Decodable { let photo: StoredPhoto }

/// `GET /records/<id>` returns the record together with its checkpoints, each
/// carrying whichever photograph is currently live for it. A retake
/// supersedes rather than replaces, so `live_photo` is the one that counts and
/// the superseded ones stay in the record.
struct RecordDetail: Decodable {
    let record: Record
    let checkpoints: [CheckpointWithPhoto]
    let photos_total: Int?
    let photos_superseded: Int?
}

struct CheckpointWithPhoto: Decodable, Identifiable {
    let id: String
    let label: String
    let point_number: Int?
    let must_show: String?
    let live_photo: StoredPhoto?
}
