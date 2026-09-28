//  ShieldClient.swift
//
//  The API. It sends bytes and an attestation, and it derives nothing.
//
//  The server's tenant_api.py is shaped around one rule: nothing a caller
//  sends is evidence. The hash is computed there, EXIF is read there, the
//  distance from site is measured there against coordinates the record
//  carries and the uploader did not write. This file is the other side of that
//  rule, and it keeps it by omission — there is no code here that computes
//  `original_hash`, `has_exif`, `verdict`, `attestation_tier` or
//  `site_distance_m`, and adding any would be the defect, not a feature.
//
//  The one hash this file does compute is the attestation's client data, and
//  it is not evidence: it is a commitment the Secure Enclave signs. The server
//  recomputes it from the bytes that arrived and refuses if they differ, which
//  is exactly what makes it worth computing here.

import Foundation

enum ClientError: LocalizedError {
    case badURL
    case notConnected
    case http(Int, String)
    case transport(String)

    var errorDescription: String? {
        switch self {
        case .badURL:
            return "That is not a valid Shield address."
        case .notConnected:
            // Distinct from badURL on purpose. This one surfaces over the
            // viewfinder, and "that is not a valid Shield address" sends
            // somebody to re-type a URL that was never the problem.
            return "You are signed out of Shield. Connect again to record this capture."
        case .http(_, let message):
            // The server's refusals are written to be read by a person —
            // "This capture was not accepted: …" — so they are surfaced as
            // they are rather than replaced with a generic failure.
            return message
        case .transport(let why):
            return "Could not reach Shield: \(why)"
        }
    }
}

actor ShieldClient {
    private let base: URL
    private let token: String
    private let session: URLSession

    init(base: URL, token: String, session: URLSession = .shared) {
        self.base = base
        self.token = token
        self.session = session
    }

    // MARK: - reads

    func whoami() async throws -> WhoAmI {
        try await get("whoami")
    }

    func records() async throws -> [Record] {
        let list: RecordList = try await get("records")
        return list.records
    }

    func record(_ id: String) async throws -> RecordDetail {
        try await get("records/\(id)")
    }

    // MARK: - writes

    func openRecord(externalRef: String, trade: String?,
                    siteAddress: String?) async throws -> Record {
        var body: [String: Any] = ["external_ref": externalRef]
        if let trade, !trade.isEmpty { body["trade"] = trade }
        if let siteAddress, !siteAddress.isEmpty { body["site_address"] = siteAddress }
        let out: RecordResponse = try await postJSON("records", body)
        return out.record
    }

    func lockCheckpoints(_ recordID: String,
                         labels: [String]) async throws -> [Checkpoint] {
        let body = ["checkpoints": labels.map { ["label": $0] }]
        let out: CheckpointList = try await postJSON(
            "records/\(recordID)/checkpoints", body)
        return out.checkpoints
    }

    func challenge(for recordID: String) async throws -> Challenge {
        try await postJSON("records/\(recordID)/capture-challenge", [String: String]())
    }

    /// Photograph first, attest second, upload third.
    ///
    /// The order is the opposite of the intuitive one and it is the whole
    /// design: the attestation commits to these exact bytes, so the bytes have
    /// to exist before it is made. An app that attested at the start of the
    /// screen and photographed afterwards would produce something genuine that
    /// proves nothing about the file.
    ///
    /// `location` is sent because the device has it and the server's geofence
    /// wants it — and it is sent as what it is, the *device's claim*. The
    /// server measures it against site coordinates the record carries, which
    /// the person holding the phone did not write.
    func upload(photo: Data, to recordID: String, checkpoint checkpointID: String,
                location: (lat: Double, lng: Double)?) async throws -> StoredPhoto {
        let issued = try await challenge(for: recordID)
        let attestation = try await Attestor.attest(photo: photo,
                                                    challenge: issued.challenge)

        var fields: [String: String] = [
            "checkpoint_id": checkpointID,
            "attestation": attestation.blob.base64EncodedString(),
            "attestation_key_id": attestation.keyID,
            "attestation_challenge": issued.challenge,
            "attestation_platform": "ios",
        ]
        if let location {
            fields["gps_lat"] = String(location.lat)
            fields["gps_lng"] = String(location.lng)
        }

        let out: PhotoResponse = try await multipart(
            "records/\(recordID)/photos", fields: fields,
            file: photo, filename: "capture.jpg", mime: "image/jpeg")
        return out.photo
    }

    // MARK: - plumbing

    private func request(_ path: String, method: String) throws -> URLRequest {
        guard let url = URL(string: "shield/v2/\(path)", relativeTo: base) else {
            throw ClientError.badURL
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return req
    }

    private func send<T: Decodable>(_ req: URLRequest) async throws -> T {
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw ClientError.transport(error.localizedDescription)
        }
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else {
            // Surface the server's own words. A capture refused for a reason
            // the person can act on ("this device could not attest…") is worth
            // more than a status code, and the refusals were written to be
            // read.
            let message = (try? JSONDecoder().decode(APIError.self, from: data))?.error
                ?? "Shield returned \(code)."
            throw ClientError.http(code, message)
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func get<T: Decodable>(_ path: String) async throws -> T {
        try await send(request(path, method: "GET"))
    }

    private func postJSON<T: Decodable>(_ path: String, _ body: Any) async throws -> T {
        var req = try request(path, method: "POST")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        return try await send(req)
    }

    private func multipart<T: Decodable>(_ path: String, fields: [String: String],
                                         file: Data, filename: String,
                                         mime: String) async throws -> T {
        let boundary = "shield.\(UUID().uuidString)"
        var req = try request(path, method: "POST")
        req.setValue("multipart/form-data; boundary=\(boundary)",
                     forHTTPHeaderField: "Content-Type")

        var body = Data()
        func append(_ text: String) { body.append(Data(text.utf8)) }

        for (name, value) in fields {
            append("--\(boundary)\r\n")
            append("Content-Disposition: form-data; name=\"\(name)\"\r\n\r\n")
            append("\(value)\r\n")
        }
        append("--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"file\"; filename=\"\(filename)\"\r\n")
        append("Content-Type: \(mime)\r\n\r\n")
        body.append(file)
        append("\r\n--\(boundary)--\r\n")

        req.httpBody = body
        return try await send(req)
    }
}
