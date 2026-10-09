//  Outbox.swift
//
//  Photographs taken with no signal. One file per capture, plus a manifest
//  that only grows. A line is appended. A line is not rewritten and not
//  deleted. When the phone has a signal again, the first captures that
//  have not been acknowledged go up in a batch of at most 8, which is the
//  server's cap. An acknowledgement is another appended line.
//
//  Files are protected with completeUntilFirstUserAuthentication. After a
//  reboot the queue is readable once the person has unlocked the phone,
//  which is when they can take the next photo anyway. It is not readable
//  from a locked phone that has not been unlocked since boot.
//
//  Compiled in CI. Not run on a device.

import CoreLocation
import Darwin
import Foundation

enum OutboxError: LocalizedError {
    case io(String)
    case broken(String)
    case noTicket

    var errorDescription: String? {
        switch self {
        case .io(let why): return why
        case .broken(let why): return why
        case .noTicket:
            return "This record has no job ticket on this phone yet. " +
                "Ask for one while the phone still has a signal."
        }
    }
}

struct QueuedCapture {
    let record: [String: Any]
    let assertion: String
    let photo: Data
    let recordHash: String
}

actor Outbox {
    static let shared = Outbox()

    private let genesis = Data("shield-outbox-v1".utf8)

    func rememberTicket(recordID: String, ticketHash: String) throws {
        let dir = try directory(recordID)
        let url = dir.appendingPathComponent("ticket.json")
        if FileManager.default.fileExists(atPath: url.path) {
            let existing = try Data(contentsOf: url)
            let obj = try JSONSerialization.jsonObject(with: existing) as? [String: Any]
            if obj?["ticket_hash"] as? String != ticketHash {
                throw OutboxError.broken(
                    "This phone already stored a different job ticket for this record.")
            }
            return
        }
        let body = try JSONSerialization.data(withJSONObject: [
            "record_id": recordID,
            "ticket_hash": ticketHash,
        ])
        try body.write(to: url, options: [.completeFileProtectionUntilFirstUserAuthentication])
    }

    func ticketHash(recordID: String) throws -> String {
        let url = try directory(recordID).appendingPathComponent("ticket.json")
        guard let data = try? Data(contentsOf: url),
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let hash = obj["ticket_hash"] as? String else {
            throw OutboxError.noTicket
        }
        return hash
    }

    /// Append one capture. `prevHash` is the ticket hash for the first
    /// photo and the previous record hash after that. The caller computed
    /// the record; this does not rewrite it.
    func enqueue(recordID: String, record: [String: Any], recordJSON: Data,
                 recordHash: String, assertion: Data, jpeg: Data) throws {
        let dir = try directory(recordID)
        let photoURL = dir.appendingPathComponent("photos").appendingPathComponent(recordHash + ".jpg")
        let itemURL = dir.appendingPathComponent("items").appendingPathComponent(recordHash + ".json")
        try jpeg.write(to: photoURL, options: [.completeFileProtectionUntilFirstUserAuthentication])
        let item = try JSONSerialization.data(withJSONObject: [
            "record": record,
            "assertion": assertion.base64EncodedString(),
        ])
        try item.write(to: itemURL, options: [.completeFileProtectionUntilFirstUserAuthentication])
        // The exact bytes that were hashed. A device check can compare this
        // file to capture_record.py. The upload sends the fields; the server
        // canonicalises them again.
        let canonURL = dir.appendingPathComponent("items")
            .appendingPathComponent(recordHash + ".canonical.json")
        try recordJSON.write(to: canonURL, options: [.completeFileProtectionUntilFirstUserAuthentication])
        let prev = try lastManifestHash(recordID: recordID)
        let line = CanonicalJSON.data(.object([
            "kind": .string("capture"),
            "prev": .string(prev),
            "record_hash": .string(recordHash),
        ]))
        try append(line, recordID: recordID)
    }

    /// Captures with no later ack, in order, at most `limit` (the server
    /// accepts 8). A manifest whose prev does not match is not uploaded
    /// past the break.
    func pending(recordID: String, limit: Int = 8) throws -> [QueuedCapture] {
        let lines = try readLines(recordID: recordID)
        var expected = Digests.sha256Hex(genesis)
        var acked: Set<String> = []
        var waiting: [String] = []
        for line in lines {
            let hash = Digests.sha256Hex(line)
            let obj = try JSONSerialization.jsonObject(with: line) as? [String: Any]
            guard let prev = obj?["prev"] as? String, prev == expected else {
                throw OutboxError.broken(
                    "The outbox manifest does not chain. Nothing will be uploaded past the break.")
            }
            expected = hash
            let kind = obj?["kind"] as? String
            if kind == "capture", let recordHash = obj?["record_hash"] as? String {
                waiting.append(recordHash)
            } else if kind == "ack", let through = obj?["through"] as? String {
                if let end = waiting.firstIndex(of: through) {
                    acked.formUnion(waiting[...end])
                }
            }
        }
        let dir = try directory(recordID)
        var out: [QueuedCapture] = []
        for recordHash in waiting where !acked.contains(recordHash) {
            if out.count == limit { break }
            let itemURL = dir.appendingPathComponent("items").appendingPathComponent(recordHash + ".json")
            let photoURL = dir.appendingPathComponent("photos").appendingPathComponent(recordHash + ".jpg")
            let item = try JSONSerialization.jsonObject(with: Data(contentsOf: itemURL)) as? [String: Any]
            guard let record = item?["record"] as? [String: Any],
                  let assertion = item?["assertion"] as? String else {
                throw OutboxError.broken("A queued capture could not be read.")
            }
            out.append(QueuedCapture(
                record: record, assertion: assertion,
                photo: try Data(contentsOf: photoURL), recordHash: recordHash))
        }
        return out
    }

    func acknowledge(recordID: String, through recordHash: String) throws {
        let prev = try lastManifestHash(recordID: recordID)
        let line = CanonicalJSON.data(.object([
            "kind": .string("ack"),
            "prev": .string(prev),
            "through": .string(recordHash),
        ]))
        try append(line, recordID: recordID)
    }

    /// The phone-chain head so far: the last capture in the manifest, or
    /// the ticket hash when nothing has been queued.
    func chainHead(recordID: String) throws -> String {
        let lines = try readLines(recordID: recordID)
        var head = try ticketHash(recordID: recordID)
        var expected = Digests.sha256Hex(genesis)
        for line in lines {
            let obj = try JSONSerialization.jsonObject(with: line) as? [String: Any]
            guard obj?["prev"] as? String == expected else { break }
            expected = Digests.sha256Hex(line)
            if obj?["kind"] as? String == "capture",
               let recordHash = obj?["record_hash"] as? String {
                head = recordHash
            }
        }
        return head
    }

    /// Send at most 8, then the next 8, until the queue is empty or the
    /// server refuses. A refusal leaves the files where they are.
    func flush(client: ShieldClient, recordID: String) async throws -> [String: Any]? {
        var last: [String: Any]?
        while true {
            let batch = try pending(recordID: recordID, limit: 8)
            if batch.isEmpty { return last }
            let body = batch.map { item -> [String: Any] in
                [
                    "photo_b64": item.photo.base64EncodedString(),
                    "record": item.record,
                    "assertion": item.assertion,
                ]
            }
            let reply = try await client.uploadBatch(
                recordID: recordID, captures: body,
                phoneChainHead: batch[batch.count - 1].recordHash)
            try acknowledge(recordID: recordID, through: batch[batch.count - 1].recordHash)
            last = reply
        }
    }

    // MARK: - files

    private func directory(_ recordID: String) throws -> URL {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true)
        let dir = base.appendingPathComponent("shield-outbox", isDirectory: true)
            .appendingPathComponent(recordID, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [
            .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        ])
        for name in ["photos", "items"] {
            try FileManager.default.createDirectory(
                at: dir.appendingPathComponent(name, isDirectory: true),
                withIntermediateDirectories: true, attributes: [
                    .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
                ])
        }
        return dir
    }

    private func manifestURL(_ recordID: String) throws -> URL {
        try directory(recordID).appendingPathComponent("manifest.jsonl")
    }

    private func lastManifestHash(recordID: String) throws -> String {
        let lines = try readLines(recordID: recordID)
        guard let last = lines.last else { return Digests.sha256Hex(genesis) }
        return Digests.sha256Hex(last)
    }

    private func readLines(recordID: String) throws -> [Data] {
        let url = try manifestURL(recordID)
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let text = try Data(contentsOf: url)
        var lines: [Data] = []
        var start = 0
        let bytes = [UInt8](text)
        for (index, byte) in bytes.enumerated() where byte == 0x0A {
            if index > start {
                lines.append(Data(bytes[start..<index]))
            }
            start = index + 1
        }
        if start < bytes.count {
            lines.append(Data(bytes[start...]))
        }
        return lines
    }

    private func append(_ json: Data, recordID: String) throws {
        let url = try manifestURL(recordID)
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [
                .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
            ])
        }
        let fd = url.path.withCString { Darwin.open($0, O_WRONLY | O_APPEND) }
        if fd < 0 {
            throw OutboxError.io("The outbox manifest could not be opened.")
        }
        defer { Darwin.close(fd) }
        var line = json
        line.append(0x0A)
        let wrote: Int = try line.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return 0 }
            var done = 0
            while done < raw.count {
                let n = Darwin.write(fd, base.advanced(by: done), raw.count - done)
                if n < 0 {
                    throw OutboxError.io("The outbox manifest could not be appended.")
                }
                if n == 0 { break }
                done += n
            }
            return done
        }
        if wrote != line.count {
            throw OutboxError.io("The outbox manifest was only partly written.")
        }
    }
}

/// One offline photograph: hash the JPEG, build the record, sign the
/// record hash, append it. Uploading is `Outbox.flush`, on reconnect.
@MainActor
enum OfflineCapture {
    static func store(frame: CapturedFrame, recordID: String, checkpointID: String,
                      location: CLLocation?) async throws -> String {
        let ticket = try await Outbox.shared.ticketHash(recordID: recordID)
        let prev = try await Outbox.shared.chainHead(recordID: recordID)
        SensorReader.shared.start()
        let clock = PhoneClock.read(location: location)
        let flags = CaptureFlag.bits(locationSimulated: clock.locationSimulated)
        let body = CaptureRecordBody(
            checkpointID: checkpointID,
            photoSHA256: frame.sha256Hex,
            ticketID: ticket,
            wallTimeMs: clock.wallTimeMs,
            monotonicMs: clock.monotonicMs,
            flags: flags,
            bootID: clock.bootID,
            gnssTimeMs: clock.gnssTimeMs,
            locationSimulated: clock.locationSimulated,
            sensorHash: SensorReader.shared.snapshotHash(),
            depthHash: frame.depthHash,
            depthPresent: frame.depthPresent ? true : false)
        let sealed = body.seal(prevHash: prev)
        guard let raw = Digests.hexBytes(sealed.recordHash) else {
            throw OutboxError.broken("The capture record hash was not 32 bytes.")
        }
        let proof = try await Attestor.assertRecord(recordHash: raw)
        try await Outbox.shared.enqueue(
            recordID: recordID,
            record: body.payload(prevHash: prev, recordHash: sealed.recordHash),
            recordJSON: sealed.json,
            recordHash: sealed.recordHash,
            assertion: proof.blob,
            jpeg: frame.jpeg)
        return sealed.recordHash
    }
}
