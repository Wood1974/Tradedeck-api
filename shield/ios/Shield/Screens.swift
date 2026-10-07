//  Screens.swift
//
//  Connect, records, checkpoints, capture, result.
//
//  One presentation rule runs through all of it: every value on screen that
//  says something about a photograph came from the server. The hash, the tier,
//  whether EXIF was present, how far from site — the app displays them and
//  computes none of them. A number the phone worked out for itself would look
//  identical to one the server stood behind, and the whole product is the
//  difference between those two things.

import CoreLocation
import SwiftUI

// MARK: - connect

struct ConnectView: View {
    @EnvironmentObject var app: AppState
    @State private var address = ""
    @State private var token = ""
    @State private var busy = false

    var body: some View {
        Form {
            Section("Service") {
                TextField("https://shield.example.com", text: $address)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
            }
            Section("Credential") {
                SecureField("shld_… or a session token", text: $token)
                Text("The token stays on this device.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section {
                Button(busy ? "Connecting…" : "Connect") {
                    Task { busy = true; await app.connect(address, token); busy = false }
                }
                .disabled(busy || address.isEmpty || token.isEmpty)
            }
            if !Attestor.isSupported {
                Section {
                    // Said up front rather than at the moment of capture. On
                    // the Simulator nothing here can ever record a
                    // photograph, and finding that out after framing a shot
                    // is worse than knowing before.
                    Label("This device cannot attest a capture, so Shield " +
                          "cannot record a photograph from it. App Attest " +
                          "needs a real iPhone or iPad.",
                          systemImage: "exclamationmark.triangle")
                        .font(.footnote)
                }
            }
            if let problem = app.problem {
                Section { Text(problem).foregroundStyle(.red).font(.callout) }
            }
        }
        .navigationTitle("Shield")
    }
}

// MARK: - records

struct RecordsView: View {
    @EnvironmentObject var app: AppState

    var body: some View {
        List(app.records) { record in
            NavigationLink(value: record.id) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(record.external_ref).font(.headline)
                    Text([record.trade, record.site_address]
                            .compactMap { $0 }.joined(separator: " · "))
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
        .overlay {
            if app.records.isEmpty {
                ContentUnavailableView("No records",
                    systemImage: "tray",
                    description: Text("Open one in the Shield console, then " +
                                      "photograph its checkpoints here."))
            }
        }
        .refreshable { await app.loadRecords() }
        .navigationTitle(app.tenantName ?? "Records")
        .navigationDestination(for: String.self) { RecordView(recordID: $0) }
        .toolbar {
            Button("Sign out") { app.signOut() }
        }
    }
}

// MARK: - one record

struct RecordView: View {
    @EnvironmentObject var app: AppState
    let recordID: String
    @StateObject private var locator = Locator()
    @State private var detail: RecordDetail?
    @State private var capturing: CheckpointWithPhoto?
    @State private var sealing = false
    @State private var ticketNote: String?
    @State private var queueNote: String?

    var body: some View {
        List {
            Section {
                Button(sealing ? "Sealing the job ticket…" : "Seal job ticket") {
                    Task { await sealTicket() }
                }
                .disabled(sealing)
                Text("Do this while the phone still has a signal, after one " +
                     "photograph has attested this install. Later photographs " +
                     "can be taken with no signal. They stay on this phone " +
                     "until Shield is reachable again.")
                    .font(.footnote).foregroundStyle(.secondary)
                if let ticketNote {
                    Text(ticketNote).font(.footnote)
                }
                if let queueNote {
                    Text(queueNote).font(.footnote)
                }
            }
            if let detail {
                ForEach(detail.checkpoints) { point in
                    CheckpointRow(point: point) { capturing = point }
                }
            }
            if let problem = app.problem {
                Text(problem).foregroundStyle(.red).font(.callout)
            }
        }
        .navigationTitle(detail?.record.external_ref ?? "Record")
        .task {
            locator.start()
            detail = await app.record(recordID)
            await sendWaiting()
        }
        .refreshable {
            detail = await app.record(recordID)
            await sendWaiting()
        }
        .onDisappear { locator.stop() }
        .fullScreenCover(item: $capturing) { point in
            CaptureView(recordID: recordID, checkpoint: point) {
                capturing = nil
                Task {
                    detail = await app.record(recordID)
                    await sendWaiting()
                }
            }
        }
    }

    /// Online. The ticket hash is what the first offline photograph chains from.
    private func sealTicket() async {
        sealing = true
        defer { sealing = false }
        do {
            let hash = try await app.establishTicket(
                recordID: recordID, location: locator.lastFix)
            ticketNote = "Job ticket sealed. Offline photographs chain from \(hash.prefix(12))…"
            app.problem = nil
        } catch {
            app.problem = error.localizedDescription
        }
    }

    /// Reconnect. Opening the record is what sends a queue that was taken
    /// in airplane mode. A failure here leaves the files where they are.
    private func sendWaiting() async {
        let waiting = (try? await Outbox.shared.pending(recordID: recordID, limit: 64)) ?? []
        guard !waiting.isEmpty else { return }
        do {
            _ = try await app.flushOutbox(recordID: recordID)
            queueNote = "Photographs saved on this phone were sent to Shield."
            detail = await app.record(recordID)
        } catch {
            let count = waiting.count
            let noun = count == 1 ? "photograph is" : "photographs are"
            queueNote = "\(count) \(noun) saved on this phone. They will be sent when Shield is reachable."
        }
    }
}

struct CheckpointRow: View {
    let point: CheckpointWithPhoto
    let photograph: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(point.label).font(.headline)
                Spacer()
                if point.live_photo != nil {
                    Label("Recorded", systemImage: "checkmark.seal")
                        .font(.caption).foregroundStyle(.green)
                }
            }
            if let show = point.must_show {
                Text(show).font(.footnote).foregroundStyle(.secondary)
            }
            if let photo = point.live_photo {
                EvidenceSummary(photo: photo)
            }
            Button(point.live_photo == nil ? "Photograph" : "Retake",
                   systemImage: "camera", action: photograph)
                .buttonStyle(.bordered)
        }
        .padding(.vertical, 4)
    }
}

/// What the server recorded. Every field here was derived there.
struct EvidenceSummary: View {
    let photo: StoredPhoto

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            if let hash = photo.original_hash {
                Text(hash.prefix(16) + "…")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            if let tier = photo.attestation_tier {
                Text(tier.replacingOccurrences(of: "_", with: " "))
                    .font(.caption2).foregroundStyle(.secondary)
            }
            if let distance = photo.site_distance_m {
                Text("\(Int(distance)) m from site")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - capture

struct CaptureView: View {
    @EnvironmentObject var app: AppState
    @StateObject private var camera = CaptureModel()
    @StateObject private var locator = Locator()

    let recordID: String
    let checkpoint: CheckpointWithPhoto
    let done: () -> Void

    @State private var busy = false
    @State private var problem: String?
    @State private var stored: StoredPhoto?
    @State private var queuedHash: String?
    @State private var sent = false

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            if camera.isReady {
                CameraPreview(session: camera.session).ignoresSafeArea()
            }

            VStack {
                HStack {
                    Button("Cancel") { camera.stop(); done() }
                        .padding().foregroundStyle(.white)
                    Spacer()
                }
                Text(checkpoint.must_show ?? checkpoint.label)
                    .font(.callout).foregroundStyle(.white)
                    .padding(.horizontal, 18).padding(.vertical, 8)
                    .background(.black.opacity(0.55), in: Capsule())
                Spacer()

                if let stored {
                    ResultCard(photo: stored) { camera.stop(); done() }
                        .padding()
                } else if let queuedHash {
                    if let problem {
                        Text(problem)
                            .font(.callout).foregroundStyle(.white)
                            .multilineTextAlignment(.center)
                            .padding()
                            .background(.red.opacity(0.85),
                                        in: RoundedRectangle(cornerRadius: 10))
                            .padding(.horizontal)
                    }
                    QueuedCard(recordHash: queuedHash, sent: sent) {
                        camera.stop(); done()
                    }
                    .padding()
                } else {
                    if let problem {
                        Text(problem)
                            .font(.callout).foregroundStyle(.white)
                            .multilineTextAlignment(.center)
                            .padding()
                            .background(.red.opacity(0.85),
                                        in: RoundedRectangle(cornerRadius: 10))
                            .padding(.horizontal)
                    }
                    Button(action: shoot) {
                        Circle().fill(.white).frame(width: 74, height: 74)
                            .overlay(Circle().stroke(.black.opacity(0.2), lineWidth: 2))
                    }
                    .disabled(busy || !camera.isReady)
                    .padding(.bottom, 34)
                    .overlay {
                        if busy {
                            // The wait is real: photograph, then attest (a
                            // round trip to Apple), then upload. Saying which
                            // step is running beats a spinner that looks
                            // stuck.
                            Text("Sealing…").foregroundStyle(.white)
                                .padding(.bottom, 120)
                        }
                    }
                }
            }
        }
        .task {
            await camera.start()
            locator.start()
            if let why = camera.problem { problem = why }
        }
        .onDisappear { camera.stop(); locator.stop() }
    }

    private func shoot() {
        busy = true
        problem = nil
        Task {
            defer { busy = false }
            do {
                let frame = try await camera.capture()
                // A sealed ticket means this photograph is part of the
                // offline chain, even when the phone happens to have a
                // signal. Airplane mode then just delays the upload.
                // No ticket yet: the online path, which is also how the
                // install attests its key the first time.
                if (try? await Outbox.shared.ticketHash(recordID: recordID)) != nil {
                    queuedHash = try await app.storeOffline(
                        frame: frame, recordID: recordID,
                        checkpointID: checkpoint.id, location: locator.lastFix)
                    do {
                        _ = try await app.flushOutbox(recordID: recordID)
                        sent = true
                    } catch let error as ClientError {
                        sent = false
                        if case .transport = error {
                            // The file is on the phone. That is the point.
                        } else {
                            problem = error.localizedDescription
                        }
                    }
                } else {
                    stored = try await app.upload(
                        photo: frame.jpeg, record: recordID,
                        checkpoint: checkpoint.id, location: locator.current)
                }
            } catch {
                problem = error.localizedDescription
            }
        }
    }
}

/// A photograph that has not reached the server yet, or has just been sent
/// from the outbox. The record hash is the phone's own commitment. The
/// server recomputes it. This card does not invent a custody verdict.
struct QueuedCard: View {
    let recordHash: String
    let sent: Bool
    let done: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(sent ? "Sent" : "Saved on this phone",
                  systemImage: sent ? "paperplane.fill" : "iphone")
                .font(.headline)
            Text(sent
                 ? "Shield accepted this photograph from the queue on this phone."
                 : "There is no signal, or Shield could not be reached. This photograph stays on this phone and is sent when the record is opened again.")
                .font(.footnote).foregroundStyle(.secondary)
            Text(recordHash.prefix(16) + "…")
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
            Button("Done", action: done).buttonStyle(.borderedProminent)
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
    }
}

struct ResultCard: View {
    let photo: StoredPhoto
    let done: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Recorded", systemImage: "checkmark.seal.fill")
                .font(.headline).foregroundStyle(.green)
            Text("The server hashed these bytes and sealed them into the " +
                 "custody chain. Everything below was derived there.")
                .font(.footnote).foregroundStyle(.secondary)
            EvidenceSummary(photo: photo)
            Button("Done", action: done).buttonStyle(.borderedProminent)
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
    }
}

// MARK: - location

/// The device's claim about where it is. Sent as exactly that.
///
/// The server measures it against site coordinates the *record* carries, fixed
/// by the party relying on the evidence — so a device that lies about its
/// position moves further from the site, not closer.
@MainActor
final class Locator: NSObject, ObservableObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    @Published private(set) var current: (lat: Double, lng: Double)?
    @Published private(set) var lastFix: CLLocation?

    override init() {
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyBest
    }

    func start() {
        manager.requestWhenInUseAuthorization()
        manager.startUpdatingLocation()
    }

    func stop() { manager.stopUpdatingLocation() }

    nonisolated func locationManager(_ manager: CLLocationManager,
                                     didUpdateLocations locations: [CLLocation]) {
        guard let last = locations.last else { return }
        Task { @MainActor in
            current = (last.coordinate.latitude, last.coordinate.longitude)
            lastFix = last
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager,
                                     didFailWithError error: Error) {
        // Deliberately silent. A capture without a position is still a
        // capture; the server records the absence rather than refusing, and a
        // location error shouted over the viewfinder would push people to
        // stop photographing.
    }
}
