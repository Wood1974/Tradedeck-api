//  ShieldApp.swift
//
//  Entry point and the small amount of state the app keeps.
//
//  The credential lives in the Keychain, not in UserDefaults: a token in
//  UserDefaults is in a plist inside the app container, readable from a
//  backup. The outbox is the other thing kept on the phone: photographs
//  taken with no signal, protected until the first unlock after boot, and
//  deleted from the queue only after the server has accepted them. The
//  server still hashes those bytes again. The phone is not a second chain
//  of custody.

import CoreLocation
import Security
import SwiftUI

@main
struct ShieldApp: App {
    @StateObject private var app = AppState()

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                if app.client == nil {
                    ConnectView()
                } else {
                    RecordsView()
                }
            }
            .environmentObject(app)
            .task { await app.resume() }
        }
    }
}

@MainActor
final class AppState: ObservableObject {
    @Published private(set) var client: ShieldClient?
    @Published private(set) var records: [Record] = []
    @Published private(set) var tenantName: String?
    @Published var problem: String?

    // MARK: - session

    /// One place where an address becomes a base URL, used by both entry
    /// points.
    ///
    /// It was two, and they disagreed. `connect` appended a trailing slash
    /// and stored the address without one; `resume` used the stored form as
    /// the base directly. Relative resolution against a base with no trailing
    /// slash drops its last path component, so a service at
    /// `https://host/api` was reached at `https://host/api/shield/v2/...`
    /// when you signed in and `https://host/shield/v2/...` after a relaunch.
    /// The app would work, then quietly talk to a different place — visible
    /// only on a path-prefixed deployment, and only after the first restart.
    static func baseURL(from address: String) -> URL? {
        let text = address.hasPrefix("http") ? address : "https://\(address)"
        return URL(string: text.hasSuffix("/") ? text : text + "/")
    }

    func resume() async {
        guard client == nil, let saved = Keychain.read(),
              let url = Self.baseURL(from: saved.address) else { return }
        await connect(saved.address, saved.token, base: url, quiet: true)
    }

    func connect(_ address: String, _ token: String) async {
        guard let url = Self.baseURL(from: address) else {
            problem = ClientError.badURL.errorDescription
            return
        }
        await connect(address, token, base: url, quiet: false)
    }

    private func connect(_ address: String, _ token: String,
                         base: URL, quiet: Bool) async {
        let candidate = ShieldClient(base: base, token: token)
        do {
            let who = try await candidate.whoami()
            client = candidate
            tenantName = who.tenant.name
            problem = nil
            Keychain.save(address: address, token: token)
            await loadRecords()
        } catch {
            // A failed resume is silent: a token that expired overnight should
            // show the connect form, not an error the person did nothing to
            // cause.
            if !quiet { problem = error.localizedDescription }

            // Only a credential the server actually rejected is discarded.
            // Clearing on any failure means opening the app somewhere with no
            // signal wipes the stored key — and re-entering an API key on a
            // phone, on a roof, is the moment somebody stops photographing.
            if case ClientError.http(let code, _) = error,
               code == 401 || code == 403 {
                Keychain.clear()
            }
        }
    }

    func signOut() {
        Keychain.clear()
        // The key was attested under this credential, and the server will
        // not accept it from another. The next sign-in attests its own.
        Attestor.forget()
        client = nil
        records = []
        tenantName = nil
    }

    // MARK: - work

    func loadRecords() async {
        guard let client else { return }
        do {
            records = try await client.records()
            problem = nil
        } catch {
            problem = error.localizedDescription
        }
    }

    func record(_ id: String) async -> RecordDetail? {
        guard let client else { return nil }
        do {
            problem = nil
            return try await client.record(id)
        } catch {
            problem = error.localizedDescription
            return nil
        }
    }

    func upload(photo: Data, record: String, checkpoint: String,
                location: (lat: Double, lng: Double)?) async throws -> StoredPhoto {
        guard let client else { throw ClientError.notConnected }
        return try await client.upload(photo: photo, to: record,
                                       checkpoint: checkpoint,
                                       location: location)
    }

    /// While the phone still has a signal. The ticket hash is what the
    /// first offline photograph chains from.
    func establishTicket(recordID: String, location: CLLocation?) async throws -> String {
        guard let client else { throw ClientError.notConnected }
        return try await client.establishTicket(recordID: recordID, location: location)
    }

    /// Airplane mode. The photograph stays on this phone until flushOutbox.
    func storeOffline(frame: CapturedFrame, recordID: String, checkpointID: String,
                      location: CLLocation?) async throws -> String {
        try await OfflineCapture.store(
            frame: frame, recordID: recordID, checkpointID: checkpointID,
            location: location)
    }

    /// Back online. Sends the queue in batches of 8.
    func flushOutbox(recordID: String) async throws -> [String: Any]? {
        guard let client else { throw ClientError.notConnected }
        return try await Outbox.shared.flush(client: client, recordID: recordID)
    }
}

// MARK: - keychain

enum Keychain {
    private static let account = "shield.credential"

    static func save(address: String, token: String) {
        guard let data = try? JSONEncoder().encode(
            ["address": address, "token": token]) else { return }
        clear()
        SecItemAdd([
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: account,
            kSecValueData: data,
            // Never leaves this device and is unreadable until it is unlocked
            // once. A crew phone that is lost and locked does not carry a
            // usable credential off site.
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)
    }

    static func read() -> (address: String, token: String)? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: account,
            kSecReturnData: true,
        ] as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data,
              let saved = try? JSONDecoder().decode([String: String].self, from: data),
              let address = saved["address"], let token = saved["token"]
        else { return nil }
        return (address, token)
    }

    static func clear() {
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: account,
        ] as CFDictionary)
    }
}
