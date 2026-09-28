//  ShieldApp.swift
//
//  Entry point and the small amount of state the app keeps.
//
//  The credential lives in the Keychain, not in UserDefaults: a token in
//  UserDefaults is in a plist inside the app container, readable from a
//  backup. Nothing else is persisted — no photographs, no hashes, no record
//  cache. The evidence lives on the server, and a copy on the phone would be
//  a second version of the truth that nobody is chaining.

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

    func resume() async {
        guard client == nil,
              let saved = Keychain.read(),
              let url = URL(string: saved.address) else { return }
        await connect(saved.address, saved.token, base: url, quiet: true)
    }

    func connect(_ address: String, _ token: String) async {
        let text = address.hasPrefix("http") ? address : "https://\(address)"
        guard let url = URL(string: text.hasSuffix("/") ? text : text + "/") else {
            problem = ClientError.badURL.errorDescription
            return
        }
        await connect(text, token, base: url, quiet: false)
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
            Keychain.clear()
        }
    }

    func signOut() {
        Keychain.clear()
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
        guard let client else { throw ClientError.badURL }
        return try await client.upload(photo: photo, to: record,
                                       checkpoint: checkpoint,
                                       location: location)
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
