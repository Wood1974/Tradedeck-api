//  Attestor.swift
//
//  The only thing in this app that produces proof. Everything else moves bytes
//  around; this asks the Secure Enclave to sign for them.
//
//  What an attestation from here is allowed to mean, exactly: a genuine
//  instance of this app, on genuine Apple hardware, holding a key generated in
//  the Secure Enclave, committing to one specific photograph and one
//  server-issued challenge.
//
//  What it is NOT allowed to mean, however often it gets written down that
//  way: that the device is not jailbroken. Apple does not expose jailbreak
//  state through App Attest. The server's `attestation.py` says the same thing
//  in its own words, and the two must not drift apart.

import CryptoKit
import DeviceCheck
import Foundation

enum AttestError: LocalizedError {
    case unsupported
    case keyGeneration(String)
    case attestation(String)

    var errorDescription: String? {
        switch self {
        case .unsupported:
            // Said plainly rather than as "an error occurred". The simulator
            // is where this is hit, and a developer who does not know App
            // Attest needs a device will otherwise spend an hour on it.
            return """
                This device cannot attest a capture. App Attest needs a real \
                iPhone or iPad — it is unavailable on the Simulator, so \
                Shield cannot record a photograph from here.
                """
        case .keyGeneration(let why):
            return """
                Could not create a Secure Enclave key: \(why)

                If this is a fresh build, check that the App Attest capability \
                is enabled on the target.
                """
        case .attestation(let why):
            return "The device could not attest this capture: \(why)"
        }
    }
}

/// What one capture carries to the server: either the key's attestation (its
/// first capture) or an assertion from a key the server already holds.
enum Proof {
    case attestation(keyID: String, blob: Data)
    case assertion(keyID: String, blob: Data)

    var keyID: String {
        switch self {
        case .attestation(let keyID, _), .assertion(let keyID, _): return keyID
        }
    }
}

enum Attestor {

    static var isSupported: Bool { DCAppAttestService.shared.isSupported }

    /// The key id the server has on file for this install, if any.
    ///
    /// UserDefaults rather than the Keychain on purpose. The id is not a
    /// secret -- the private key never leaves the Secure Enclave -- and an
    /// App Attest key does not survive the app being deleted, so storage that
    /// is deleted with the app is the storage whose lifetime matches the key's.
    /// A Keychain entry would outlive the key and point at nothing.
    private static let keyDefault = "shield.appattest.keyID"

    static var registeredKeyID: String? {
        UserDefaults.standard.string(forKey: keyDefault)
    }

    /// Keep a key id, once the server has said it stored the key.
    static func keep(_ keyID: String) {
        UserDefaults.standard.set(keyID, forKey: keyDefault)
    }

    /// Drop the key id: on sign-out, and whenever the server asks for a fresh
    /// attestation. The next capture attests a new key.
    static func forget() {
        UserDefaults.standard.removeObject(forKey: keyDefault)
    }

    /// The hash is the whole contract with the server, so it is written here
    /// once and nowhere else, and attestations and assertions both use it:
    ///
    ///     clientDataHash = SHA256( challenge_utf8 ‖ SHA256(photo bytes) )
    ///
    /// Both halves matter. Drop the challenge and one proof covers every
    /// upload forever. Drop the photo digest — the easy mistake, because
    /// `clientDataHash` is 32 bytes we choose and hashing the challenge alone
    /// looks complete — and the proof shows a genuine app was running when
    /// the nonce was issued while saying nothing at all about the file in the
    /// same request.
    static func clientDataHash(photo: Data, challenge: String) -> Data {
        var clientData = Data(challenge.utf8)
        clientData.append(contentsOf: SHA256.hash(data: photo))
        return Data(SHA256.hash(data: clientData))
    }

    /// Prove one photograph against one challenge.
    ///
    /// With a key on file, an assertion: one Secure Enclave signature, no
    /// round trip to Apple. Without one — first capture, a fresh install, or
    /// the server asked for it — a new key, attested. `attestKey` may be
    /// called once per key and Apple rate-limits it, which is why it is the
    /// fallback and not the rule.
    static func prove(photo: Data, challenge: String) async throws -> Proof {
        guard DCAppAttestService.shared.isSupported else {
            throw AttestError.unsupported
        }
        let hash = clientDataHash(photo: photo, challenge: challenge)
        if let keyID = registeredKeyID {
            do {
                return .assertion(keyID: keyID,
                                  blob: try await signAssertion(keyID: keyID, hash: hash))
            } catch let error as DCError where error.code == .invalidKey {
                // The key is gone: restored from a backup onto another device,
                // or invalidated by the system. Attest a new one.
                forget()
            }
        }
        return try await attest(hash: hash)
    }

    private static func signAssertion(keyID: String, hash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation {
            (cont: CheckedContinuation<Data, Error>) in
            DCAppAttestService.shared.generateAssertion(
                keyID, clientDataHash: hash) { blob, error in
                if let blob {
                    cont.resume(returning: blob)
                } else if let error {
                    cont.resume(throwing: error)
                } else {
                    cont.resume(throwing: AttestError.attestation(
                        "no assertion was returned"))
                }
            }
        }
    }

    private static func attest(hash: Data) async throws -> Proof {
        let service = DCAppAttestService.shared

        let keyID: String = try await withCheckedThrowingContinuation {
            (cont: CheckedContinuation<String, Error>) in
            service.generateKey { keyID, error in
                if let keyID {
                    cont.resume(returning: keyID)
                } else {
                    cont.resume(throwing: AttestError.keyGeneration(
                        error?.localizedDescription ?? "no key was returned"))
                }
            }
        }

        let blob: Data = try await withCheckedThrowingContinuation {
            (cont: CheckedContinuation<Data, Error>) in
            service.attestKey(keyID, clientDataHash: hash) { blob, error in
                if let blob {
                    cont.resume(returning: blob)
                } else {
                    cont.resume(throwing: AttestError.attestation(
                        error?.localizedDescription ?? "no attestation was returned"))
                }
            }
        }

        return .attestation(keyID: keyID, blob: blob)
    }
}
