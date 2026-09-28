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

struct Attestation {
    let keyID: String       // Apple's own base64 key identifier, passed through
    let blob: Data          // the CBOR attestation object
}

enum Attestor {

    static var isSupported: Bool { DCAppAttestService.shared.isSupported }

    /// Attest one photograph against one challenge.
    ///
    /// The hash is the whole contract with the server, so it is written here
    /// once and nowhere else:
    ///
    ///     clientDataHash = SHA256( challenge_utf8 ‖ SHA256(photo bytes) )
    ///
    /// Both halves matter. Drop the challenge and one attestation covers every
    /// upload forever. Drop the photo digest — the easy mistake, because
    /// `clientDataHash` is 32 bytes we choose and hashing the challenge alone
    /// looks complete — and the attestation proves a genuine app was running
    /// when the nonce was issued while saying nothing at all about the file in
    /// the same request.
    ///
    /// A fresh key per capture, deliberately: `attestKey` may be called once
    /// per key. See the Attestation cost section in the README — this is a
    /// real constraint on volume, not a detail.
    static func attest(photo: Data, challenge: String) async throws -> Attestation {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw AttestError.unsupported }

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

        var clientData = Data(challenge.utf8)
        clientData.append(contentsOf: SHA256.hash(data: photo))
        let clientDataHash = Data(SHA256.hash(data: clientData))

        let blob: Data = try await withCheckedThrowingContinuation {
            (cont: CheckedContinuation<Data, Error>) in
            service.attestKey(keyID, clientDataHash: clientDataHash) { blob, error in
                if let blob {
                    cont.resume(returning: blob)
                } else {
                    cont.resume(throwing: AttestError.attestation(
                        error?.localizedDescription ?? "no attestation was returned"))
                }
            }
        }

        return Attestation(keyID: keyID, blob: blob)
    }
}
