# Shield Capture — the Android client

The server half is built: `shield/android_attest.py` verifies Android Key
Attestation, and `tenant_api.py` accepts it. The app under `app/` is that
contract, written in Kotlin.

**This code has not been run on a device.** `./gradlew :app:assembleDebug`
was run once on Linux, with the Android SDK, and it produced a debug APK.
That compile did not install the app, talk to a keystore, or take a
photograph. The GitHub Actions workflow compiles the same APK again. It
does not install it either. `device_acceptance.sh` prints the run a person
does on a phone. The script does not perform it.

The package name is `com.tradedeck.shield`. `ANDROID_PACKAGE_NAME` and
`ANDROID_SIGNING_CERT_SHA256` have to name this app and the certificate
that actually signs it. A debug build's certificate is not the Play signing
key, and the server refuses a certificate it was not given.

## The one rule

Same as iOS: **no path from storage into Shield.** No `READ_MEDIA_IMAGES` or
`READ_EXTERNAL_STORAGE` permission, no photo picker, no `ACTION_GET_CONTENT`,
no share-target intent filter for images. CameraX (or Camera2) in-process is
the only thing that produces bytes, and the bytes are never written to shared
storage before upload.

## The capture sequence

1. `POST /shield/v2/records/<id>/capture-challenge` → a single-use nonce.
2. Take the photograph (CameraX `ImageCapture`, in memory).
3. `clientData = challenge_utf8 ‖ SHA256(photo bytes)`.
4. Prove it:
   - **First capture on this install** (no key on file): generate an EC P-256
     key in the Android Keystore with
     `KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)`,
     `.setDigests(DIGEST_SHA256)`,
     `.setAttestationChallenge(SHA256(clientData))`, and
     `.setIsStrongBoxBacked(true)` where available (fall back to the TEE on
     `StrongBoxUnavailableException`). Read
     `keyStore.getCertificateChain(alias)`.
   - **Every capture after that:** sign `clientData` with the stored key using
     `Signature.getInstance("SHA256withECDSA")`.
5. `POST /shield/v2/records/<id>/photos` — multipart: the file,
   `checkpoint_id`, `attestation_challenge` (the challenge verbatim),
   `attestation_platform=android`, and **one** of:
   - `attestation`: the certificate chain, leaf first, each certificate
     base64 DER, joined with commas; or
   - `assertion`: the base64 DER signature, plus `attestation_key_id` =
     base64 SHA256 of the key's uncompressed public point (65 bytes, `0x04 ‖
     X ‖ Y`).

Keep the key alias only when the response says
`attestation_key_registered: true`. On a `422` with `reattest: true`, delete
the key and retry once with a fresh challenge and a fresh attestation. Delete
the key on sign-out.

## What the server checks

Chain to a configured Google root; no revoked certificate; the attestation
extension on the leaf only; TEE or StrongBox; the challenge equals
`SHA256(clientData)`; the key was generated (not imported), is EC and can
sign; verified boot and a locked bootloader; the package name and a signing
certificate digest match the configuration. StrongBox is recorded at the
`hardware_attested` tier, the TEE at `device_attested`. Both are accepted.

A phone with an unlocked bootloader, a custom ROM, or no secure hardware is
refused. So is a debug build, unless its signing certificate is configured.

## Server configuration

- `ANDROID_ATTESTATION_ROOTS_PEM`: Google's hardware attestation roots, as a
  PEM bundle, fetched from Google's documentation and pinned. Never committed.
- `ANDROID_PACKAGE_NAME`: the app's package name.
- `ANDROID_SIGNING_CERT_SHA256`: the SHA-256 of the app's signing certificate,
  hex (colons allowed; comma-separate several to rotate). With Play App
  Signing this is the **app signing key** from the Play Console, not your
  upload key.
- `ANDROID_ATTESTATION_STATUS_URL`: defaults to Google's revocation list.

## Genesis (job ticket)

While the phone still has a signal, and after the record's checkpoints are
locked, it asks for a job ticket and countersigns it with the install key
already in `shield.attested_keys`. `ShieldClient.establishTicket` is that
call. It has been compiled when the Android workflow runs, and it has not
been run on a device. The contract is:

1. `POST /shield/v2/records/<id>/genesis` with JSON `{ "platform": "android" }`.
   The response is the ticket, `ticket_hash`, and `server_signature`. Nothing
   is stored yet.
2. Read the phone clocks now (`wall_time_ms`, `monotonic_ms`, and
   `boot_id` or `BOOT_COUNT`). `clientData` is the UTF-8 bytes of
   `shield-genesis-v1` followed by SHA-256 of the raw 32-byte ticket hash
   concatenated with the canonical JSON of that clock (sorted keys, tight
   separators). Not the hex text, and not the bare ticket hash.
   `Signature.getInstance("SHA256withECDSA")` over that `clientData`, the same
   key the capture path already uses. Do not pre-hash: the server hashes once,
   inside ECDSA. The server stores this clock. A later batch cannot replace it.
3. `POST` the same path again with `platform`, `ticket`, `ticket_clock`,
   `server_signature`, `assertion` (base64 DER signature), and
   `attestation_key_id`. A missing or invalid signature, or a clock that
   is not the one that was signed, is refused and nothing is stored.
4. Keep `ticket_hash`. The first offline capture record uses it as `ticket_id`
   and as `prev_hash`.

Optional `play_integrity` on that second call is the decoded token body, one
verdict for the job, not one per photo. This server release does not call
Google to verify it, so a body that arrives is stored as unverifiable, not as
a pass. Omitting it stores **absent**, which is not a failure. iOS has no
Play Integrity call. App Attest does not report jailbreak.
