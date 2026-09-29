# Shield Capture — the Android client (not written yet)

The server half is built: `shield/android_attest.py` verifies Android Key
Attestation, and `tenant_api.py` accepts it. This is the contract an Android
app has to meet. There is no app code here yet.

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
