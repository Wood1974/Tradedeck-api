# Shield Capture — the iOS client

The app that makes the gate reachable. Everything else in Shield refuses a
photograph that cannot prove it came from a camera on a genuine device; this is
the only thing that can produce that proof.

## What you are getting, and what you are not

**This code has never run on a device.** It was written somewhere with no
Swift toolchain and no Xcode. Since the `Shield iOS build` workflow was added,
CI compiles it for the iPhone SDK on every change under `shield/ios/`, so
"does it compile" now has an answer. "Does it work" does not: nothing here has
been checked against a device or Apple's real App Attest service. That is not a
disclaimer bolted on at the end — it is the reason the server half was built
and break-tested first. On the server, `app_attest.py` has sixteen checks and a
test that fails for each one removed. Here there is nothing of the kind, and
saying otherwise would be the exact drift this project's CLAUDE.md warns about.

Treat it as a specification you can build, not as a shipped app. The first
real device run is the first real test. `device_acceptance.sh` is that run
written down: genesis while online, airplane mode, 5 photos, reboot, 1
photo, reconnect, then a wall clock set 3 minutes ahead. The script prints
the steps. It does not perform them, and CI does not either. CI compiles
the sources for the iPhone SDK and stops there.

Specifically unverified: the exact `DCAppAttestService` error cases, the CBOR
shape Apple returns (the server parses it, so a mismatch shows up as a refusal
with a readable reason), AVFoundation orientation and EXIF handling on real
hardware, and whether Apple's attestation rate limit is tolerable at the volume
a crew actually shoots — see **Attestation cost**, which is a real open question
rather than a detail.

## The one rule the architecture enforces

**There is no path from the photo library into Shield, and there cannot be.**

Not a disabled button, not a check in code somebody can delete: `Info.plist`
carries no `NSPhotoLibraryUsageDescription`, so iOS itself refuses to hand this
app a library image. A file chosen from storage cannot be attested, an
unattestable capture is refused by the server, and a control that looked
available and always failed would read as a bug rather than as the decision it
is. `PHPicker`, `UIImagePickerController` and `UTType.image` document pickers
are absent for the same reason — `Capture.swift` drives `AVCapturePhotoOutput`
directly and nothing else ever produces bytes.

## The capture sequence

Order matters, and it is not the obvious one — the photograph comes *before*
the proof, because the proof has to commit to the bytes.

1. `POST /shield/v2/records/<id>/capture-challenge` → a single-use nonce.
2. Take the photograph. `AVCapturePhotoOutput`, in-process, bytes never
   written to a shared container.
3. `clientDataHash = SHA256( challenge_utf8 ‖ SHA256(photo bytes) )`.
4. Prove it:
   - **First capture on this install** (no key on file):
     `DCAppAttestService.generateKey`, then `attestKey(keyId, clientDataHash:)`.
   - **Every capture after that:** `generateAssertion(keyId, clientDataHash:)`
     with the key the server stored.
5. `POST /shield/v2/records/<id>/photos` — multipart: the file, the
   `checkpoint_id`, the base64 `keyId`, the challenge verbatim,
   `attestation_platform=ios`, and **one** of `attestation` (step 4, first
   case) or `assertion` (second case).

Both halves of step 3 are load-bearing and neither is optional. Without the
challenge, one proof covers every upload forever. Without the photo digest,
the proof says a real app on real silicon was running when the nonce was
issued and nothing whatever about the file in the same request — buy an
iPhone, run this app, attest honestly, upload a stock photograph of somebody
else's finished roof.

The app sends **no hash, no verdict, no EXIF flag, no distance**. Every one of
those is derived on the server from the bytes that arrived. The client's job is
to produce bytes and prove where they came from.

## Attest once, assert after

`attestKey` may be called **once per key**, makes a network round trip to Apple,
and is rate-limited. So it is used once: the first capture on an install
attests a key, the server verifies the chain to Apple's root and stores the
key's public half in `shield.attested_keys`, and the response says
`attestation_key_registered: true`. Only then does the app keep the key id.

Every later capture is a `generateAssertion` signature — Secure Enclave only,
no call to Apple. The server checks it against the stored key, requires the
counter to go up, and advances the stored counter with a compare-and-set, so
two uploads racing on one assertion cannot both be recorded. A key is bound to
the tenant and credential that attested it.

When the server does not recognise the key (unknown, revoked, or attested
under a different sign-in) it refuses with `reattest: true`. The app forgets
the key and tries once more with a fresh challenge and a freshly attested key.
Any other refusal is final. Signing out forgets the key too.

Unverified until a device run: that Apple's assertion signature is over
`nonce` exactly as `app_attest.verify_assertion` checks it (it follows Apple's
documentation and `node-app-attest`), and how Apple encodes the newer
`validationCategory` in the assertion's extensions. The server enforces the
category when it can read one and does not require it, because older iOS
versions do not send it.

## Genesis (job ticket)

While the phone still has a signal, and after the record's checkpoints are
locked, it asks for a job ticket and countersigns it with the install key
already on file. `ShieldClient.establishTicket` is that call. It has been
compiled in CI and has not been run on a device. The contract is:

1. `POST /shield/v2/records/<id>/genesis` with JSON `{ "platform": "ios" }`.
   The response is the ticket, `ticket_hash`, and `server_signature`. Nothing
   is stored yet.
2. Read the phone clocks now (`wall_time_ms`, `monotonic_ms`, and
   `boot_id` or the boot count). Sign with `generateAssertion`.
   `clientData` is the UTF-8 bytes of `shield-genesis-v1` followed by
   SHA-256 of the raw 32-byte ticket hash concatenated with the canonical
   JSON of that clock (sorted keys, tight separators). Not the hex text,
   and not the bare ticket hash. Pass `SHA256(clientData)` to
   `generateAssertion`, the same way a later capture passes
   `SHA256(challenge || SHA256(photo))`. The server stores this clock.
   A later batch cannot replace it.
3. `POST` the same path again with `platform`, `ticket`, `ticket_clock`,
   `server_signature`, `assertion` (base64), and `attestation_key_id`
   (base64). A missing or invalid signature, or a clock that is not the
   one that was signed, is refused and nothing is stored.
4. Keep `ticket_hash`. The first offline capture record uses it as `ticket_id`
   and as `prev_hash`.

iOS has no Play Integrity API. App Attest does not report whether the device
is jailbroken. The ticket records that absence; it does not record a pass.

## Building it

The Xcode project is generated from `project.yml` by
[XcodeGen](https://github.com/yonaskolb/XcodeGen), rather than committed as a
`.pbxproj` nobody has opened. On a Mac with Xcode 16 or newer:

1. `brew install xcodegen`
2. Create `shield/ios/Local.xcconfig` (gitignored) with your team and bundle id:

       DEVELOPMENT_TEAM = ABCDE12345
       PRODUCT_BUNDLE_IDENTIFIER = com.yourcompany.shield

3. In your Apple Developer account, enable **App Attest** for that bundle id.
4. `cd shield/ios && xcodegen generate && open Shield.xcodeproj`
5. Pick a real iPhone as the destination. `DCAppAttestService.isSupported` is
   false on the Simulator, and this app deliberately has no fallback for that —
   it shows why capture is unavailable instead.

Debug builds attest in Apple's **development** environment
(`Shield-Development.entitlements`), Release builds in **production**
(`Shield.entitlements`).

On the server:

- `APP_ATTEST_APP_ID` = `<TEAM_ID>.<bundle id>`, the same values as step 2.
- `APPLE_APP_ATTEST_ROOT_PEM` = Apple's App Attest root CA, fetched from Apple
  and pinned. With either missing, every capture is refused.
- `APP_ATTEST_ALLOW_DEVELOPMENT=1` only on a deployment you test Debug builds
  against, and never in production — a development attestation says nothing
  about a production device.
- Apply `supabase/migrations/20260929000000_shield_attested_keys.sql`, or every
  first capture's key fails to register and the app attests on every shot.

`Info.plist.template` is used as-is, merged with the keys Xcode generates.
`NSCameraUsageDescription` is required. **`NSPhotoLibraryUsageDescription`
must stay absent** — see above.

## Files

| File | What it does |
|---|---|
| `ShieldApp.swift` | Entry point and navigation |
| `Attestor.swift` | `DCAppAttestService` — attests a key once, then asserts; the only source of proof |
| `ShieldClient.swift` | The API. Sends bytes and attestations, derives nothing |
| `Capture.swift` | `AVCapturePhotoOutput`. The only thing that produces bytes. SHA-256 is updated in 64 KiB chunks |
| `Time.swift` | Wall clock, `mach_continuous_time` via `mach_timebase_info`, `kern.bootsessionuuid`, GNSS time, simulated-location bit |
| `Sensors.swift` | IMU and barometer snapshot hash when a sample exists; depth hash when the photo has depth |
| `Flags.swift` | Screen capture, debugger, mock location. Jailbreak is a best-effort note and does not change a label |
| `Outbox.swift` | One file per capture, append-only manifest, Data Protection, upload in batches of 8 |
| `CanonicalJSON.swift` | Sorted keys, tight separators, whole numbers, Python's `\u` escapes |
| `CaptureRecord.swift` | Canonical capture-record bytes. The strings are checked against `capture_record.py` |
| `Models.swift` | What the API returns |
| `Screens.swift` | Connect, records, checkpoints, capture, result |
| `Info.plist.template` | Camera yes, photo library deliberately absent |
| `Shield*.entitlements` | App Attest environment: development (Debug), production (Release) |
| `../project.yml` | XcodeGen spec for the Xcode project |
| `../Config.xcconfig` | Bundle id and team; override in `Local.xcconfig` |
