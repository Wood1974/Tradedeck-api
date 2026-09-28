# Shield Capture — the iOS client

The app that makes the gate reachable. Everything else in Shield refuses a
photograph that cannot prove it came from a camera on a genuine device; this is
the only thing that can produce that proof.

## What you are getting, and what you are not

**This code has never been compiled.** There is no Swift toolchain and no Xcode
in the environment it was written in, so every line here is unverified against
a compiler, a device, or Apple's real App Attest service. That is not a
disclaimer bolted on at the end — it is the reason the server half was built
and break-tested first. On the server, `app_attest.py` has sixteen checks and a
test that fails for each one removed. Here there is nothing of the kind, and
saying otherwise would be the exact drift this project's CLAUDE.md warns about.

Treat it as a specification you can build, not as a shipped app. Expect to fix
compile errors. The first real device run is the first real test.

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
the attestation, because the attestation has to commit to the bytes.

1. `POST /shield/v2/records/<id>/capture-challenge` → a single-use nonce.
2. Take the photograph. `AVCapturePhotoOutput`, in-process, bytes never
   written to a shared container.
3. `clientDataHash = SHA256( challenge_utf8 ‖ SHA256(photo bytes) )`.
4. `DCAppAttestService.generateKey` then `attestKey(keyId, clientDataHash:)`.
5. `POST /shield/v2/records/<id>/photos` — multipart: the file, the
   `checkpoint_id`, the base64 attestation, the base64 `keyId`, the challenge
   verbatim, `attestation_platform=ios`.

Both halves of step 3 are load-bearing and neither is optional. Without the
challenge, one attestation covers every upload forever. Without the photo
digest, the attestation says a real app on real silicon was running when the
nonce was issued and nothing whatever about the file in the same request — buy
an iPhone, run this app, attest honestly, upload a stock photograph of
somebody else's finished roof.

The app sends **no hash, no verdict, no EXIF flag, no distance**. Every one of
those is derived on the server from the bytes that arrived. The client's job is
to produce bytes and prove where they came from.

## Attestation cost — an open question, not a footnote

`attestKey` may be called **once per key**, and it makes a network round trip to
Apple, which rate-limits it. This client generates a fresh key per capture,
which is correct and works, and which will run into that limit for a crew
shooting fifty photographs in an afternoon. The scaling path is Apple's
intended one: attest a key once, then sign each later capture with
`generateAssertion` and verify the assertion server-side against the stored
public key and a monotonic counter.

**Assertion verification is not built** — `app_attest.py` verifies attestations
only. Until it is, treat the rate limit as a real constraint on volume and find
out where it bites before promising anyone otherwise.

## Building it

Xcode 15+, iOS 17+. A real device: `DCAppAttestService.isSupported` is false on
the simulator, and this app deliberately has no fallback for that — it shows
why capture is unavailable instead.

1. New iOS App target, bundle id matching the server's `APP_ATTEST_APP_ID`
   (which is `TEAMID.your.bundle.id`).
2. Add the **App Attest** capability. Without it `generateKey` fails.
3. Add these sources, and `Info.plist` from `Info.plist.template`.
4. `NSCameraUsageDescription` is required. **`NSPhotoLibraryUsageDescription`
   must stay absent** — see above.

On the server: `APPLE_APP_ATTEST_ROOT_PEM` and `APP_ATTEST_APP_ID` must both be
set, or every capture is refused. Use `APP_ATTEST_ALLOW_DEVELOPMENT=1` while
building against a development provisioning profile, and never in production —
a development attestation says nothing about a production device.

## Files

| File | What it does |
|---|---|
| `ShieldApp.swift` | Entry point and navigation |
| `Attestor.swift` | `DCAppAttestService` — the only source of proof |
| `ShieldClient.swift` | The API. Sends bytes and attestations, derives nothing |
| `Capture.swift` | `AVCapturePhotoOutput`. The only thing that produces bytes |
| `Models.swift` | What the API returns |
| `Screens.swift` | Connect, records, checkpoints, capture, result |
| `Info.plist.template` | Camera yes, photo library deliberately absent |
