#!/bin/sh
# Device acceptance for the Shield Android app.
#
# This script does not talk to a phone. It prints the run a person does on
# a real Android device, and the labels the time rules produce for that run.
# CI compiles the app. CI does not install it, sign it, or take a photograph.
#
# What you need before you start
#   - A real phone with a locked bootloader and a hardware keystore. An
#     emulator has no Key Attestation chain this server will accept.
#   - The app installed as com.tradedeck.shield, signed with the certificate
#     named in ANDROID_SIGNING_CERT_SHA256.
#   - The server configured with ANDROID_ATTESTATION_ROOTS_PEM,
#     ANDROID_PACKAGE_NAME, and that signing-certificate digest.
#   - One record whose checkpoints are already locked.
#   - One photograph taken while online, so the install has an attested key.
#     Genesis refuses to start without that key.
#   - Play Integrity is optional. If Play returns a token, the app sends the
#     decoded body with the ticket. This server does not call Google, so that
#     body is stored as unverifiable, not as a pass. If Play returns nothing,
#     the field is omitted and the ticket stores absent, which is not a failure.
#
# The run
#   1. Online. Enter the address, credential, and record id. Tap
#      "Seal job ticket". The phone reads the wall clock, elapsedRealtime(),
#      and Settings.Global.BOOT_COUNT, and signs them with the keystore key.
#   2. Turn on airplane mode. Confirm the phone cannot reach the server.
#   3. Take 5 photographs. Each needs the checkpoint id filled in.
#      They stay in the on-phone outbox. Nothing is uploaded.
#   4. Reboot the phone. Unlock it once. BOOT_COUNT has increased.
#   5. Still in airplane mode, take 1 more photograph.
#   6. Turn airplane mode off and open the app. Tap "Send queue".
#      The queue goes up in batches of at most 8. This run is 6 photographs,
#      so it is one batch.
#
# What the receipt should say
#   - 5 photographs CONSISTENT. They are the five taken before the reboot.
#     They share the ticket's boot count, and their wall clock is within
#     2 minutes of ticket time plus the monotonic interval.
#   - 1 photograph UNVERIFIED TIME. That is the one after the reboot. The
#     boot count changed, so the monotonic interval is not a duration anymore.
#     UNVERIFIED TIME is not a forgery and it is not tampered.
#   - A receipt whose signature checks.
#   - A timestamp token when DigiCert or Sectigo answered. If neither
#     answered, the seal card says "receipt present, timestamp absent".
#     That is not FORGED.
#   - Flags, if any (screen recording, a debugger, a mock location, a
#     best-effort root note), are words beside the label. They do not
#     change it.
#
# Then the clock
#   7. Set the phone's wall clock 3 minutes ahead. Take 1 photograph with
#      no signal, then tap "Send queue".
#   8. That photograph is DEVICE CLOCK MISMATCH. The wall clock moved and
#      elapsedRealtime did not. Three minutes is past the two-minute limit.
#      The signature can still check. The label is the clock, not FORGED
#      and not TAMPERED.
#
echo "Shield Android device acceptance — instructions only."
echo "This host did not run them. Read the comments in this file and do the run on a phone."
exit 0
