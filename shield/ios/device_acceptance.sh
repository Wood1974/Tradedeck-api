#!/bin/sh
# Device acceptance for the Shield iOS outbox.
#
# This script does not talk to a phone. It prints the run a person does on
# a real iPhone, and the labels the time rules produce for that run. CI
# compiles the app. CI does not install it, sign it, or take a photograph.
#
# What you need before you start
#   - A real iPhone. App Attest does not run in the Simulator.
#   - The app installed from a Debug or Release build with App Attest enabled.
#   - The server configured with APP_ATTEST_APP_ID and the Apple root.
#   - One record whose checkpoints are already locked.
#   - One photograph taken while online, so the install has an attested key.
#     Genesis refuses to start without that key.
#
# The run
#   1. Online. Open the record and tap "Seal job ticket".
#      The phone reads wall time, mach_continuous_time (converted with
#      mach_timebase_info), and kern.bootsessionuuid, and signs them.
#   2. Turn on airplane mode. Confirm the phone cannot reach the server.
#   3. Take 5 photographs, each for a checkpoint on that record.
#      They stay in the on-phone outbox. Nothing is uploaded.
#   4. Reboot the phone. Unlock it once, so the outbox (protected until
#      first unlock) can be read again.
#   5. Still in airplane mode, take 1 more photograph.
#   6. Turn airplane mode off and open the record again. That is what sends
#      the queue, in batches of at most 8. This run is 6 photographs, so
#      it is one batch.
#
# What the receipt should say
#   - 5 photographs time-consistent (the word on the seal is CONSISTENT).
#     They are the five taken before the reboot. They share the ticket's
#     boot id, and their wall clock is within 2 minutes of ticket time
#     plus the monotonic interval. The time rules do not drop one of
#     those five. A count of 4 would mean one of them was labeled for a
#     different reason.
#   - 1 photograph UNVERIFIED TIME. That is the one after the reboot. The
#     boot id changed, so the monotonic interval is not a duration anymore.
#     UNVERIFIED TIME is not a forgery and it is not tampered.
#   - A receipt whose signature checks.
#   - A timestamp token when DigiCert or Sectigo answered. If neither
#     answered, the seal card says "receipt present, timestamp absent".
#     That is not FORGED.
#   - Flags, if any (screen recording, a debugger, a simulated location,
#     a best-effort jailbreak note), are words beside the label. They do
#     not change it.
#
# Then the clock
#   7. Set the phone's wall clock 3 minutes ahead. Leave airplane mode off
#      only if you need the settings screen, then take 1 photograph with
#      no signal, then reconnect.
#   8. That photograph is DEVICE CLOCK MISMATCH. The wall clock moved and
#      the monotonic clock did not. Three minutes is past the two-minute
#      limit. The signature can still check. The label is the clock, not
#      FORGED and not TAMPERED.
#
echo "Shield iOS device acceptance — instructions only."
echo "This host did not run them. Read the comments in this file and do the run on an iPhone."
exit 0
