"""
Shield Capture v1 Audit Module

Enforcement of immutable trust model invariants through cryptographic integrity
validation, checkpoint consistency checking, nonce management, GPS spoofing detection,
and device binding verification.

Core invariants:
- Evidence chain integrity (manifests are valid, immutable, sequential)
- Checkpoint consistency (captures match pack definitions)
- Nonce exhaustion (challenges consumed exactly once)
- GPS spoofing detection (location consistency checks pass)
- Device binding consistency (device hashes are stable or change predictably)
"""

from audit.invariants import (
    assert_manifest_structure,
    assert_pack_checkpoint_correspondence,
    assert_nonce_single_use,
    assert_location_consistent,
    assert_device_consistency,
    assert_capture_sequence_integrity,
    assert_timestamp_monotonic,
    assert_no_manifest_tampering,
    assert_bind_hash_validity,
)

__all__ = [
    "assert_manifest_structure",
    "assert_pack_checkpoint_correspondence",
    "assert_nonce_single_use",
    "assert_location_consistent",
    "assert_device_consistency",
    "assert_capture_sequence_integrity",
    "assert_timestamp_monotonic",
    "assert_no_manifest_tampering",
    "assert_bind_hash_validity",
]
