"""The iOS capture record must name the same bytes as capture_record.py.

There is no Swift compiler on this machine, and the GitHub Actions job
compiles the app without running it. What can be checked here is the
contract the Swift file copied: the canonical JSON and the record hash
for the same fields. If either side is edited alone, this fails.

It does not prove the Swift encoder produces those strings. It proves the
strings the Swift file claims are Python's strings. A device run is still
the first execution of the encoder.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import capture_record  # noqa: E402

SWIFT = os.path.join(os.path.dirname(__file__), "..", "ios", "Shield",
                     "CaptureRecord.swift")


def _literal(name):
    text = open(SWIFT).read()
    raw = re.search(rf'static let {name} = #"(.*)"#', text)
    if raw:
        return raw.group(1)
    plain = re.search(rf'static let {name} = "([^"]*)"', text)
    assert plain, f"{name} is not in CaptureRecord.swift"
    return plain.group(1)


def _seal(**fields):
    prev = fields.pop("prev")
    record = capture_record.build(**fields)
    raw = capture_record.canonical(record).decode()
    sealed = capture_record.seal(record, prev)
    return raw, sealed["record_hash"]


class TestTheCopiedBytes:
    def test_a_plain_record_matches_python(self):
        raw, digest = _seal(
            checkpoint_id="cp-1", photo_sha256="ab" * 32, ticket_id="cd" * 32,
            wall_time_ms=1_700_000_000_000, monotonic_ms=5_000_000,
            boot_id="BOOT-UUID", flags=0,
            prev="cd" * 32)
        assert raw == _literal("plainCanonical")
        assert digest == _literal("plainHash")
        assert "version" in raw
        assert "." not in raw

    def test_flags_depth_and_a_false_bool_match_python(self):
        raw, digest = _seal(
            checkpoint_id="cp-2", photo_sha256="11" * 32, ticket_id="cd" * 32,
            wall_time_ms=1_700_000_010_000, monotonic_ms=5_010_000,
            boot_id="BOOT-UUID", flags=15,
            gnss_time_ms=1_700_000_010_050, location_simulated=False,
            depth_present=False, sensor_hash="22" * 32,
            prev="ab" * 32)
        assert raw == _literal("flaggedCanonical")
        assert digest == _literal("flaggedHash")
        assert '"depth_present":false' in raw
        assert '"location_simulated":false' in raw
        assert '"flags":15' in raw

    def test_a_sensor_snapshot_and_a_ticket_clock_match_python(self):
        sensor = {
            "accel_milli_g": [0, 0, 1000],
            "baro_pa": 101325,
            "gyro_milli_rad_s": [1, -2, 3],
        }
        assert capture_record.canonical_whole(sensor).decode() == _literal("sensorCanonical")
        assert capture_record.hash_whole(sensor) == _literal("sensorHash")
        clock = {
            "boot_id": "BOOT-UUID",
            "monotonic_ms": 5_000_000,
            "wall_time_ms": 1_700_000_000_000,
        }
        assert capture_record.canonical_whole(clock).decode() == _literal("clockCanonical")
