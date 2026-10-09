//  Time.swift
//
//  The clocks a capture record and a job ticket are signed over.
//
//  wall_time_ms is the wall clock, Unix milliseconds, a whole number.
//  monotonic_ms is mach_continuous_time converted with mach_timebase_info.
//  That clock does not jump when the user sets the time, and it does not
//  reset on sleep. It does reset on a reboot, which is why boot_id is
//  kern.bootsessionuuid: a new boot is a new id, and the time rules then
//  say UNVERIFIED TIME rather than pretending the interval still means
//  something.
//
//  GNSS time is the location fix's timestamp when a fix is already in
//  hand. It is omitted when there is no fix. A missing GNSS reading is
//  not a zero.
//
//  This file has been compiled by CI. It has not been run on a device.
//  The tick conversion in particular wants a device: the timebase is
//  hardware, and a wrong division would move every later photo by a
//  constant factor.

import CoreLocation
import Darwin
import Foundation

struct PhoneClock {
    var wallTimeMs: Int
    var monotonicMs: Int
    var bootID: String?
    var gnssTimeMs: Int?
    var locationSimulated: Bool?

    /// Read now. `location` is a fix the caller already has. This does not
    /// start a location session and does not wait for one.
    static func read(location: CLLocation?) -> PhoneClock {
        let wall = Int((Date().timeIntervalSince1970 * 1000).rounded())
        let mono = Int(monotonicMilliseconds())
        var gnss: Int?
        var simulated: Bool?
        if let location {
            gnss = Int((location.timestamp.timeIntervalSince1970 * 1000).rounded())
            simulated = location.sourceInformation?.isSimulatedBySoftware
        }
        return PhoneClock(
            wallTimeMs: wall,
            monotonicMs: mono,
            bootID: bootSessionUUID(),
            gnssTimeMs: gnss,
            locationSimulated: simulated)
    }

    /// The signed clock object. boot_count is an Android field and is not
    /// sent from here. Absent boot id is omitted, not sent as an empty string.
    func ticketClock() -> [String: Any] {
        var body: [String: Any] = [
            "wall_time_ms": wallTimeMs,
            "monotonic_ms": monotonicMs,
        ]
        if let bootID, !bootID.isEmpty { body["boot_id"] = bootID }
        return body
    }

    func canonicalClock() -> Data {
        var fields: [String: Canon] = [
            "wall_time_ms": .int(wallTimeMs),
            "monotonic_ms": .int(monotonicMs),
        ]
        if let bootID, !bootID.isEmpty { fields["boot_id"] = .string(bootID) }
        return CanonicalJSON.data(.object(fields))
    }
}

/// mach_continuous_time is a tick count. mach_timebase_info says how many
/// nanoseconds one tick is (numer/denom). Milliseconds are what the record
/// signs. The multiply is split so a long uptime does not overflow the
/// intermediate product.
func monotonicMilliseconds() -> UInt64 {
    var info = mach_timebase_info_data_t(numer: 0, denom: 0)
    mach_timebase_info(&info)
    let denom = UInt64(info.denom == 0 ? 1 : info.denom)
    let numer = UInt64(info.numer == 0 ? 1 : info.numer)
    let ticks = mach_continuous_time()
    let nanos = (ticks / denom) * numer + (ticks % denom) * numer / denom
    return nanos / 1_000_000
}

/// kern.bootsessionuuid. Nil when the kernel does not answer. The capture
/// is still stored; the time rules will call the interval unverified
/// because the boot was not shown.
func bootSessionUUID() -> String? {
    var size = 0
    if sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) != 0 || size <= 1 {
        return nil
    }
    var buffer = [CChar](repeating: 0, count: size)
    if sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) != 0 {
        return nil
    }
    let text = String(cString: buffer).trimmingCharacters(in: .whitespacesAndNewlines)
    return text.isEmpty ? nil : text
}
