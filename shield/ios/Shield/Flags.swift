//  Flags.swift
//
//  Bits in the capture record. They are facts beside the photo. They do
//  not change SEALED, UNVERIFIED TIME, or DEVICE CLOCK MISMATCH. The
//  server carries them and does not grade on them.
//
//  Jailbreak detection is best-effort and known to be incomplete. App
//  Attest does not report it. A hit sets the root-traces bit. A miss
//  means nothing. This is not a claim that the phone is unmodified.

import Darwin
import Foundation
import UIKit

enum CaptureFlag {
    static let screenCaptured = 1 << 0
    static let debugger = 1 << 1
    static let mockLocation = 1 << 2
    static let rootTraces = 1 << 3

    @MainActor
    static func bits(locationSimulated: Bool?) -> Int {
        var value = 0
        if UIScreen.main.isCaptured { value |= screenCaptured }
        if debuggerAttached() { value |= debugger }
        if locationSimulated == true { value |= mockLocation }
        if jailbreakTraces() { value |= rootTraces }
        return value
    }

    /// Best-effort. A stock phone and a careful modified phone both return
    /// false. The bit is a note, not a verdict.
    static func jailbreakTraces() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
        ]
        return paths.contains { FileManager.default.fileExists(atPath: $0) }
    }
}

/// P_TRACED on the current process. A debugger attached to a release build
/// is worth recording. It is not, by itself, a reason to refuse the photo.
private func debuggerAttached() -> Bool {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    let status = name.withUnsafeMutableBufferPointer { buffer in
        sysctl(buffer.baseAddress, 4, &info, &size, nil, 0)
    }
    if status != 0 { return false }
    // P_TRACED from xnu's proc.h. A macro the SDK does not always surface.
    return (info.kp_proc.p_flag & 0x00000800) != 0
}
