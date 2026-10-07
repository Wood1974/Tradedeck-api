//  Sensors.swift
//
//  A snapshot of the motion coprocessor and the barometer, hashed into the
//  capture record when a sample is already available. No sample means the
//  field is omitted. A stand-in hash would be a claim the phone did not
//  measure.
//
//  Depth is the same rule. AVDepthData is hashed when the capture carries
//  it. Otherwise depth_present is false and there is no depth_hash.
//
//  Units are whole numbers before they are signed: milli-g, milli-radians
//  per second, pascals. The conversion happens here. The canonical JSON
//  never sees a float.
//
//  Compiled in CI. Not run on a device, so a missing sample on hardware is
//  an expected thing to look at during the acceptance script, not a failure
//  of the seal.

import AVFoundation
import CoreMotion
import CryptoKit
import Foundation

@MainActor
final class SensorReader {
    static let shared = SensorReader()

    private let motion = CMMotionManager()
    private let altimeter = CMAltimeter()
    private var pressurePascals: Int?
    private var started = false

    func start() {
        guard !started else { return }
        started = true
        if motion.isDeviceMotionAvailable {
            motion.deviceMotionUpdateInterval = 0.05
            motion.startDeviceMotionUpdates()
        }
        guard CMAltimeter.isRelativeAltitudeAvailable() else { return }
        altimeter.startRelativeAltitudeUpdates(to: .main) { [weak self] data, _ in
            guard let data else { return }
            // CMAltimeter reports kilopascals. The record signs pascals.
            let pascals = Int((data.pressure.doubleValue * 1000).rounded())
            Task { @MainActor in self?.pressurePascals = pascals }
        }
    }

    /// SHA-256 hex of the canonical snapshot, or nil when nothing has
    /// arrived yet. Omitted from the record, not stored as a placeholder.
    func snapshotHash() -> String? {
        start()
        guard let sample = motion.deviceMotion else { return nil }
        let accel = sample.gravity
        let gyro = sample.rotationRate
        var fields: [String: Canon] = [
            "accel_milli_g": .array([
                .int(Self.milli(accel.x)),
                .int(Self.milli(accel.y)),
                .int(Self.milli(accel.z)),
            ]),
            "gyro_milli_rad_s": .array([
                .int(Self.milli(gyro.x)),
                .int(Self.milli(gyro.y)),
                .int(Self.milli(gyro.z)),
            ]),
        ]
        if let pressurePascals {
            fields["baro_pa"] = .int(pressurePascals)
        }
        let json = CanonicalJSON.data(.object(fields))
        return Digests.sha256Hex(json)
    }

    private static func milli(_ value: Double) -> Int {
        Int((value * 1000).rounded())
    }
}

enum DepthDigest {
    /// Hash the depth map's bytes when the photo has one.
    /// `(false, nil)` is "not available", which the record stores as
    /// depth_present false and no depth_hash.
    static func hash(_ photo: AVCapturePhoto) -> (present: Bool, hash: String?) {
        guard let depth = photo.depthData else { return (false, nil) }
        let buffer = depth.depthDataMap
        CVPixelBufferLockBaseAddress(buffer, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(buffer, .readOnly) }
        guard let base = CVPixelBufferGetBaseAddress(buffer) else {
            return (false, nil)
        }
        let count = CVPixelBufferGetHeight(buffer) * CVPixelBufferGetBytesPerRow(buffer)
        let bytes = Data(bytes: base, count: count)
        return (true, Digests.sha256Hex(bytes))
    }
}
