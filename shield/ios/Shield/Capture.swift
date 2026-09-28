//  Capture.swift
//
//  The only thing in this app that produces image bytes.
//
//  That sentence is the design. There is no `PHPickerViewController`, no
//  `UIImagePickerController`, no document picker, no drag-and-drop, and no
//  `NSPhotoLibraryUsageDescription` in Info.plist — so iOS itself will not
//  hand this app a library image even if a future version of this file asked
//  for one.
//
//  Why it is structural rather than a check: a file chosen from storage cannot
//  be attested, and an unattestable capture is refused by the server. A
//  library button would therefore be a control that looks available and always
//  fails, which reads as a bug rather than as the decision it is. The honest
//  shape is for the path not to exist.
//
//  The bytes go straight from AVCapturePhotoOutput into memory and from there
//  into the upload. They are never written to a shared container, so there is
//  no window in which another process could swap them.

import AVFoundation
import Foundation
import SwiftUI

@MainActor
final class CaptureModel: NSObject, ObservableObject {
    @Published var isReady = false
    @Published var problem: String?

    let session = AVCaptureSession()
    private let output = AVCapturePhotoOutput()
    private var pending: CheckedContinuation<Data, Error>?

    enum CaptureError: LocalizedError {
        case denied, unavailable, failed(String)

        var errorDescription: String? {
            switch self {
            case .denied:
                return """
                    Shield needs the camera. It has no other way to make a \
                    photograph: a file chosen from storage cannot prove where \
                    it came from, so there is no library option to fall back on.
                    """
            case .unavailable:
                return "No camera is available on this device."
            case .failed(let why):
                return "The capture failed: \(why)"
            }
        }
    }

    func start() async {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            break
        case .notDetermined:
            guard await AVCaptureDevice.requestAccess(for: .video) else {
                problem = CaptureError.denied.errorDescription
                return
            }
        default:
            problem = CaptureError.denied.errorDescription
            return
        }

        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera,
                                                   for: .video, position: .back),
              let input = try? AVCaptureDeviceInput(device: device) else {
            problem = CaptureError.unavailable.errorDescription
            return
        }

        session.beginConfiguration()
        session.sessionPreset = .photo
        if session.canAddInput(input) { session.addInput(input) }
        if session.canAddOutput(output) { session.addOutput(output) }
        session.commitConfiguration()

        // Off the main actor: starting the session blocks, and blocking here
        // freezes the preview that is supposed to be showing the shot.
        let session = self.session
        await Task.detached { session.startRunning() }.value
        isReady = true
    }

    func stop() {
        let session = self.session
        Task.detached { session.stopRunning() }
    }

    /// One photograph, as JPEG bytes. These exact bytes are what the
    /// attestation commits to and what the server hashes.
    func capture() async throws -> Data {
        try await withCheckedThrowingContinuation {
            (cont: CheckedContinuation<Data, Error>) in
            pending = cont
            let settings = AVCapturePhotoSettings(
                format: [AVVideoCodecKey: AVVideoCodecType.jpeg])
            // EXIF is left exactly as the camera wrote it. The server reads it
            // and treats it as a claim rather than as proof — it is forgeable
            // in about twelve lines — so stripping or rewriting it here would
            // only destroy a weak signal without adding a strong one.
            output.capturePhoto(with: settings, delegate: self)
        }
    }
}

extension CaptureModel: AVCapturePhotoCaptureDelegate {
    nonisolated func photoOutput(_ output: AVCapturePhotoOutput,
                                 didFinishProcessingPhoto photo: AVCapturePhoto,
                                 error: Error?) {
        Task { @MainActor in
            guard let cont = pending else { return }
            pending = nil
            if let error {
                cont.resume(throwing: CaptureError.failed(error.localizedDescription))
            } else if let data = photo.fileDataRepresentation() {
                cont.resume(returning: data)
            } else {
                cont.resume(throwing: CaptureError.failed("no image data was produced"))
            }
        }
    }
}

/// The live preview. A plain wrapper — it shows the session and nothing else.
struct CameraPreview: UIViewRepresentable {
    let session: AVCaptureSession

    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        view.previewLayer.session = session
        view.previewLayer.videoGravity = .resizeAspectFill
        return view
    }

    func updateUIView(_ view: PreviewView, context: Context) {}

    final class PreviewView: UIView {
        // `layerClass` makes the view's own layer the preview layer.
        // Overriding `layer` itself to narrow its type is not legal Swift, so
        // reach it through an accessor.
        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        var previewLayer: AVCaptureVideoPreviewLayer {
            layer as! AVCaptureVideoPreviewLayer
        }
    }
}
