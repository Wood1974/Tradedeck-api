package com.tradedeck.shield

import android.graphics.ImageFormat
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.ImageReader
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.view.Gravity
import android.view.Surface
import android.view.TextureView
import android.widget.Button
import android.widget.FrameLayout
import androidx.appcompat.app.AppCompatActivity
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The only thing in this app that produces image bytes.
 *
 * There is no photo picker, no ACTION_GET_CONTENT, and no storage permission.
 * The JPEG stays in memory. A DEPTH16 frame is hashed when this camera can
 * deliver one, and omitted when it cannot.
 *
 * Not run on a device. Session configuration for depth is the part most
 * likely to need a change after the first real phone.
 */
class CameraActivity : AppCompatActivity() {
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var jpegReader: ImageReader? = null
    private var depthReader: ImageReader? = null
    private val thread = HandlerThread("shield-camera").also { it.start() }
    private val handler = Handler(thread.looper)
    private val shot = AtomicBoolean(false)
    private var depthBytes: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val texture = TextureView(this)
        val button = Button(this).apply {
            text = "Shutter"
            setOnClickListener { take() }
        }
        val root = FrameLayout(this)
        root.addView(texture, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        root.addView(button, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.WRAP_CONTENT,
            FrameLayout.LayoutParams.WRAP_CONTENT,
            Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL))
        setContentView(root)
        texture.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(surface: android.graphics.SurfaceTexture, w: Int, h: Int) {
                open(texture)
            }
            override fun onSurfaceTextureSizeChanged(surface: android.graphics.SurfaceTexture, w: Int, h: Int) {}
            override fun onSurfaceTextureDestroyed(surface: android.graphics.SurfaceTexture): Boolean = true
            override fun onSurfaceTextureUpdated(surface: android.graphics.SurfaceTexture) {}
        }
    }

    private fun open(texture: TextureView) {
        val manager = getSystemService(CAMERA_SERVICE) as CameraManager
        val id = manager.cameraIdList.firstOrNull { candidate ->
            val facing = manager.getCameraCharacteristics(candidate)
                .get(CameraCharacteristics.LENS_FACING)
            facing == CameraCharacteristics.LENS_FACING_BACK
        } ?: manager.cameraIdList.firstOrNull() ?: run {
            finish()
            return
        }
        val chars = manager.getCameraCharacteristics(id)
        val caps = chars.get(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES)
        val depth = caps?.contains(
            CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_DEPTH_OUTPUT) == true
        jpegReader = ImageReader.newInstance(1920, 1080, ImageFormat.JPEG, 2)
        val surfaces = mutableListOf<Surface>()
        val preview = Surface(texture.surfaceTexture)
        surfaces.add(preview)
        surfaces.add(jpegReader!!.surface)
        if (depth) {
            depthReader = ImageReader.newInstance(640, 480, ImageFormat.DEPTH16, 2)
            surfaces.add(depthReader!!.surface)
        }
        try {
            manager.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    camera = device
                    device.createCaptureSession(surfaces, object : CameraCaptureSession.StateCallback() {
                        override fun onConfigured(s: CameraCaptureSession) { session = s }
                        override fun onConfigureFailed(s: CameraCaptureSession) {
                            // Depth is the usual reason. Retry the session without it.
                            depthReader?.close()
                            depthReader = null
                            device.createCaptureSession(
                                listOf(preview, jpegReader!!.surface),
                                object : CameraCaptureSession.StateCallback() {
                                    override fun onConfigured(s2: CameraCaptureSession) { session = s2 }
                                    override fun onConfigureFailed(s2: CameraCaptureSession) { finish() }
                                },
                                handler)
                        }
                    }, handler)
                }
                override fun onDisconnected(device: CameraDevice) { device.close() }
                override fun onError(device: CameraDevice, error: Int) { device.close(); finish() }
            }, handler)
        } catch (_: SecurityException) {
            finish()
        }
    }

    private fun take() {
        val device = camera ?: return
        val jpeg = jpegReader ?: return
        val active = session ?: return
        if (!shot.compareAndSet(false, true)) return
        depthReader?.setOnImageAvailableListener({ reader ->
            val image = reader.acquireLatestImage() ?: return@setOnImageAvailableListener
            try {
                val plane = image.planes.firstOrNull()
                if (plane != null) {
                    val buf = plane.buffer
                    val bytes = ByteArray(buf.remaining())
                    buf.get(bytes)
                    depthBytes = bytes
                }
            } finally {
                image.close()
            }
        }, handler)
        jpeg.setOnImageAvailableListener({ reader ->
            val image = reader.acquireLatestImage() ?: return@setOnImageAvailableListener
            try {
                val buf = image.planes[0].buffer
                val bytes = ByteArray(buf.remaining())
                buf.get(bytes)
                val depth = depthBytes
                val (present, hash) = if (depth != null && depth.isNotEmpty()) {
                    true to Digests.sha256Hex(depth)
                } else {
                    false to null
                }
                CaptureHold.frame = CapturedFrame(
                    jpeg = bytes,
                    sha256Hex = Digests.sha256Hex(bytes),
                    depthPresent = present,
                    depthHash = hash,
                )
            } finally {
                image.close()
            }
            runOnUiThread { finish() }
        }, handler)
        val request = device.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE).apply {
            addTarget(jpeg.surface)
            depthReader?.let { addTarget(it.surface) }
            set(CaptureRequest.JPEG_ORIENTATION, 90)
        }
        active.capture(request.build(), null, handler)
    }

    override fun onDestroy() {
        session?.close()
        camera?.close()
        jpegReader?.close()
        depthReader?.close()
        thread.quitSafely()
        super.onDestroy()
    }
}
