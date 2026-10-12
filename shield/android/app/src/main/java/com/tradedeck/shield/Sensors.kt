package com.tradedeck.shield

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.media.Image
import kotlin.math.roundToInt

/**
 * A snapshot of the accelerometer, gyroscope, and barometer, hashed into
 * the capture record when a sample is already available. No sample means
 * the field is omitted. Units are whole numbers before they are signed:
 * milli-g, milli-radians per second, pascals. A float never reaches the
 * canonical JSON.
 *
 * Depth is the same rule. A DEPTH16 frame is hashed when the capture
 * carries one. Otherwise depth_present is false and there is no depth_hash.
 *
 * Compiled when the Android workflow runs. Not run on a device.
 */
class SensorReader(context: Context) : SensorEventListener {
    private val manager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    private var accel: FloatArray? = null
    private var gyro: FloatArray? = null
    private var pressureHpa: Float? = null
    private var started = false

    fun start() {
        if (started) return
        started = true
        listen(Sensor.TYPE_ACCELEROMETER)
        listen(Sensor.TYPE_GYROSCOPE)
        listen(Sensor.TYPE_PRESSURE)
    }

    private fun listen(type: Int) {
        val sensor = manager.getDefaultSensor(type) ?: return
        manager.registerListener(this, sensor, SensorManager.SENSOR_DELAY_NORMAL)
    }

    fun stop() {
        if (!started) return
        manager.unregisterListener(this)
        started = false
    }

    override fun onSensorChanged(event: SensorEvent) {
        when (event.sensor.type) {
            Sensor.TYPE_ACCELEROMETER -> accel = event.values.copyOf(3)
            Sensor.TYPE_GYROSCOPE -> gyro = event.values.copyOf(3)
            Sensor.TYPE_PRESSURE -> pressureHpa = event.values[0]
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}

    /** SHA-256 hex of the canonical snapshot, or null when nothing has arrived. */
    fun snapshotHash(): String? {
        start()
        val a = accel ?: return null
        val g = gyro
        val fields = linkedMapOf<String, Canon>(
            "accel_milli_g" to Canon.Arr(listOf(
                Canon.Num(milliG(a[0]).toLong()),
                Canon.Num(milliG(a[1]).toLong()),
                Canon.Num(milliG(a[2]).toLong()),
            )),
        )
        if (g != null && g.size >= 3) {
            fields["gyro_milli_rad_s"] = Canon.Arr(listOf(
                Canon.Num(milli(g[0]).toLong()),
                Canon.Num(milli(g[1]).toLong()),
                Canon.Num(milli(g[2]).toLong()),
            ))
        }
        pressureHpa?.let { hpa ->
            // TYPE_PRESSURE is hectopascals. The record signs pascals.
            fields["baro_pa"] = Canon.Num((hpa * 100.0).roundToInt().toLong())
        }
        return Digests.sha256Hex(CanonicalJson.bytes(Canon.Obj(fields)))
    }

    private fun milli(value: Float): Int = (value * 1000.0).roundToInt()

    /** m/s^2 to milli-g. Standard gravity is 9.80665. */
    private fun milliG(mps2: Float): Int = (mps2 / 9.80665 * 1000.0).roundToInt()

    companion object {
        /** Hash a DEPTH16 plane when the camera delivered one. */
        fun depthHash(image: Image?): Pair<Boolean, String?> {
            if (image == null) return false to null
            val plane = image.planes.firstOrNull() ?: return false to null
            val buf = plane.buffer
            val bytes = ByteArray(buf.remaining())
            buf.get(bytes)
            if (bytes.isEmpty()) return false to null
            return true to Digests.sha256Hex(bytes)
        }
    }
}
