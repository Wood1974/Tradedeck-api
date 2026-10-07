package com.tradedeck.shield

import android.Manifest
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Bundle
import android.os.Looper
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors

/**
 * Connect, seal a job ticket, photograph, and send the queue.
 *
 * A sealed ticket means the next photograph is part of the offline chain,
 * even when the phone happens to have a signal. No ticket yet: the online
 * path, which is also how the install attests its key the first time.
 *
 * Not run on a device.
 */
class MainActivity : AppCompatActivity() {
    private lateinit var address: EditText
    private lateinit var token: EditText
    private lateinit var recordId: EditText
    private lateinit var checkpointId: EditText
    private lateinit var projectNumber: EditText
    private lateinit var status: TextView
    private val io = Executors.newSingleThreadExecutor()
    private var lastFix: Location? = null
    private lateinit var sensors: SensorReader

    private val camera = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val frame = CaptureHold.frame
        CaptureHold.frame = null
        if (frame == null) {
            status.text = "No photograph was produced."
            return@registerForActivityResult
        }
        val record = recordId.text.toString().trim()
        val checkpoint = checkpointId.text.toString().trim()
        io.execute {
            try {
                val note = if (Outbox(this).hasTicket(record)) {
                    val hash = OfflineCapture.store(this, frame, record, checkpoint, lastFix)
                    var refusal: String? = null
                    val sent = try {
                        client().let { Outbox(this).flush(it, record) }
                        true
                    } catch (err: ShieldClient.HttpException) {
                        if (err.code != 0) refusal = err.message
                        false
                    } catch (_: java.io.IOException) {
                        false
                    }
                    when {
                        sent -> "Sent ${hash.take(12)}…"
                        refusal != null ->
                            "Saved on this phone ${hash.take(12)}… Shield did not accept the batch: $refusal"
                        else ->
                            "Saved on this phone ${hash.take(12)}… It will be sent when Shield is reachable."
                    }
                } else {
                    val out = client().uploadPhoto(record, checkpoint, frame.jpeg)
                    "Recorded online. ${out.optJSONObject("photo")?.optString("attestation_tier").orEmpty()}"
                }
                runOnUiThread { status.text = note }
            } catch (err: Exception) {
                runOnUiThread { status.text = err.message ?: err.toString() }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sensors = SensorReader(this)
        SensorHold.reader = sensors
        sensors.start()
        CaptureFlag.watchScreenCapture(this)
        listenForGnss()

        address = field("https://shield.example.com")
        token = field("shld_…")
        recordId = field("record id")
        checkpointId = field("checkpoint id")
        projectNumber = field("Play Cloud project number, optional")
        status = TextView(this)

        val prefs = getSharedPreferences("shield.connection", MODE_PRIVATE)
        address.setText(prefs.getString("address", ""))
        token.setText(prefs.getString("token", ""))
        recordId.setText(prefs.getString("record", ""))
        projectNumber.setText(prefs.getString("project", ""))

        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
            addView(address)
            addView(token)
            addView(recordId)
            addView(checkpointId)
            addView(projectNumber)
            addView(button("Save connection") { saveConnection() })
            addView(button("Seal job ticket") { seal() })
            addView(button("Photograph") { photograph() })
            addView(button("Send queue") { sendQueue() })
            addView(status)
        }
        setContentView(ScrollView(this).apply { addView(column) })
    }

    override fun onDestroy() {
        sensors.stop()
        io.shutdown()
        super.onDestroy()
    }

    private fun field(hint: String) = EditText(this).apply {
        this.hint = hint
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    }

    private fun button(label: String, action: () -> Unit) = Button(this).apply {
        text = label
        setOnClickListener { action() }
    }

    private fun saveConnection() {
        getSharedPreferences("shield.connection", MODE_PRIVATE).edit()
            .putString("address", address.text.toString().trim())
            .putString("token", token.text.toString().trim())
            .putString("record", recordId.text.toString().trim())
            .putString("project", projectNumber.text.toString().trim())
            .apply()
        status.text = "Saved on this phone."
    }

    private fun client(): ShieldClient {
        val base = address.text.toString().trim()
        val cred = token.text.toString().trim()
        if (base.isEmpty() || cred.isEmpty()) {
            throw IllegalStateException("Enter the Shield address and the credential first.")
        }
        return ShieldClient(this, base, cred)
    }

    private fun project(): Long? =
        projectNumber.text.toString().trim().toLongOrNull()

    private fun seal() {
        val record = recordId.text.toString().trim()
        status.text = "Sealing the job ticket…"
        io.execute {
            try {
                val hash = client().establishTicket(
                    record, PhoneClock.read(this, lastFix, GnssHold.clock), project())
                runOnUiThread {
                    status.text = "Job ticket sealed. Offline photographs chain from ${hash.take(12)}…"
                }
            } catch (err: Exception) {
                runOnUiThread { status.text = err.message ?: err.toString() }
            }
        }
    }

    private fun photograph() {
        val needed = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED) {
            needed.add(Manifest.permission.CAMERA)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
            != PackageManager.PERMISSION_GRANTED) {
            needed.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        if (needed.isNotEmpty()) {
            requestPermissions(needed.toTypedArray(), 1)
            status.text = "Allow the camera, then tap Photograph again."
            return
        }
        camera.launch(android.content.Intent(this, CameraActivity::class.java))
    }

    private fun sendQueue() {
        val record = recordId.text.toString().trim()
        io.execute {
            try {
                val waiting = Outbox(this).pending(record, 64)
                if (waiting.isEmpty()) {
                    runOnUiThread { status.text = "Nothing is waiting on this phone." }
                    return@execute
                }
                Outbox(this).flush(client(), record)
                runOnUiThread { status.text = "Photographs saved on this phone were sent to Shield." }
            } catch (err: Exception) {
                val waiting = try { Outbox(this).pending(record, 64).size } catch (_: Exception) { 0 }
                runOnUiThread {
                    status.text = if (waiting > 0) {
                        "$waiting photographs are saved on this phone. They will be sent when Shield is reachable. ${err.message ?: ""}"
                    } else {
                        err.message ?: err.toString()
                    }
                }
            }
        }
    }

    private fun listenForGnss() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
            != PackageManager.PERMISSION_GRANTED) {
            return
        }
        val manager = getSystemService(LOCATION_SERVICE) as LocationManager
        try {
            manager.requestLocationUpdates(
                LocationManager.GPS_PROVIDER, 1000L, 0f,
                object : LocationListener {
                    override fun onLocationChanged(location: Location) { lastFix = location }
                },
                Looper.getMainLooper())
        } catch (_: Exception) {
            // A capture without a position is still a capture.
        }
        try {
            manager.registerGnssMeasurementsCallback(object : android.location.GnssMeasurementsEvent.Callback() {
                override fun onGnssMeasurementsReceived(event: android.location.GnssMeasurementsEvent) {
                    GnssHold.clock = event.clock
                }
            }, android.os.Handler(Looper.getMainLooper()))
        } catch (_: Exception) {
            // No sky, or the platform refused the callback. GNSS time stays absent.
        }
    }
}
