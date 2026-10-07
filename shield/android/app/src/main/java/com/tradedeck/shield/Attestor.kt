package com.tradedeck.shield

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.math.BigInteger

/**
 * The Android Keystore key this install signs with.
 *
 * The first capture generates an EC P-256 key with an attestation challenge
 * of SHA-256(clientData), StrongBox where the device has it and the TEE
 * otherwise, and returns the certificate chain. Later captures sign
 * clientData with SHA256withECDSA and do not pre-hash: the server hashes
 * once, inside ECDSA.
 *
 * clientData for a photograph is the challenge bytes followed by the raw
 * SHA-256 of the photograph. clientData for an offline record is
 * "shield-capture-v1" followed by the raw record hash. clientData for a
 * second phone is "shield-countersign-v1" followed by that same raw record
 * hash. clientData for a job ticket is "shield-genesis-v1" followed by
 * SHA-256 of the raw ticket hash concatenated with the canonical clock JSON.
 *
 * Compiled when the Android workflow runs. Not run on a device. Keystore,
 * StrongBox, and the attestation extension are the parts a device has to
 * confirm.
 */
object Attestor {
    private const val PREFS = "shield.attested"
    private const val ALIAS_KEY = "alias"
    private const val STORE = "AndroidKeyStore"

    fun registeredAlias(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(ALIAS_KEY, null)

    fun keep(context: Context, alias: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(ALIAS_KEY, alias).apply()
    }

    fun forget(context: Context) {
        val alias = registeredAlias(context)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(ALIAS_KEY).apply()
        if (alias != null) {
            val ks = keystore()
            if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        }
    }

    /** Certificate chain, leaf first, each certificate base64 DER, joined with commas. */
    fun attest(context: Context, clientData: ByteArray): Pair<String, String> {
        val alias = "shield." + Digests.sha256Hex(clientData).take(16)
        val challenge = Digests.sha256(clientData)
        try {
            generate(alias, challenge, strongBox = true)
        } catch (err: Exception) {
            if (!isStrongBoxMiss(err)) throw err
            generate(alias, challenge, strongBox = false)
        }
        val chain = keystore().getCertificateChain(alias)
            ?: throw IllegalStateException("The keystore returned no certificate chain.")
        val joined = chain.joinToString(",") {
            Base64.encodeToString(it.encoded, Base64.NO_WRAP)
        }
        return alias to joined
    }

    fun sign(context: Context, clientData: ByteArray): Pair<String, ByteArray> {
        val alias = registeredAlias(context)
            ?: throw IllegalStateException(
                "This install has no attested key yet. Take one photograph " +
                    "online before sealing a job ticket or an offline capture.")
        val ks = keystore()
        val entry = ks.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("The attested key is not in the keystore.")
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(entry.privateKey)
        signature.update(clientData)
        return alias to signature.sign()
    }

    fun keyId(context: Context): String {
        val alias = registeredAlias(context)
            ?: throw IllegalStateException("This install has no attested key.")
        val cert = keystore().getCertificate(alias)
            ?: throw IllegalStateException("The attested key has no certificate.")
        val point = uncompressed(cert.publicKey as ECPublicKey)
        return Base64.encodeToString(Digests.sha256(point), Base64.NO_WRAP)
    }

    fun clientData(challenge: String, payload: ByteArray): ByteArray =
        challenge.toByteArray(Charsets.UTF_8) + payload

    private fun generate(alias: String, attestationChallenge: ByteArray, strongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(attestationChallenge)
        if (strongBox && android.os.Build.VERSION.SDK_INT >= 28) {
            builder.setIsStrongBoxBacked(true)
        }
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, STORE)
        gen.initialize(builder.build())
        gen.generateKeyPair()
    }

    private fun isStrongBoxMiss(err: Exception): Boolean {
        var current: Throwable? = err
        while (current != null) {
            if (current.javaClass.simpleName == "StrongBoxUnavailableException") return true
            current = current.cause
        }
        return false
    }

    private fun keystore(): KeyStore =
        KeyStore.getInstance(STORE).apply { load(null) }

    /** 0x04 || X || Y, each coordinate 32 bytes. */
    fun uncompressed(key: ECPublicKey): ByteArray {
        val x = fixed(key.w.affineX)
        val y = fixed(key.w.affineY)
        return byteArrayOf(0x04) + x + y
    }

    private fun fixed(n: BigInteger): ByteArray {
        var raw = n.toByteArray()
        if (raw.size > 32) raw = raw.copyOfRange(raw.size - 32, raw.size)
        if (raw.size < 32) raw = ByteArray(32 - raw.size) + raw
        return raw
    }
}
