package com.indigomfa.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.util.Arrays

object CryptoManager {

    private const val KEY_ALIAS = "IndigoMFAKey"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    // 1. Generate Key Pair (SECP256R1 / NIST P-256)
    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
        )

        val parameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_AGREE_KEY
        ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
         .setUserAuthenticationRequired(false) // Set true for Biometrics
         .build()

        keyPairGenerator.initialize(parameterSpec)
        return keyPairGenerator.generateKeyPair()
    }

    fun getPublicKeyPem(): String {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        val pub = entry?.certificate?.publicKey ?: return ""

        val encoded = Base64.encodeToString(pub.encoded, Base64.NO_WRAP)
        return "-----BEGIN PUBLIC KEY-----\n$encoded\n-----END PUBLIC KEY-----"
    }

    // 2. Decrypt ECIES (ECDH + HKDF + AES-GCM)
    // Matches mfa_sdk/crypto.py: X9.62 Uncompressed Point format
    fun decrypt(encryptedData: ByteArray): String {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val privateKey = (ks.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry).privateKey

        // A. Parse Blob
        // Format: [65 bytes Ephemeral Pub][12 bytes IV][Ciphertext + Tag]
        if (encryptedData.size < 93) throw Exception("Invalid blob size")

        val ephPubBytes = encryptedData.copyOfRange(0, 65)
        val iv = encryptedData.copyOfRange(65, 77)
        val ciphertext = encryptedData.copyOfRange(77, encryptedData.size)

        // B. Load Ephemeral Public Key
        // Android KeyFactory expects standard X.509 SubjectPublicKeyInfo wrapping usually.
        // But we have raw X9.62 point. We need to construct the KeySpec.
        // Or use BouncyCastle.
        // To stick to standard Android, we can construct the X.509 header manually for P-256
        val x509Header = byteArrayOf(
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        )
        val fullPubBytes = x509Header + ephPubBytes
        val keyFactory = KeyFactory.getInstance("EC")
        val pubKeySpec = java.security.spec.X509EncodedKeySpec(fullPubBytes)
        val ephemeralPublicKey = keyFactory.generatePublic(pubKeySpec)

        // C. ECDH - Derive Shared Secret
        val keyAgreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore") // Or BC provider
        // Note: AndroidKeyStore provider usually handles private key ops.
        // For KeyAgreement, if private key is in hardware, we must use the provider.
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(ephemeralPublicKey, true)
        val sharedSecret = keyAgreement.generateSecret()

        // D. HKDF (RFC 5869) - Derive AES Key
        // Backend uses: Hash=SHA256, Salt=None (32 nulls), Info="mfa-protocol-encryption", Length=32
        val aesKey = hkdfDerive(sharedSecret)

        // E. AES-GCM Decrypt
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv) // 128 bit auth tag length
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"), spec)

        val plaintext = cipher.doFinal(ciphertext)
        return String(plaintext, Charsets.UTF_8)
    }

    private fun hkdfDerive(inputKeyingMaterial: ByteArray): ByteArray {
        // HKDF-Extract
        // Salt = 32 bytes of zeros if None
        val salt = ByteArray(32)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val pseudoRandomKey = mac.doFinal(inputKeyingMaterial)

        // HKDF-Expand
        val info = "mfa-protocol-encryption".toByteArray(Charsets.UTF_8)
        val output = ByteBuffer.allocate(32 + info.size + 1)
        output.put(info)
        output.put(0x01) // Counter

        val macExpand = Mac.getInstance("HmacSHA256")
        macExpand.init(SecretKeySpec(pseudoRandomKey, "HmacSHA256"))
        val derivedKey = macExpand.doFinal(output.array())

        // We need 32 bytes (AES-256)
        return Arrays.copyOf(derivedKey, 32)
    }
}
