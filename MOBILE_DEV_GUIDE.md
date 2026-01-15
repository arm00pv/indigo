# Mobile App Development Guide

This guide provides technical specifications and implementation details for building the **Indigo MFA** mobile authenticator app on Android (Kotlin) and iOS (Swift).

---

## 🏗️ 1. Architecture Overview

The mobile app acts as a **Secure Enclave** that stores the user's Private Key. The server *never* sees this key.

### Core Responsibilities
1.  **Key Generation:** Create a secure ECC Key Pair (SECP256R1).
2.  **Registration:** Export Public Key (PEM/DER) and send to server.
3.  **Authentication:** Receive encrypted OTP, decrypt it using Private Key (protected by PIN/Biometric), and return plaintext OTP.
4.  **Duress Mode:** Detect "Duress PIN" and modify the OTP to signal silent alarm.

---

## 🤖 2. Android Implementation (Kotlin)

### Dependencies (build.gradle)
Recommended libraries for modern Android security.
```kotlin
dependencies {
    implementation("androidx.security:security-crypto:1.1.0-alpha06") // Jetpack Security
    implementation("com.google.crypto.tink:tink-android:1.8.0") // Google Tink (Easy Crypto)
    implementation("androidx.biometric:biometric:1.1.0") // Biometric Auth
    implementation("com.squareup.retrofit2:retrofit:2.9.0") // Networking
}
```

### Class Structure: `Authenticator.kt`

```kotlin
import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager

class Authenticator(context: Context) {

    private val PREF_FILE = "indigo_mfa_prefs"
    private val TINK_KEYSET_NAME = "indigo_keyset"
    private var keysetHandle: KeysetHandle? = null

    init {
        HybridConfig.register()
        // Initialize or Load Keyset from Android Keystore
        val masterKeyUri = "android-keystore://master_key"

        keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(context, TINK_KEYSET_NAME, PREF_FILE)
            .withKeyTemplate(HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
            .withMasterKeyUri(masterKeyUri)
            .build()
            .keysetHandle
    }

    fun getPublicKeyPem(): String {
        // Extract public key from keysetHandle and convert to PEM format
        // Note: Tink exports raw keys, you may need a helper to wrap in PEM header
        val publicHandle = keysetHandle!!.publicKeysetHandle
        // ... Implementation to export public key bytes ...
        return pemString
    }

    fun decryptOtp(encryptedData: ByteArray, pin: String, storedPin: String, duressPin: String?): String {
        // 1. PIN Check (In production, use PIN to encrypt the Keyset itself!)
        val isDuress = (duressPin != null && pin == duressPin)
        if (pin != storedPin && !isDuress) {
            throw Exception("Invalid PIN")
        }

        // 2. Decrypt
        val hybridDecrypt = keysetHandle!!.getPrimitive(HybridDecrypt::class.java)
        val decryptedBytes = hybridDecrypt.decrypt(encryptedData, null)
        val otp = String(decryptedBytes, Charsets.UTF_8)

        // 3. Duress Logic
        return if (isDuress) {
            modifyForDuress(otp)
        } else {
            otp
        }
    }

    private fun modifyForDuress(otp: String): String {
        // Increment last digit (Mod 10)
        val lastDigit = otp.last().digitToInt()
        val newDigit = (lastDigit + 1) % 10
        return otp.dropLast(1) + newDigit
    }
}
```

---

## 🍏 3. iOS Implementation (Swift)

### Dependencies
No external dependencies required. Use native **CryptoKit** and **LocalAuthentication**.

### Class Structure: `Authenticator.swift`

```swift
import Foundation
import CryptoKit
import Security

class Authenticator {

    private let tag = "com.indigo.privateKey"

    // 1. Generate / Retrieve Key
    func getPrivateKey() -> P256.KeyAgreement.PrivateKey {
        // Check Keychain first
        if let storedKey = retrieveKeyFromKeychain() {
            return storedKey
        }

        // Generate New
        let privateKey = P256.KeyAgreement.PrivateKey()
        saveKeyToKeychain(key: privateKey)
        return privateKey
    }

    // 2. Export Public Key
    func getPublicKeyPEM() -> String {
        let key = getPrivateKey()
        let pubKey = key.publicKey
        let x963 = pubKey.x963Representation
        return x963.base64EncodedString() // Send as Base64/Hex to server
    }

    // 3. Decrypt OTP
    func decryptOTP(encryptedData: Data, userPin: String, actualPin: String, duressPin: String?) throws -> String {

        // PIN Validation logic here...
        let isDuress = (duressPin != null && userPin == duressPin)

        // Reconstruct Ephemeral Key & Ciphertext from encryptedData blob
        // (Assuming format: [Len][PubKey][Nonce][Cipher])
        // ... Parsing logic ...

        // Perform ECIES
        let privateKey = getPrivateKey()
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: "mfa-protocol-encryption".data(using: .utf8)!,
            outputByteCount: 32
        )

        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
        let otp = String(data: decryptedData, encoding: .utf8)!

        return isDuress ? modifyForDuress(otp) : otp
    }

    private func modifyForDuress(_ otp: String) -> String {
        guard let lastChar = otp.last, let digit = Int(String(lastChar)) else { return otp }
        let newDigit = (digit + 1) % 10
        return String(otp.dropLast(1)) + String(newDigit)
    }

    // ... Keychain Helper Methods ...
}
```

---

## 🔌 4. Networking Logic

The app needs two simple API calls.

### A. Register
*   **Endpoint:** `POST /register`
*   **Payload:** `{ "user_id": "email@corp.com", "public_key_pem_hex": "..." }`
*   **Action:** Send the PEM (hex encoded) after key generation.

### B. Authenticate
*   **Step 1: Poll/Receive Challenge** (via Push Notification or Manual Request)
    *   **Endpoint:** `POST /auth/challenge`
    *   **Response:** `{ "encrypted_challenge_hex": "..." }`
*   **Step 2: Decrypt Locally** (using `Authenticator.decryptOTP`)
*   **Step 3: Submit OTP**
    *   **Endpoint:** `POST /auth/verify`
    *   **Payload:** `{ "user_id": "...", "otp": "123456" }`
