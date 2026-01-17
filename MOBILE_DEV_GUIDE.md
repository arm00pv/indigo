# Mobile App Development Guide

This guide provides technical specifications and implementation details for building the **Indigo MFA** mobile authenticator app. It covers the reference **Flutter** implementation as well as specifications for native **Android (Kotlin)** and **iOS (Swift)** apps.

---

## 🏗️ 1. Architecture Overview

The mobile app acts as a **Secure Enclave** that stores the user's Private Key. The server *never* sees this key.

### Core Responsibilities
1.  **Key Generation:** Create a secure ECC Key Pair (SECP256R1).
2.  **Registration:** Export Public Key (PEM/DER) and send to server.
3.  **Authentication:** Receive encrypted OTP, decrypt it using Private Key (protected by PIN/Biometric), and return plaintext OTP.
4.  **Duress Mode:** Detect "Duress PIN" and modify the OTP to signal silent alarm.
5.  **Context Awareness:** Decrypt and display transaction context (e.g., "Transfer $500") for user verification.

---

## 🦋 2. Flutter Implementation (Reference App)

This section details how to build and deploy the Flutter reference client found in `flutter_app/`.

### Step 1: Initialize Project
If starting from scratch:
```bash
flutter create indigo_authenticator
cd indigo_authenticator
```

### Step 2: Add Dependencies
Update `pubspec.yaml` to include necessary packages for Crypto, Storage, Networking, and QR Scanning.

```yaml
dependencies:
  flutter:
    sdk: flutter
  # Networking
  http: ^1.1.0
  # Security & Storage
  flutter_secure_storage: ^9.0.0
  cryptography: ^2.5.0
  # QR Code Scanning
  mobile_scanner: ^3.5.5
  permission_handler: ^11.0.0
```
Run `flutter pub get` to install.

### Step 3: Configure Permissions
**Android (`android/app/src/main/AndroidManifest.xml`):**
```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.CAMERA"/>
```

**iOS (`ios/Runner/Info.plist`):**
```xml
<key>NSCameraUsageDescription</key>
<string>Camera permission is required for QR Code scanning.</string>
```

### Step 4: Cryptography Implementation (`lib/crypto.dart`)
The core security relies on ECIES (P-256 + HKDF + AES-GCM). Ensure the HKDF parameters match the backend:
- **Salt/Nonce**: 32 bytes of zeros.
- **Info**: `b'mfa-protocol-encryption'`.

```dart
// Snippet from lib/crypto.dart
static Future<List<int>> decrypt(SimpleKeyPair keyPair, List<int> encryptedBlob) async {
    // ... Extract Ephemeral Key, IV, Tag, Ciphertext ...

    // Derive Shared Secret (ECDH)
    final sharedSecret = await ecdh.sharedSecretKey(keyPair: keyPair, remotePublicKey: ephemeralKey);
    final sharedBytes = await sharedSecret.extractBytes();

    // Derive AES Key (HKDF)
    // CRITICAL: Must match backend parameters
    final aesKeyMaterial = await hkdf.deriveKey(
      secretKey: SecretKey(sharedBytes),
      nonce: List.filled(32, 0), // Salt = 32 null bytes
      info: utf8.encode('mfa-protocol-encryption'),
    );

    // Decrypt (AES-GCM)
    // ...
}
```

### Step 5: Secure Storage & Key Management
Use `flutter_secure_storage` to persist sensitive data.
- **Private Key**: Serialize and store in secure storage (Keychain/Keystore).
- **App Configuration**: Store `user_id`, `tenant_id`, and `base_url`.

### Step 6: Duress & Context Logic
Implement the logic to handle special payloads and PINs.

**Context-Awareness:**
```dart
// Check if decrypted payload is JSON
if (plaintext.trim().startsWith('{')) {
    final data = jsonDecode(plaintext);
    String context = data['context'];
    // Display Alert Dialog with context
}
```

**Duress Mode:**
```dart
if (enteredPin == duressPin) {
    // Mod 10 Logic to signal distress
    int lastDigit = int.parse(otp.substring(otp.length - 1));
    int newLast = (lastDigit + 1) % 10;
    otp = otp.substring(0, otp.length - 1) + newLast.toString();
}
```

---

## 🤖 3. Android Implementation (Kotlin)

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
// ...

class Authenticator(context: Context) {
    // ... Keyset Management ...

    fun decryptOtp(encryptedData: ByteArray, pin: String, storedPin: String, duressPin: String?): String {
        // 1. PIN Check
        val isDuress = (duressPin != null && pin == duressPin)
        if (pin != storedPin && !isDuress) throw Exception("Invalid PIN")

        // 2. Decrypt
        val hybridDecrypt = keysetHandle!!.getPrimitive(HybridDecrypt::class.java)
        val decryptedBytes = hybridDecrypt.decrypt(encryptedData, null)
        val plaintext = String(decryptedBytes, Charsets.UTF_8)

        // 3. Context & OTP Extraction (JSON Parsing)
        // ...

        // 4. Duress Logic
        return if (isDuress) modifyForDuress(otp) else otp
    }

    private fun modifyForDuress(otp: String): String {
        val lastDigit = otp.last().digitToInt()
        val newDigit = (lastDigit + 1) % 10
        return otp.dropLast(1) + newDigit
    }
}
```

---

## 🍏 4. iOS Implementation (Swift)

### Dependencies
No external dependencies required. Use native **CryptoKit** and **LocalAuthentication**.

### Class Structure: `Authenticator.swift`

```swift
import CryptoKit
import Security

class Authenticator {

    // ... Key Generation & Retrieval ...

    func decryptOTP(encryptedData: Data, userPin: String, actualPin: String, duressPin: String?) throws -> String {

        let isDuress = (duressPin != null && userPin == duressPin)

        // ... Reconstruct Ephemeral Key & Ciphertext ...

        // Perform ECIES
        let privateKey = getPrivateKey()
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(count: 32), // 32 null bytes
            sharedInfo: "mfa-protocol-encryption".data(using: .utf8)!,
            outputByteCount: 32
        )

        // ... AES-GCM Decrypt ...
        let plaintext = String(data: decryptedData, encoding: .utf8)!

        // ... JSON Parsing for Context ...

        return isDuress ? modifyForDuress(otp) : otp
    }

    private func modifyForDuress(_ otp: String) -> String {
        guard let lastChar = otp.last, let digit = Int(String(lastChar)) else { return otp }
        let newDigit = (digit + 1) % 10
        return String(otp.dropLast(1)) + String(newDigit)
    }
}
```

---

## 🔌 5. Networking Logic

The app needs the following API calls. Ensure `X-Tenant-ID` header is sent with every request.

### A. Register
*   **Endpoint:** `POST /register`
*   **Payload:** `{ "user_id": "email@corp.com", "public_key_pem_hex": "..." }`
*   **Action:** Send the PEM (hex encoded) after key generation.

### B. Authenticate
*   **Step 1: Request Challenge**
    *   **Endpoint:** `POST /auth/challenge`
    *   **Payload:** `{ "user_id": "..." }`
    *   **Response:** `{ "encrypted_challenge_hex": "..." }`
*   **Step 2: Decrypt Locally** (using `Authenticator.decrypt`)
    *   Verify Context if present.
*   **Step 3: Submit OTP**
    *   **Endpoint:** `POST /auth/verify`
    *   **Payload:** `{ "user_id": "...", "otp": "123456" }`
