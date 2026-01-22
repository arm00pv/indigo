# Mobile App Development Guide

This guide provides technical specifications and implementation details for building the **Indigo MFA** mobile authenticator app.

---

## 📂 Reference Implementations

We provide full reference implementations for all major platforms in the repository:

*   **Flutter (Cross-Platform):** `flutter_app/` (Production Ready)
*   **Android (Kotlin):** `android_client/` (Reference)
*   **iOS (Swift):** `ios_client/` (Reference)

---

## 🏗️ 1. Architecture Overview

The mobile app acts as a **Secure Enclave** that stores the user's Private Key. The server *never* sees this key.

### Core Responsibilities
1.  **Key Generation:** Create a secure ECC Key Pair (SECP256R1 / NIST P-256).
2.  **Registration:** Export Public Key (PEM/DER) and send to server.
3.  **Authentication:** Receive encrypted OTP, decrypt it using Private Key (protected by PIN/Biometric), and return plaintext OTP.
4.  **Duress Mode:** Detect "Duress PIN" and modify the OTP to signal silent alarm.
5.  **Context Awareness:** Decrypt and display transaction context (e.g., "Transfer $500") for user verification.

---

## 🤖 2. Android Implementation (Kotlin)

### Setup
1.  Open `android_client/` in **Android Studio**.
2.  Sync Gradle files.
3.  Run on Emulator or Device.

### Dependencies
The reference implementation uses standard Android Crypto APIs (KeyStore, Cipher) to ensure maximum compatibility without external crypto libraries, though Google Tink is recommended for production apps.

### Key Logic: `CryptoManager.kt`
The `CryptoManager` object handles the ECIES decryption pipeline manually to match the backend's format:
1.  **Parse Blob:** Splits the encrypted payload into `[Ephemeral PubKey (65b)] [IV (12b)] [Ciphertext]`.
2.  **Load Ephemeral Key:** Constructs an X.509 spec from the raw X9.62 point.
3.  **ECDH:** Derives shared secret using `KeyAgreement`.
4.  **HKDF:** Derives AES key using `HmacSHA256` with 32 null bytes as salt.
5.  **AES-GCM:** Decrypts the OTP.

---

## 🍏 3. iOS Implementation (Swift)

### Setup
1.  Open `ios_client/` (or create a new project and drag in the files) in **Xcode**.
2.  Ensure Target is set to iOS 14+.
3.  Build and Run.

### Dependencies
Uses native `CryptoKit` for all operations.

### Key Logic: `CryptoManager.swift`
1.  **ECIES:** Uses `P256.KeyAgreement.PrivateKey` to perform ECDH.
2.  **HKDF:** Uses `sharedSecret.hkdfDerivedSymmetricKey` matching backend parameters.
3.  **AES-GCM:** Uses `AES.GCM.open`.

---

## 🦋 4. Flutter Implementation (Production)

The `flutter_app/` directory contains a complete application with QR scanning, secure storage, and UI.

### Build
```bash
cd flutter_app
flutter pub get
flutter run
```

### Key Libraries
- `cryptography`: Handles ECIES/HKDF.
- `flutter_secure_storage`: secure enclave abstraction.
- `mobile_scanner`: QR code reading.

---

## 🔌 5. Networking Logic (All Platforms)

Ensure `X-Tenant-ID` header is sent with every request.

### A. Register
*   **Endpoint:** `POST /register`
*   **Payload:** `{ "user_id": "email@corp.com", "public_key_pem_hex": "..." }`
*   **Action:** Send the PEM (hex encoded) after key generation.

### B. Authenticate
*   **Step 1: Request Challenge**
    *   **Endpoint:** `POST /auth/challenge`
    *   **Payload:** `{ "user_id": "..." }`
    *   **Response:** `{ "encrypted_challenge_hex": "..." }`
*   **Step 2: Decrypt Locally**
    *   Verify Context if present (JSON payload).
*   **Step 3: Submit OTP**
    *   **Endpoint:** `POST /auth/verify`
    *   **Payload:** `{ "user_id": "...", "otp": "123456" }`

---

## 🚨 6. Duress Mode Implementation

If the user enters their **Duress PIN** instead of the standard PIN:
1.  Decrypt the OTP as normal.
2.  **Modify the OTP**: Increment the last digit by 1 (modulo 10).
    *   `123456` -> `123457`
    *   `123459` -> `123450`
3.  Submit the modified OTP.
4.  The server validates it as "DURESS" and triggers the Silent Alarm.
