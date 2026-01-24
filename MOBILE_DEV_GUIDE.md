# Mobile App Development Guide

This guide provides technical specifications and implementation details for building the **Indigo MFA** mobile authenticator app.

---

## 📂 Quick Start: Deploying the Apps

We provide full reference implementations for all major platforms.

### 🦋 1. Flutter (Cross-Platform) - Recommended
This is the most complete client, featuring QR scanning, secure storage, and UI.

1.  **Prerequisites:** Install [Flutter SDK](https://docs.flutter.dev/get-started/install).
2.  **Open Project:**
    ```bash
    cd flutter_app
    flutter pub get
    ```
3.  **Run:**
    ```bash
    flutter run
    ```
    *   (Android emulator or iOS simulator required).

### 🤖 2. Android Native (Kotlin)
A native reference implementation for developers who prefer pure Kotlin.

1.  **Open Project:** Launch **Android Studio** and select `Open` -> navigate to `android_client/`.
2.  **Sync:** Allow Gradle to sync dependencies.
3.  **Run:** Click the "Run" button (Green Arrow) to deploy to a connected device/emulator.

### 🍏 3. iOS Native (Swift)
A native reference implementation using SwiftUI and CryptoKit.

1.  **Create Project:**
    *   Open **Xcode**.
    *   Select "Create a new Xcode project" -> "App".
    *   Name it `IndigoMFA`.
    *   Select "SwiftUI" for Interface.
2.  **Import Files:**
    *   Delete the default `ContentView.swift` and `IndigoMFAApp.swift`.
    *   Drag and drop the files from `ios_client/IndigoMFA/` (`ContentView.swift`, `CryptoManager.swift`, `IndigoMFAApp.swift`) into your Xcode project navigator.
3.  **Run:** Select a Simulator and click the "Play" button.

---

## 🏗️ Architecture Overview

The mobile app acts as a **Secure Enclave** that stores the user's Private Key. The server *never* sees this key.

### Core Responsibilities
1.  **Key Generation:** Create a secure ECC Key Pair (SECP256R1 / NIST P-256).
2.  **Registration:** Export Public Key (PEM/DER) and send to server.
3.  **Authentication:** Receive encrypted OTP, decrypt it using Private Key (protected by PIN/Biometric), and return plaintext OTP.
4.  **Duress Mode:** Detect "Duress PIN" and modify the OTP to signal silent alarm.
5.  **Context Awareness:** Decrypt and display transaction context (e.g., "Transfer $500") for user verification.

---

## 🔌 Networking Logic (All Platforms)

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

## 🚨 Duress Mode Implementation

If the user enters their **Duress PIN** instead of the standard PIN:
1.  Decrypt the OTP as normal.
2.  **Modify the OTP**: Increment the last digit by 1 (modulo 10).
    *   `123456` -> `123457`
    *   `123459` -> `123450`
3.  Submit the modified OTP.
4.  The server validates it as "DURESS" and triggers the Silent Alarm (Webhook/Email).
