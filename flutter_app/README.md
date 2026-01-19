# Indigo MFA Flutter Client

A Reference Implementation of the Indigo MFA Mobile Authenticator using Flutter.

## Features
*   **Secure Storage:** Uses `flutter_secure_storage` (Keychain/Keystore) to protect the Private Key.
*   **Biometrics:** Optional biometric gating (future).
*   **Duress Mode:** Supports a secondary "Duress PIN" that triggers a silent alarm on the server.
*   **Offline Capable:** Decryption happens locally; network is only needed to receive the challenge (Push) or submit the OTP.

## Setup

### 1. Prerequisites
*   Flutter SDK (3.0+)
*   Android Studio / Xcode

### 2. Configuration
Edit `lib/main.dart` if you need to point to a specific hardcoded backend URL (default is localhost `10.0.2.2` for Android emulator).

### 3. Running
```bash
flutter pub get
flutter run
```

## Usage Flow

1.  **Enrollment:**
    *   Open App -> "Setup via QR / Smart Code".
    *   Scan QR from Admin Dashboard or paste the Base64 Smart Code.
    *   **Set PIN:** Create a standard access PIN.
    *   **Set Duress PIN:** Create a distress PIN (must be different).

2.  **Authentication:**
    *   Receive Push Notification OR manually fetch challenge.
    *   App prompts for PIN.
    *   **Enter Standard PIN:** App decrypts OTP and submits it. (Server: SUCCESS)
    *   **Enter Duress PIN:** App decrypts OTP, modifies last digit, and submits it. (Server: DURESS / Silent Alarm)

## Security Implementation

### PIN Verification
PINs are **not** stored in plaintext.
*   On Setup: `SHA-256(PIN)` is stored in Secure Storage.
*   On Verify: `SHA-256(Input)` is compared against the stored hash.

### Duress Logic
```dart
// Pseudo-code
if (hash(input) == stored_duress_pin_hash) {
    otp = decrypt(challenge);
    duress_otp = modify_last_digit(otp);
    submit(duress_otp); // Triggers alarm
}
```
