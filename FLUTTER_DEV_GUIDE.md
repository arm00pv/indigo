# Indigo MFA - Flutter Developer Guide

This guide details the implementation of the Indigo Authenticator client in Flutter (Dart).

## Project Structure
- `lib/main.dart`: UI logic, configuration, and Auth Flow.
- `lib/crypto.dart`: ECIES implementation (P-256 + AES-GCM).
- `lib/api.dart`: HTTP Client interacting with the Indigo Backend.

## Dependencies
Add to `pubspec.yaml`:
```yaml
dependencies:
  cryptography: ^2.5.0
  flutter_secure_storage: ^9.0.0
  http: ^1.1.0
```

## Cryptography (ECIES)
Indigo uses a standard ECIES flow:
1.  **ECDH**: Derive shared secret using Client Private Key (P-256) and Server Ephemeral Public Key.
2.  **HKDF**: Derive 32-byte AES key from shared secret (SHA-256).
3.  **AES-GCM**: Decrypt the payload (OTP + Context).

### Implementation Details
See `lib/crypto.dart` for the exact reference implementation using the `cryptography` package.
The `getPublicKeyPem` function manually constructs the X.509 SubjectPublicKeyInfo header for P-256 curves to ensure compatibility with the Python backend.

## Security Features

### Duress Mode (Stealth Auth)
If the user enters the **Duress PIN** (configured during setup, e.g., "9999"), the client MUST:
1.  Decrypt the OTP as normal.
2.  Modify the last digit: `(last_digit + 1) % 10`.
3.  Send the modified OTP to the backend.
This signals the backend to trigger a silent alarm (Webhook/Log) while returning a successful authentication response to the user.

### Context-Aware Authentication (WYSIWYS)
The decrypted payload may be a JSON string: `{"otp": "123456", "context": "Transfer $500"}`.
If `context` is present, you **MUST** display it to the user in a modal and require explicit confirmation before sending the OTP. This prevents "blind signing" attacks.

## Setup & Enrollment
Users can enroll by:
1.  Scanning a QR Code from the Dashboard.
2.  Pasting a "Smart Code" (Base64 encoded JSON) into the app.

The payload structure:
```json
{
  "url": "https://mfa.example.com",
  "tenant_id": "uuid-...",
  "user_id": "employee@example.com"
}
```
