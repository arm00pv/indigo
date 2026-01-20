# Indigo MFA Mobile Client (Python CLI)

A reference implementation of the Indigo Authenticator for desktop environments (Linux/Windows/macOS) using a CLI.

## Features
*   **Secure Storage:** Stores private keys in `~/.indigo-mfa/device_key.pem` (encrypted at rest by OS file permissions, implementing key wrapping in future).
*   **Duress Mode:** Supports secondary Duress PIN for silent alarm triggering.
*   **Redundancy:** Supports multiple API endpoints for high availability.
*   **Push Simulation:** Listens on port 8089 to receive "Push" notifications from the server (localhost simulation).

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 mobile_client/main.py
```

### 1. Setup
*   **Option A: Manual:** Enter User ID. The app will generate a key pair and register it.
*   **Option B: Smart Code:** Select "Setup via Smart Code" and paste the JSON/Base64 code from the Admin Dashboard.

### 2. Authentication
*   Select "Login".
*   The app requests a challenge from the server.
*   Enter your PIN to decrypt the challenge.
*   (Optional) If you enter your **Duress PIN**, a modified OTP is sent to trigger the Silent Alarm.

### 3. Configuration
Config is stored in `~/.indigo-mfa/client_config.json`.

```json
{
  "user_id": "alice",
  "api_urls": ["http://primary.auth.com", "http://backup.auth.com"],
  "tenant_id": "default",
  "security": {
    "pin_hash": "sha256...",
    "duress_hash": "sha256..."
  }
}
```
