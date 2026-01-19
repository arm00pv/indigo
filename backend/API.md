# Indigo MFA API Reference

## Authentication

All Admin endpoints require authentication via headers.
*   **Tenant Admin:** `X-Admin-Key: <api_key>`
*   **System Admin:** `X-Master-Key: <master_key>`

---

## User Endpoints

### Register User
Registers a new user device with a public key.

*   **URL:** `/register`
*   **Method:** `POST`
*   **Headers:** `X-Tenant-ID` (Optional, defaults to 'default')
*   **Body:**
    ```json
    {
        "user_id": "alice@example.com",
        "public_key_pem_hex": "3059301306072a8648ce3d0201...",
        "push_endpoint": "https://fcm.googleapis.com/..."
    }
    ```
*   **Response (201):**
    ```json
    {
        "message": "User registered successfully.",
        "backup_codes": ["code1", "code2", ...]
    }
    ```

### Get Challenge
Request an encrypted OTP challenge.

*   **URL:** `/auth/challenge`
*   **Method:** `POST`
*   **Body:**
    ```json
    {
        "user_id": "alice@example.com",
        "context": "Login to VPN"
    }
    ```
*   **Response (200):**
    ```json
    {
        "encrypted_challenge_hex": "abc123...",
        "message": "Challenge sent."
    }
    ```

### Verify OTP
Submit the decrypted OTP for verification.

*   **URL:** `/auth/verify`
*   **Method:** `POST`
*   **Body:**
    ```json
    {
        "user_id": "alice@example.com",
        "otp": "123456"
    }
    ```
*   **Response (200):**
    ```json
    {
        "status": "success",
        "message": "Authentication Successful"
    }
    ```
*   **Response (403):** If account is locked or Duress signal triggered (silent success for Duress).

---

## Admin Endpoints

### System Health
Check the operational status of the backend.

*   **URL:** `/admin/system/health`
*   **Method:** `GET`
*   **Headers:** `X-Admin-Key`
*   **Response (200):**
    ```json
    {
        "status": "healthy",
        "checks": [
            {"name": "Database", "status": "pass"},
            {"name": "Admin Keys", "status": "pass", "count": 1},
            {"name": "Permission: logs", "status": "pass"}
        ]
    }
    ```

### Lock User
Manually soft-lock a user.

*   **URL:** `/admin/user/<user_id>/lock`
*   **Method:** `POST`

### Unlock User
Unlock a user account.

*   **URL:** `/admin/user/<user_id>/unlock`
*   **Method:** `POST`

### Global Settings
Read or update system policies.

*   **URL:** `/admin/settings`
*   **Method:** `GET` / `POST`
*   **Body (POST):**
    ```json
    {
        "policy_max_failures_soft_lock": "10",
        "policy_max_failures_temp_lock": "5",
        "policy_temp_lock_duration_seconds": "900",
        "business_hours_enabled": "false"
    }
    ```

### Notification Channels
Manage alert destinations (Email/Webhook).

*   **URL:** `/admin/notifications`
*   **Method:** `GET` / `POST`
*   **Body (POST - Webhook):**
    ```json
    {
        "type": "WEBHOOK",
        "events": ["DURESS", "ABUSE"],
        "config": {"url": "https://hooks.slack.com/..."}
    }
    ```
*   **Body (POST - Email):**
    ```json
    {
        "type": "EMAIL",
        "events": ["DURESS"],
        "config": {
            "email": "security@example.com",
            "host": "smtp.gmail.com",
            "port": 465,
            "encryption": "SSL",
            "user": "me@gmail.com",
            "pass": "secret"
        }
    }
    ```

### Export Logs
Download audit logs.

*   **URL:** `/admin/export/logs`
*   **Method:** `GET`
*   **Params:** `format=csv|json`, `filter=all|threats|admin|errors`

### Provisioning
Generate QR codes or Smart Codes for enrollment.

*   **URL:** `/admin/provision/qrcode`
*   **Method:** `POST`
*   **Body:** `{"user_id": "alice"}`
