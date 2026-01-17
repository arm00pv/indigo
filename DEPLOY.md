# Indigo MFA Deployment & Implementation Guide

This guide covers the deployment, configuration, and client implementation for **Indigo MFA**, a high-security, decentralized authentication system featuring Duress Mode, Adaptive Security Policies, and real-time forensics.

---

## 🏗️ 1. Backend Deployment

### Smart Installer (Recommended)
Use `scripts/install_lamp.sh` for an automated setup on Ubuntu/Debian.

#### Usage
```bash
./scripts/install_lamp.sh -d auth.example.com -e admin@example.com -y
```
**Flags:**
- `-d`: Domain Name.
- `-e`: Email for SSL (Let's Encrypt).
- `-y`: Non-interactive mode (Yes to all).
- `-u`: Skip UFW firewall configuration.
- `-s`: Skip SSL configuration.

### A. Linux LAMP Server (Apache + Gunicorn)
Standard deployment for a single Linux server (Ubuntu/Debian/CentOS).

#### 1. Prerequisites
*   Python 3.8+
*   Apache HTTP Server
*   `pip` and `venv`

#### 2. Installation
Navigate to your project directory on the server:
```bash
cd /var/www/indigo-mfa
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 3. Configure Systemd
Create a service file: `/etc/systemd/system/indigo-mfa.service`

```ini
[Unit]
Description=Indigo MFA Backend
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/indigo-mfa
Environment="PATH=/var/www/indigo-mfa/venv/bin"
Environment="PYTHONPATH=/var/www/indigo-mfa"
# Alerting (Optional)
Environment="ALERT_WEBHOOK_URL=https://your-slack-webhook-url"
ExecStart=/var/www/indigo-mfa/venv/bin/gunicorn --workers 3 --bind unix:indigo.sock -m 007 backend.app:app

[Install]
WantedBy=multi-user.target
```
Enable: `sudo systemctl enable --now indigo-mfa`

#### 4. Configure Apache (Reverse Proxy)
File: `/etc/apache2/sites-available/indigo.conf`

```apache
<VirtualHost *:80>
    ServerName auth.yourcompany.com

    # Proxy to Gunicorn Socket
    ProxyPreserveHost On
    ProxyPass / unix:/var/www/indigo-mfa/indigo.sock|http://127.0.0.1/
    ProxyPassReverse / unix:/var/www/indigo-mfa/indigo.sock|http://127.0.0.1/

    ErrorLog ${APACHE_LOG_DIR}/indigo_error.log
    CustomLog ${APACHE_LOG_DIR}/indigo_access.log combined
</VirtualHost>
```

---

### B. Docker & Kubernetes

#### Docker Compose
```bash
# Edit docker-compose.yml to set ALERT_WEBHOOK_URL
docker-compose up -d
```

#### Kubernetes
1.  Edit `k8s/deployment.yaml` to set your `ALERT_WEBHOOK_URL`.
2.  Apply manifests:
    ```bash
    kubectl apply -f k8s/deployment.yaml
    kubectl apply -f k8s/service.yaml
    ```

---

## 🛡️ 2. Security Features & Configuration

### A. Real-Time Alerts (Webhooks)
Indigo MFA can send JSON POST requests to a webhook (Slack, Discord, PagerDuty) for critical events:
*   **DURESS:** User entered a panic code.
*   **ABUSE:** User reached the 10-failure soft-lock threshold.

**Setup:** Set the `ALERT_WEBHOOK_URL` environment variable.

### B. Adaptive Policy Engine
Managed via the Dashboard (`/dashboard`) or API.

1.  **Time-Fencing (Business Hours):**
    *   Toggle to restrict authentication to **08:00 - 18:00** (Server Time).
    *   Useful for corporate environments to reduce off-hour attack surface.
    *   *Note:* This applies globally based on the server's timezone.
2.  **IP Blacklisting:**
    *   Block specific IPs or Subnets (CIDR, e.g., `192.168.1.0/24`).
    *   Requests from these IPs are rejected immediately (403 Forbidden).

### C. Abuse Thresholds
*   **5 Failures:** Account locked for 15 minutes (Temp Lock).
*   **10 Failures:** Account **Soft Locked**. Requires Admin intervention (Unlock button in Dashboard) to restore access.

---

## 📱 3. Mobile Client Implementation

The client app acts as the Secure Enclave. It holds the Private Key and performs decryption.

### Core Specs
*   **Curve:** SECP256R1 (NIST P-256)
*   **Encryption:** ECIES (ECDH + HKDF + AES-256-GCM)

### 🚨 Duress Mode Implementation (Critical)
To support **Stealth Auth**, the client must handle a secondary "Duress PIN".

**Logic:**
1.  If User enters **Standard PIN**: Decrypt OTP. Send to Server.
2.  If User enters **Duress PIN**:
    *   Decrypt OTP.
    *   **Modify the OTP:** Increment the last digit by 1 (modulo 10).
    *   *Example:* `123456` -> `123457`. `123459` -> `123450`.
    *   Send modified OTP to Server.

**Why?** The server checks both the original and modified OTP. If the modified one matches, it authenticates the user but triggers a **Silent Alarm**.

### Swift (iOS) Snippet
```swift
func getDuressOtp(originalOtp: String) -> String {
    guard let lastChar = originalOtp.last, let lastDigit = Int(String(lastChar)) else { return originalOtp }
    let newDigit = (lastDigit + 1) % 10
    return String(originalOtp.dropLast()) + String(newDigit)
}

// In your Auth Flow:
let decryptedOtp = decrypt(encryptedData, key) // ECIES decryption
if pin == userDuressPin {
    let stealthOtp = getDuressOtp(originalOtp: decryptedOtp)
    submitToServer(stealthOtp)
} else {
    submitToServer(decryptedOtp)
}
```

### Kotlin (Android) Snippet
```kotlin
fun getDuressOtp(otp: String): String {
    if (otp.isEmpty() || !otp.all { it.isDigit() }) return otp
    val lastDigit = otp.last().toString().toInt()
    val newDigit = (lastDigit + 1) % 10
    return otp.dropLast(1) + newDigit
}
```

---

## 🔧 4. Admin API Reference

The backend provides a REST API for management.

| Method | Endpoint | Description | Payload |
| :--- | :--- | :--- | :--- |
| `POST` | `/admin/user/<id>/lock` | Manually Soft Lock a user | - |
| `POST` | `/admin/user/<id>/unlock` | Unlock a user | - |
| `POST` | `/admin/settings` | Update Global Settings | `{"business_hours_enabled": true}` |
| `POST` | `/admin/policy/blacklist` | Block an IP/CIDR | `{"cidr": "1.2.3.4", "reason": "Spam"}` |
| `DELETE` | `/admin/policy/blacklist` | Unblock an IP | `{"cidr": "1.2.3.4"}` |
| `GET` | `/admin/export/logs` | Download Audit Logs | Params: `format=csv|json`, `filter=all|threats` |
