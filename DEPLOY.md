# Deployment Guide (Linux LAMP)

This guide explains how to deploy the Decentralized MFA Backend on a Linux server and how to use the Client.

## Prerequisites

- Linux Server (Ubuntu/Debian/CentOS)
- Python 3.8+
- Apache or Nginx (for production reverse proxy)

## 1. Backend Deployment

### Setup Python Environment
1.  Navigate to the project root.
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Run with Gunicorn (Production)
Instead of running `python backend/app.py` directly, use `gunicorn` for better performance.

```bash
# Run server on port 5000 with 4 workers
gunicorn -w 4 -b 0.0.0.0:5000 backend.app:app
```

### Configure Apache (Reverse Proxy)
If you are running a LAMP stack, configure Apache to proxy requests to Gunicorn.

1.  Enable proxy modules:
    ```bash
    sudo a2enmod proxy proxy_http
    ```
2.  Edit your site config (e.g., `/etc/apache2/sites-available/000-default.conf`):
    ```apache
    <VirtualHost *:80>
        ServerName mfa.yourcompany.com

        ProxyPreserveHost On
        ProxyPass / http://127.0.0.1:5000/
        ProxyPassReverse / http://127.0.0.1:5000/
    </VirtualHost>
    ```
3.  Restart Apache: `sudo systemctl restart apache2`

## 2. Mobile Client Usage

The `mobile_client/` directory contains the Python source code that mimics the mobile app logic.

### Running the Simulator
1.  On your local machine (or the device simulating the phone):
    ```bash
    python mobile_client/main.py
    ```
2.  Enter your User ID (e.g., email).
3.  Select **1. Register** to send your public key to the server.
4.  Select **2. Login** to receive an encrypted challenge, decrypt it with your PIN, and verify.

### Porting to Real Mobile App
To build a real Android/iOS app:
1.  **Logic**: Copy `mfa_sdk/crypto.py` logic to Swift (iOS) or Kotlin (Android).
    *   Key Generation: SECP256R1
    *   Encryption: ECIES (ECDH + HKDF + AES-GCM)
2.  **API**: Use standard HTTP libraries to call `/register` and `/auth/challenge`.
