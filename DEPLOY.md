# Indigo MFA Deployment Guide

This comprehensive guide covers deploying the Indigo MFA Backend on various platforms (Linux LAMP, Docker, Kubernetes) and provides implementation details for building native mobile clients (Swift, Kotlin).

---

## 🏗️ 1. Backend Deployment

### A. Linux LAMP Server (Apache + Gunicorn)
This is the standard deployment for a single Linux server (Ubuntu/Debian/CentOS).

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

#### 3. Configure Systemd (Keep it running)
Create a service file to manage the Gunicorn process automatically.
**File:** `/etc/systemd/system/indigo-mfa.service`

```ini
[Unit]
Description=Gunicorn instance to serve Indigo MFA
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/indigo-mfa
Environment="PATH=/var/www/indigo-mfa/venv/bin"
Environment="PYTHONPATH=/var/www/indigo-mfa"
ExecStart=/var/www/indigo-mfa/venv/bin/gunicorn --workers 3 --bind unix:indigo.sock -m 007 backend.app:app

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl start indigo-mfa
sudo systemctl enable indigo-mfa
```

#### 4. Configure Apache (Reverse Proxy)
Configure Apache to proxy traffic to the socket created by Gunicorn.

**File:** `/etc/apache2/sites-available/indigo.conf`

```apache
<VirtualHost *:80>
    ServerName auth.yourcompany.com

    ProxyPreserveHost On
    ProxyPass / unix:/var/www/indigo-mfa/indigo.sock|http://127.0.0.1/
    ProxyPassReverse / unix:/var/www/indigo-mfa/indigo.sock|http://127.0.0.1/

    ErrorLog ${APACHE_LOG_DIR}/indigo_error.log
    CustomLog ${APACHE_LOG_DIR}/indigo_access.log combined
</VirtualHost>
```
Enable site and modules: `sudo a2enmod proxy proxy_http && sudo a2ensite indigo && sudo systemctl restart apache2`

---

### B. Docker Deployment
For containerized environments or quick testing.

#### 1. Build and Run
```bash
docker build -t indigo-mfa .
docker run -d -p 5000:5000 indigo-mfa
```

#### 2. Using Docker Compose
```bash
docker-compose up -d
```
The API will be available at `http://localhost:5000`.

---

### C. Kubernetes (K8s) Cluster
For high availability and scaling.

#### 1. Deploy
Apply the provided manifests in the `k8s/` directory.

```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

#### 2. Scaling
To handle more traffic, scale the replicas:
```bash
kubectl scale deployment indigo-mfa-backend --replicas=5
```
*Note: In production, ensure you replace the SQLite DB with a centralized PostgreSQL/MySQL database so all pods share the same data.*

---

## 📱 2. Mobile Client Implementation Guide

To use Indigo MFA, you need to build a mobile app that acts as the Authenticator. The core logic relies on **Elliptic Curve Cryptography (ECC)**.

### Core Cryptography Specs
*   **Curve:** SECP256R1 (NIST P-256) / Prime256v1
*   **Encryption Scheme:** ECIES (Elliptic Curve Integrated Encryption Scheme)
    *   **Key Agreement:** ECDH (Elliptic Curve Diffie-Hellman)
    *   **KDF:** HKDF-SHA256
    *   **Symmetric Encryption:** AES-256-GCM

### A. iOS App (Swift)
Use the native `CryptoKit` framework (available iOS 13+).

**1. Generate Key Pair & Export Public Key**
```swift
import CryptoKit

// Generate Private Key (Store this securely in Keychain)
let privateKey = P256.KeyAgreement.PrivateKey()
let publicKey = privateKey.publicKey

// Export Public Key as PEM/DER for the server
let x963Representation = publicKey.x963Representation
// Convert x963 to PEM format or send raw bytes depending on your server adaptation
```

**2. Decrypt Challenge (ECIES)**
Swift's `CryptoKit` supports `AES.GCM` and `SharedSecret`.

```swift
func decryptChallenge(encryptedData: Data, privateKey: P256.KeyAgreement.PrivateKey) throws -> String {
    // 1. Parse encryptedData to extract Ephemeral Public Key, Nonce, and Ciphertext
    // (Assume data structure: [Len][Pub][Nonce][Cipher])

    // 2. Perform ECDH to get Shared Secret
    let ephemeralPub = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPubBytes)
    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPub)

    // 3. Derive Symmetric Key (HKDF)
    let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data(),
        sharedInfo: "mfa-protocol-encryption".data(using: .utf8)!,
        outputByteCount: 32
    )

    // 4. Decrypt (AES-GCM)
    let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonceData), ciphertext: ciphertext, tag: tag)
    let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)

    return String(data: decryptedData, encoding: .utf8)!
}
```

### B. Android App (Kotlin)
Use `Google Tink` (recommended) or `Bouncy Castle`.

**Using Google Tink (Easier):**
Tink handles ECIES complexity automatically.

```kotlin
// build.gradle
implementation 'com.google.crypto.tink:tink-android:1.7.0'
```

```kotlin
import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.hybrid.HybridConfig

// 1. Initialize
HybridConfig.register()

// 2. Generate Keys
val privateKeysetHandle = KeysetHandle.generateNew(HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
val publicKeysetHandle = privateKeysetHandle.publicKeysetHandle

// 3. Decrypt
val hybridDecrypt = privateKeysetHandle.getPrimitive(HybridDecrypt::class.java)
val decrypted = hybridDecrypt.decrypt(encryptedData, null) // Context info if needed
val otp = String(decrypted, Charsets.UTF_8)
```
*Note: Ensure the Server's ECIES parameters match Tink's default or configure Tink to match the Python `cryptography` library parameters.*

**Using Java Cryptography Architecture (Standard):**
1.  **KeyPairGenerator** with `EC` and `secp256r1`.
2.  **KeyAgreement** (ECDH) to derive shared secret.
3.  **HKDF** (Standard logic).
4.  **Cipher** (`AES/GCM/NoPadding`).

---

## 🔒 Security Best Practices
1.  **Secure Storage**:
    *   **iOS**: Always store the Private Key in the **Keychain**.
    *   **Android**: Use the **Android Keystore System**.
2.  **PIN Protection**:
    *   Do not just check `if (pin == input)`. Use the PIN to **encrypt the Private Key** at rest, or use the Biometric API (FaceID/TouchID) to gate access to the Keychain item.
3.  **SSL/TLS**: Always serve the Backend API over HTTPS.
