# Indigo MFA

**Indigo MFA** is a decentralized, high-security Multi-Factor Authentication system designed to replace SMS and centralized identity providers with a self-hosted, encrypted-by-default architecture.

## 🚀 Key Features

*   **🚫 No SMS/MMS**: Uses ECIES (Elliptic Curve Integrated Encryption Scheme) over data channels.
*   **🛡️ Duress Mode**: "Stealth Auth" capability. Enter a distress PIN to authenticate normally while silently triggering a critical security alert via Webhooks or Encrypted Email.
*   **🏢 Multi-Tenancy**: Host multiple organizations on a single deployment with strict data isolation.
*   **🔌 High Availability**: Cluster-ready architecture with PostgreSQL Replication and Load Balancing support.
*   **🧠 Adaptive Security**: Time-Fencing (Business Hours), IP Blacklisting, and Abuse Thresholds (Soft Locking).
*   **🔍 Forensics**: Detailed audit logs with IP tracking and real-time monitoring.

## 📦 Getting Started

### 1. Deployment
Read the **[Deployment Guide](DEPLOY.md)** for detailed instructions.

#### 🚀 First Run (Setup Wizard)
When you first deploy the application (e.g., via DigitalOcean App Platform or Docker), the system starts in **Uninitialized Mode**.
1.  Access your deployment URL (e.g., `https://your-app.com/`).
2.  You will see a **Setup Wizard** instead of a Login screen.
3.  Create your **Admin API Key** (minimum 8 characters).
4.  The system will initialize and log you in automatically.

*Note: If you provide an `ADMIN_API_KEY` environment variable during deployment, the Wizard is skipped.*

**Lost your key?** Read **[Troubleshooting: Reset Database](docs/TROUBLESHOOTING.md)** to perform a hard reset via `RESET_DB=true`.

### 2. Client Development
Read the **[Mobile Developer Guide](MOBILE_DEV_GUIDE.md)** to build the native Authenticator app for iOS (Swift) and Android (Kotlin) or use the Flutter Reference App.

## 📚 Guides
- **[Enterprise Guide](docs/ENTERPRISE_GUIDE.md)**: For IT Admins managing multi-tenant clusters.
- **[User Guide](docs/USER_GUIDE.md)**: For end-users enrolling via Smart Code/QR.
- **[Validator Guide](docs/VALIDATOR_GUIDE.md)**: For system operators and auditors.
- **[API Reference](backend/API.md)**: Full REST API documentation.
- **[Knowledge Base](docs/KNOWLEDGE_BASE.md)**: Troubleshooting guide for common issues.

## 🔧 Architecture

The system consists of three main components:
1.  **Backend API (Flask)**: Handles registration, challenge generation (encrypted), and verification. Stateless and scalable.
2.  **Database (PostgreSQL/SQLite)**: Stores user public keys, logs, and security policies.
3.  **Mobile Client (Flutter/Native)**: Holds the Private Key in the device's Secure Enclave/Keystore and performs decryption.

## 🤝 Contributing

Please read `CHANGELOG.md` to see the project history.

## 📄 License

MIT
