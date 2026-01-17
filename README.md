# Indigo MFA

**Indigo MFA** is a decentralized, high-security Multi-Factor Authentication system designed to replace SMS and centralized identity providers with a self-hosted, encrypted-by-default architecture.

## 🚀 Key Features

*   **🚫 No SMS/MMS**: Uses ECIES (Elliptic Curve Integrated Encryption Scheme) over data channels.
*   **🛡️ Duress Mode**: "Stealth Auth" capability. Enter a distress PIN to authenticate normally while silently triggering a critical security alert.
*   **🏢 Multi-Tenancy**: Host multiple organizations on a single deployment with strict data isolation.
*   **🔌 High Availability**: Cluster-ready architecture with PostgreSQL Replication and Load Balancing support.
*   **🧠 Adaptive Security**: Time-Fencing (Business Hours), IP Blacklisting, and Abuse Thresholds (Soft Locking).
*   **🔍 Forensics**: detailed audit logs with IP tracking and real-time Webhook alerts.

## 📦 Getting Started

### 1. Deployment
Read the **[Deployment Guide](DEPLOY.md)** for detailed instructions on:
*   **One-Click LAMP Install**: `scripts/install_lamp.sh` for Ubuntu/Debian.
*   **Docker Compose**: Quick start with `docker-compose.yml`.
*   **High Availability**: Enterprise cluster setup with `docker-compose-cluster.yml` (Postgres Primary/Replica).
*   **Kubernetes**: Manifests in `k8s/`.

### 2. Client Development
Read the **[Mobile Developer Guide](MOBILE_DEV_GUIDE.md)** to build the native Authenticator app for iOS (Swift) and Android (Kotlin).

## 📚 Guides
- **[Enterprise Guide](docs/ENTERPRISE_GUIDE.md)**: For IT Admins managing multi-tenant clusters.
- **[User Guide](docs/USER_GUIDE.md)**: For end-users enrolling via Smart Code/QR.
- **[Validator Guide](docs/VALIDATOR_GUIDE.md)**: For system operators and auditors.
- **[Flutter Developer Guide](FLUTTER_DEV_GUIDE.md)**: Implementation specs for the Flutter Mobile App.
- **[Knowledge Base](docs/KNOWLEDGE_BASE.md)**: Troubleshooting guide for common issues.

## 🔧 Architecture

The system consists of three main components:
1.  **Backend API (Flask)**: Handles registration, challenge generation (encrypted), and verification. Stateless and scalable.
2.  **Database (PostgreSQL/SQLite)**: Stores user public keys, logs, and security policies.
3.  **Mobile Client (You Build It)**: Holds the Private Key in the device's Secure Enclave/Keystore and performs decryption.

## 🤝 Contributing

Please read `CHANGELOG.md` to see the project history.

## 📄 License

MIT
