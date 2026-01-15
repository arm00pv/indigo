# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-15
### Added
- **Deployment**: Smart "One-Click" Installer (`scripts/install_lamp.sh`) with path auto-detection and safe Apache config appending.
- **Documentation**: Comprehensive `MOBILE_DEV_GUIDE.md` detailing Swift (iOS) and Kotlin (Android) implementation for ECIES and Duress Mode.
- **Admin Security**: Protected all Admin API endpoints (`/admin/*`) with `X-Admin-Key` authentication.
- **User Management**: New Dashboard widget to view, lock, and unlock users directly from the UI.
- **UX**: Client-side Admin Login modal in the Dashboard.

### Changed
- **Installer**: Refactored to avoid hardcoded paths and manage permissions dynamically for `www-data`.

## [0.5.0] - 2026-01-15
### Added
- **Adaptive Security**:
    - **IP Blacklisting**: Admin API and Dashboard UI to block specific IPs or CIDR ranges.
    - **Time-Fencing**: Global "Business Hours Only" toggle (08:00 - 18:00 Server Time).
- **Forensics**:
    - Added IP Address tracking to `audit_logs`.
    - Added Webhook Alerts (`notifications.py`) for critical events (Duress/Abuse).
- **Reporting**:
    - Export Logs as CSV or JSON.
    - Filtering support for "Threats Only" or "Errors Only".
    - New Dashboard visualizations: Activity Line Chart and Failure Reason Breakdown.

## [0.4.0] - 2026-01-15
### Added
- **Duress Mode**: "Stealth Auth" feature. Entering a Duress PIN authenticates the user but logs a critical alert by modifying the OTP (mod 10).
- **Abuse Thresholds**:
    - **Soft Lock**: Automatically locks accounts after 10 failed attempts.
    - **Admin Unlock**: API and UI to restore access for soft-locked users.
- **Revocation**: API endpoint to permanently revoke a user's keys.

## [0.3.0] - 2026-01-15
### Changed
- **Rebranding**: Renamed project from "Decentralized MFA" to **Indigo MFA**.
- **Containerization**: Added `Dockerfile`, `docker-compose.yml`, and Kubernetes manifests (`k8s/`).
- **Documentation**: Major update to `DEPLOY.md` covering LAMP, Docker, and K8s.

## [0.2.0] - 2026-01-15
### Added
- **Observability**:
    - Created `audit_logs` database table.
    - Implemented Admin Dashboard (`/dashboard`) using Chart.js.
    - Added structured file logging (`app.log`).
- **Security**:
    - Implemented OTP Expiration (5-minute TTL).
    - Implemented Rate Limiting (Temporary block after 5 failures).

## [0.1.0] - 2026-01-15
### Initial Release
- **Core SDK**: `mfa_sdk` package with `Verifier` and `Authenticator` classes.
- **Cryptography**:
    - Implemented ECIES (Elliptic Curve Integrated Encryption Scheme).
    - Uses SECP256R1 for key pairs.
    - Uses ECDH + HKDF + AES-GCM for encrypted OTP delivery.
- **Architecture**:
    - Split project into `backend` (Flask API) and `mobile_client` (Python CLI simulator).
    - Replaced SMS/MMS with data-channel encryption.
