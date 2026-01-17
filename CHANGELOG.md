# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-01-16
### Added
- **Context-Aware Authentication**:
    - Backend now supports attaching a `context` string (e.g., "Transfer $500") to the encrypted challenge.
    - Mobile Client decrypts and displays this context, enforcing "What You See Is What You Sign" (WYSIWYS).
- **Client Redundancy**:
    - Mobile Client now supports multiple API endpoints (Failover List).
    - `send_request` automatically retries backup endpoints if the primary is unreachable.
- **Documentation**: Updated User Guide with Context-Aware Auth instructions.

## [1.2.0] - 2026-01-16
### Added
- **Observability**:
    - **Prometheus Metrics**: Exposing `/metrics` endpoint with counters for requests, latency, auth events, and threats.
    - Instrumented `log_and_record` to capture all security events automatically.
- **Onboarding**:
    - **QR Code Enrollment**: Admin Dashboard can now generate configuration QR codes for users.
    - **Mobile Client**: Added "Setup via QR Payload" to the CLI menu for easy configuration.
    - New API endpoint `/admin/provision/qrcode` to generate provisioning payloads.

## [1.1.0] - 2026-01-16
### Added
- **Multi-Tenancy**:
    - Introduced `Tenant` model to support multiple organizations in a single instance.
    - Added `ApiKey` system for scoped API access (`X-Admin-Key` header).
    - Updated all models (`User`, `AuditLog`, etc.) to include `tenant_id` (Composite Primary Keys).
- **High Availability**:
    - Added `docker-compose-cluster.yml` for Nginx Load Balancing + 3 App Replicas + Postgres.
    - Migrated database layer to SQLAlchemy to support PostgreSQL for clustering.
- **Emergency Access**:
    - **Backup Codes**: Users now receive 5 one-time use backup codes during registration.
    - Added "Login with Backup Code" flow to API and Mobile Client.
- **Push Notifications**:
    - Integrated Webhook-based Push Notification simulation.
    - Mobile client listens for push events to auto-trigger login.

### Changed
- **Database**: Refactored from raw SQLite `sqlite3` calls to SQLAlchemy ORM.
- **API**: `/register` response now includes `backup_codes`.
- **Dashboard**: Added "Backup Codes Remaining" badge to user list.

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
