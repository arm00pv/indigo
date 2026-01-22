# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2026-01-22
### Added
- **Security Hardening**:
    - **Health API**: New `/admin/system/health` endpoint checks DB, Keys, and Permissions.
    - **SMTP SSL**: Enhanced Email Notification channels to support SSL/TLS (Port 465).
    - **Database Reset**: Added `RESET_DB=true` support to wipe the database via environment variable, allowing recovery from persistent state issues.
- **Onboarding Experience**:
    - **Setup Wizard**: New "Trust On First Use" (TOFU) flow. If no Admin Keys exist, the dashboard presents a Setup Wizard instead of a Login screen.
    - **Role Selection**: Setup Wizard includes an "Installation Role" selector (Validator, Enterprise, User, Admin) to configure default security policies.
    - **Auto-Discovery**: Backend `/api/system/status` endpoint to detect initialization state.
- **Documentation**:
    - Created `backend/API.md` referencing all endpoints.
    - Added `docs/TROUBLESHOOTING.md` for database reset instructions.
    - Updated `mobile_client/README.md` for the Python CLI.

### Changed
- **Crypto Interoperability**: Updated `mfa_sdk/crypto.py` to use standard **X9.62 Uncompressed Point** format (65 bytes) for Ephemeral Public Keys, ensuring compatibility with the Flutter Client.
- **Deployment**:
    - Updated `scripts/install_lamp.sh` to explicitly create and permission `logs/` and `backups/` directories.
    - Updated `Dockerfile` and `app.py` logic to prevent pre-seeding the database with default keys, enabling the Setup Wizard on fresh installs.
    - **Fix**: Added root route (`/`) to redirect to `/dashboard`, fixing 404 errors on some platforms.
- **Refactor**: Consolidated notification logic into `backend/notifications.py` to reduce duplication.

### Fixed
- **Deployment**: Removed `backend/mfa.db` from the repository to prevent "Already Initialized" state on fresh deployments.
- **Legacy Cleanup**: `init_db_data` now automatically detects and purges insecure legacy default keys (`secret-admin-key`) to unlock the Setup Wizard for existing deployments.

## [2.3.0] - 2026-01-17
### Added
- **Security & UX**:
    - **Smart Rate Limiting**: Backend now returns standard `Retry-After` header on 403 Forbidden responses when users are temporarily locked.
    - **Client Guidance**: Mobile Client parses `Retry-After` and displays a clear countdown message instead of a generic error.
- **Admin Dashboard**:
    - **Admin Activity View**: New modal and filter to view dedicated Administrative logs (e.g., Key Revocation, Policy Changes, Maintenance).
- **Maintenance**:
    - **CLI**: Added `flask prune-logs` command to clean up old audit logs (default > 30 days).

## [2.2.0] - 2026-01-17
### Added
- **Notifications & Alerts**:
    - **Multi-Channel**: Configure per-tenant Webhook and Email (SMTP) alerts for critical events (Duress, Abuse).
    - **Dispatch System**: Backend logic to route alerts based on configured channels.
- **Dashboard**:
    - New "Alert Channels" card to manage and test notification settings.

## [2.1.0] - 2026-01-17
### Added
- **Smart Installer v2.1**:
    - PostgreSQL Support (`-db postgres`): Auto-installs and configures Postgres DB/User.
    - Automated Backups (`-b`): Sets up a daily cron job for `flask backup`.
    - Uninstallation (`--uninstall`): Cleanly removes the service and files.
    - Health Check: Verifies deployment success.
- **CLI**: Added `flask backup` command for automated maintenance.

## [2.0.0] - 2026-01-17
### Added
- **Impossible Travel Detection**:
    - Tracks User Geo-Location (Lat/Lon).
    - Flags logins with >800km/h travel speed as `ABUSE`.
- **Smart Installer v2.0**:
    - Automated SSL (Certbot) and Firewall (UFW).
    - Interactive and Non-Interactive (`-y`) modes.

## [1.8.0] - 2026-01-17
### Added
- **Flutter App**: Complete reference implementation in `flutter_app/`.
- **Enterprise Features**:
    - Bulk Provisioning (`/admin/provision/bulk`) via CSV/List.
    - PDF Enrollment Sheets (`/admin/provision/pdf`) with QR Codes.
    - Geo-Location Tracking (City/Country) for security events.
    - Backup and Restore endpoints for disaster recovery.
- **Documentation**:
    - Merged Flutter and Native guides into `MOBILE_DEV_GUIDE.md`.
    - Added `KNOWLEDGE_BASE.md`.
### Fixed
- **Crypto**: Aligned Flutter HKDF parameters with backend.
- **Stability**: Enforced single-worker mode for SQLite.

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
    - Replaced SMS/MMS with data-찼 channels.
