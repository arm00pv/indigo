# Indigo MFA Backend

The Flask-based backend service for Indigo MFA.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running

```bash
# Development
export FLASK_APP=backend.app:app
flask run

# Production (Gunicorn)
gunicorn --workers 3 --bind 0.0.0.0:5000 backend.app:app
```

## CLI Commands

The backend includes several CLI commands for administration and maintenance.

### 1. Initialization
Initialize the database and tables.
```bash
flask init-db
```

### 2. Admin Management
Add a new Admin API Key for accessing the Dashboard or Admin API.
```bash
# Interactive prompt
flask add-admin

# Direct command
flask add-admin --key "my-secret-key" --tenant "default"
```

### 3. Health Check
Run a system diagnostic to verify Database, Keys, and Permissions.
```bash
flask doctor
```

### 4. Backup & Restore
Manage full system backups (JSON format).

```bash
# Create a backup in backups/
flask backup

# Restore from a file
flask restore backups/indigo_full_backup_20231027_120000.json
```

### 5. Maintenance
Prune old audit logs to save space.
```bash
# Delete logs older than 30 days (default)
flask prune-logs

# Delete logs older than 90 days
flask prune-logs --days 90
```

## Configuration

Environment Variables:
*   `DATABASE_URL`: Connection string (e.g., `postgresql://user:pass@localhost/indigo`). Defaults to SQLite `mfa.db`.
*   `MASTER_KEY`: System Admin key for creating tenants.
*   `FLASK_APP`: `backend.app:app`

## API Documentation

See [API.md](API.md) for detailed endpoint documentation.
