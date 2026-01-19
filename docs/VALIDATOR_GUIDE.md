# Indigo MFA - Validator Guide

"Validators" in the Indigo ecosystem are the server nodes responsible for authenticating requests.

## Role
Validators ensure that:
1. The user's cryptographic signature matches the registered public key.
2. The request originates from an allowed IP/Time (Policy Check).
3. The request belongs to a valid Tenant.

## Operations
- **Monitoring**: Use the `/dashboard` to view real-time threats.
- **Logs**: Periodically export logs via `/admin/export/logs` for auditing.
- **Maintenance**: Prune old logs using the "Maintenance" card in the Dashboard or `flask prune-logs`.

## Configuration
Security policies (Lockout thresholds, duration) can be configured directly from the Dashboard via the **Security Policies** card.

## Backup & Recovery
It is critical to regularly backup the system database.

### Automated Backups
The installer can set up a daily cron job.
To run manually:
```bash
# Export all data to 'backups/' directory
flask backup
```

### Restore
Currently, restoration is manual. Use the JSON files in `backups/` to repopulate the database or reference during disaster recovery.

### Health Check
Run the doctor command to verify database connectivity and permissions:
```bash
flask doctor
```
