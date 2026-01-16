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
- **Maintenance**: Prune old logs using the "Maintenance" tab.
