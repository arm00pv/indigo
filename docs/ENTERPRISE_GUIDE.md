# Indigo MFA - Enterprise Guide

This guide is for IT Administrators and Security Operations teams deploying Indigo MFA.

## Multi-Tenancy & Identification
Indigo MFA supports multiple organizations ("Tenants") on a single cluster. Each tenant data is isolated.

### Creating a Tenant
Use the System Admin API (requires `MASTER_KEY`) to provision new tenants:
`POST /sys/tenants` -> `{"name": "Company XYZ"}`

### Identifying Users
When enrolling users, generate a "Smart Code" or QR Code via the Dashboard.
This code contains:
- **Server URL**: Directs the user to your specific cluster.
- **Tenant ID**: Associates the user with your organization.
- **User ID**: Unique identifier for the employee.

## SSO Configuration (Single Sign-On)
Indigo MFA can serve as a second factor for your existing SSO Provider (e.g., Okta, Azure AD, Google).

### Integration Overview
The `/auth/sso/login` endpoint acts as a stub/placeholder for OIDC redirects. To fully enable SSO:

1.  **Identity Provider (IdP):** Configure your IdP to redirect to `https://your-indigo-server.com/auth/sso/callback`.
2.  **User Mapping:** Ensure the `user_id` in Indigo matches the `sub` or `email` claim from your IdP.
3.  **Self-Registration:** Enable "Allow Self-Registration" in the Dashboard to let users self-enroll using their SSO email address.

**Note:** A future update will include a built-in OIDC client. For now, you can extend `backend/app.py` to handle the specific handshake of your provider.

## Cluster Management
For high availability, deploy Indigo using the provided `docker-compose-cluster.yml`.
Ensure load balancers pass through the `X-Tenant-ID` header if validators are distributed.

## Security Policy Configuration
Indigo MFA allows customization of lockout thresholds and durations per tenant. These can be configured via the `POST /admin/settings` endpoint.

### Available Settings
| Key | Default | Description |
| :--- | :--- | :--- |
| `policy_max_failures_soft_lock` | `10` | Number of failed attempts before a **Permanent Soft Lock** (requires Admin unlock). |
| `policy_max_failures_temp_lock` | `5` | Number of failed attempts before a **Temporary Lock**. |
| `policy_temp_lock_duration_seconds` | `900` | Duration (in seconds) of the Temporary Lock (default 15 minutes). |
| `allow_self_registration` | `false` | Enables the `/register-user` page for self-service enrollment. |

### Example: Stricter Policy
To set a strict policy (3 attempts -> 1 hour lock, 5 attempts -> permanent):

```bash
curl -X POST https://auth.corp.com/admin/settings \
  -H "X-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_max_failures_soft_lock": "5",
    "policy_max_failures_temp_lock": "3",
    "policy_temp_lock_duration_seconds": "3600"
  }'
```
