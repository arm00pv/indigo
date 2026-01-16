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

## Cluster Management
For high availability, deploy Indigo using the provided `docker-compose-cluster.yml`.
Ensure load balancers pass through the `X-Tenant-ID` header if validators are distributed.
