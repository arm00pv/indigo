### Troubleshooting: Resetting the Database

If you deploy to a persistent environment (like DigitalOcean with Managed Postgres) and lose access to your Admin API Key, you can force a hard reset of the database.

**WARNING: This deletes ALL users and data.**

1.  Set the environment variable `RESET_DB=true` in your deployment settings.
2.  Redeploy the application.
3.  The database will be wiped, and the Setup Wizard will appear at the root URL.
4.  Remove the `RESET_DB` variable afterwards to prevent accidental resets.
