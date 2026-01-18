# Indigo MFA Knowledge Base & Troubleshooting

This guide helps end-users, administrators, and developers troubleshoot common issues with the Indigo MFA ecosystem.

---

## 📱 Mobile App & Client (Flutter / Python)

### 🔴 "Decryption Failed" or "Invalid PIN"
**Symptoms:** The app attempts to login but fails immediately after entering the PIN.
**Causes:**
1.  **Wrong PIN:** You entered a PIN different from the one set during "Setup".
2.  **Corrupted Key:** The `device_key.pem` file (or Secure Storage) is missing or mismatched.
**Solution:**
- Retry the PIN carefully.
- If you have forgotten your PIN, you must **Reset** the app (delete data) and ask your Admin for a new Enrollment QR Code.

### 🔴 "Network Error" or "Connection Refused"
**Symptoms:** The app hangs or shows "Connection Error" when trying to Register or Login.
**Causes:**
1.  **Wrong Server URL:** The URL in the QR code is incorrect or unreachable from your device.
2.  **Firewall:** The server port (default `5000`) is blocked.
**Solution:**
- Ensure your mobile device is on the same network (Wi-Fi) as the server if using a local deployment.
- Verify the URL in "Setup" matches the server IP (e.g., `http://192.168.1.5:5000`).
- **Python Client:** Check `client_config.json` for the stored URL.

### 🔴 "Authentication Failed" (Server Rejected)
**Symptoms:** The app says "Decrypted OTP: 123456", but the Server responds with "Failure".
**Causes:**
1.  **Time Drift:** TOTP/ECIES challenges are time-sensitive. If your device clock is >5 minutes off, it fails.
2.  **Expired Challenge:** You took too long to enter the PIN.
3.  **Account Locked:** You have failed 5+ times recently (Temp Lock) or 10+ times (Soft Lock).
**Solution:**
- Enable "Automatic Date & Time" on your device settings.
- Ask an Admin to check the Dashboard to see if your status is "Locked".

### ⚠️ Context-Aware Authentication
**Question:** "Why is the app asking me to 'Verify this action'?"
**Answer:** This is a security feature. The server sent a specific context (e.g., "Transfer $500").
- **Action:** Read the message carefully.
- **If it matches what you are doing:** Click "Approve".
- **If you did NOT initiate this:** Click "Reject" and contact security immediately.

### ⚠️ Impossible Travel Detected
**Symptom:** You receive an "Abuse" alert or your account is locked after traveling.
**Cause:** You logged in from two locations that are physically impossible to travel between in the elapsed time (e.g., New York then London 1 hour later).
**Solution:**
- If you are using a VPN, this might trigger the alert.
- Contact Admin to verify the locations and unlock if it was a false positive.

---

## 🛑 Error Handling & Rate Limiting

### 🔴 "Locked. Retry in X seconds."
**Symptoms:** The client app refuses to authenticate and displays a countdown timer.
**Cause:** You have triggered the **Rate Limiter** by entering an incorrect PIN or OTP 5 times in a row.
**Mechanism:**
- The server returns HTTP `403 Forbidden` with a `Retry-After` header (seconds).
- The client respects this header and blocks further attempts until the timer expires.
**Solution:**
- Wait for the timer to reach zero.
- Ensure you are using the correct PIN.
- If you fail 5 more times (Total 10), the device will be **Soft Locked** and require Admin intervention.

---

## 🛠️ Maintenance

### Managing Audit Logs
Over time, `audit_logs` can grow large, affecting dashboard performance.

**Action:**
Use the CLI command to prune old logs:
```bash
# Delete logs older than 30 days (Default)
flask prune-logs

# Custom retention (e.g., 90 days)
flask prune-logs --days 90
```
This is safe to run on a live system.

---

## 🖥️ Admin Dashboard

### 🔴 "Admin access denied" / Login Modal Loop
**Symptoms:** You enter the Admin Key, but the modal reappears or shows "Invalid Key".
**Causes:**
1.  **Wrong Key:** The key does not match the hash stored in the database.
2.  **Browser Cache:** `localStorage` might have an old invalid key.
**Solution:**
- Check the server logs (`app.log`) for `[AUTH] Admin access denied`.
- If you lost the key, you must generate a new one via CLI or DB access.
- Default key for development is `secret-admin-key`.

### 🔴 Graphs or Logs are Empty
**Solution:**
- Ensure the database is initialized (`flask init-db`).
- Check if users are actually performing actions.
- Refresh the page (Charts update every 3 seconds).

---

## ⚙️ Server & Deployment

### 🔴 "OperationalError: no such table"
**Cause:** The database tables have not been created.
**Solution:**
- **Docker:** The entrypoint should handle this, but you can force it: `docker-compose exec backend flask init-db`.
- **Manual/LAMP:** Run `export FLASK_APP=backend.app && flask init-db`.

### 🔴 "Address already in use"
**Cause:** Port 5000 is occupied by another service or a zombie python process.
**Solution:**
- Find the process: `lsof -i :5000` or `netstat -nlp | grep 5000`.
- Kill it: `kill <PID>`.

### 🔴 "Migration check failed" in logs
**Cause:** You updated the code but have an old database file (`mfa.db`) missing new columns (like `last_ip`).
**Solution:**
- The server attempts to auto-migrate on startup. Check `app.log` for "Migrating DB".
- If that fails, delete `mfa.db` (DATA LOSS!) and restart, or manually run SQL `ALTER TABLE` commands.

---

## 🚨 Emergency Procedures

### What is Duress Mode?
**Scenario:** You are being forced to unlock your account by an attacker.
**Action:** Enter your **Duress PIN** (e.g., `9999`) instead of your real PIN.
**Result:**
1.  The App behaves NORMALLY (shows "Success").
2.  The Server accepts the login.
3.  **BUT** the server logs a `DURESS` event and triggers a silent alarm (Webhook).

### I Lost My Device
**Immediate Action:**
1.  Use a **Backup Code** (saved during registration) to log in temporarily if needed.
2.  Contact IT/Admin to **Revoke** your old device credentials.
3.  Re-enroll a new device.
