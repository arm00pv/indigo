import sys
import os
import sqlite3
import logging
import datetime
from flask import Flask, request, jsonify, render_template

# Add project root to path so we can import mfa_sdk
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mfa_sdk.verifier import Verifier, VerificationStatus
from mfa_sdk.crypto import CryptoUtils

app = Flask(__name__)

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("Indigo_MFA_Backend")

# Initialize Verifier SDK
verifier = Verifier(verifier_id="Indigo-MFA-Backend")

# Database Setup
DB_PATH = os.path.join(os.path.dirname(__file__), 'mfa.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (user_id TEXT PRIMARY KEY, public_key_pem BLOB)''')
    # Add created_at to active_challenges
    c.execute('''CREATE TABLE IF NOT EXISTS active_challenges
                 (user_id TEXT PRIMARY KEY, otp TEXT, created_at DATETIME)''')

    # Audit Log Table
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  event_type TEXT,
                  user_id TEXT,
                  status TEXT,
                  details TEXT)''')

    # Security Table (Rate Limiting)
    c.execute('''CREATE TABLE IF NOT EXISTS user_security
                 (user_id TEXT PRIMARY KEY,
                  failed_attempts INTEGER DEFAULT 0,
                  locked_until DATETIME)''')
    conn.commit()
    conn.close()

init_db()

def log_and_record(event_type, user_id, status, details=""):
    """Logs to file and records in DB for dashboard."""
    # 1. File Log
    log_msg = f"[{event_type}] User: {user_id} | Status: {status} | {details}"
    if status == "SUCCESS":
        logger.info(log_msg)
    elif status == "DURESS":
        logger.critical(f"🚨 DURESS SIGNAL: {log_msg}")
    else:
        logger.warning(log_msg)

    # 2. DB Record
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO audit_logs (event_type, user_id, status, details) VALUES (?, ?, ?, ?)",
                  (event_type, user_id, status, details))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to write to audit log: {e}")

@app.route('/')
def home():
    return "Indigo MFA Backend API is running. <a href='/dashboard'>View Dashboard</a>"

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user_id = data.get('user_id')
    public_key_pem_hex = data.get('public_key_pem_hex')

    if not user_id or not public_key_pem_hex:
        log_and_record("REGISTER", "unknown", "FAIL", "Missing data")
        return jsonify({"error": "Missing user_id or public_key_pem_hex"}), 400

    try:
        public_key_pem = bytes.fromhex(public_key_pem_hex)
        CryptoUtils.load_public_key(public_key_pem)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO users (user_id, public_key_pem) VALUES (?, ?)",
                  (user_id, public_key_pem))
        # Reset security stats on new registration/update
        c.execute("DELETE FROM user_security WHERE user_id=?", (user_id,))
        conn.commit()
        conn.close()

        verifier.register_user(user_id, public_key_pem)

        log_and_record("REGISTER", user_id, "SUCCESS", "User registered")
        return jsonify({"message": f"User {user_id} registered successfully."}), 201
    except Exception as e:
        log_and_record("REGISTER", user_id, "FAIL", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/auth/challenge', methods=['POST'])
def get_challenge():
    data = request.json
    user_id = data.get('user_id')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 1. Check if user is locked
    c.execute("SELECT locked_until FROM user_security WHERE user_id=?", (user_id,))
    row = c.fetchone()
    if row and row[0]:
        locked_until = datetime.datetime.fromisoformat(row[0])
        if datetime.datetime.now() < locked_until:
            conn.close()
            log_and_record("CHALLENGE", user_id, "BLOCK", "User Locked")
            return jsonify({"error": "Account temporarily locked due to too many failed attempts."}), 403

    # 2. Get Key
    c.execute("SELECT public_key_pem FROM users WHERE user_id=?", (user_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        log_and_record("CHALLENGE", user_id, "FAIL", "User not found")
        return jsonify({"error": "User not found"}), 404

    public_key_pem = row[0]

    verifier.register_user(user_id, public_key_pem)
    otp = verifier.generate_otp()

    # 3. Store OTP with Timestamp
    now = datetime.datetime.now().isoformat()
    c.execute("INSERT OR REPLACE INTO active_challenges (user_id, otp, created_at) VALUES (?, ?, ?)",
              (user_id, otp, now))
    conn.commit()
    conn.close()

    encrypted_blob = verifier.encrypt_otp_for_user(user_id, otp)

    log_and_record("CHALLENGE", user_id, "SUCCESS", "OTP generated")

    return jsonify({
        "encrypted_challenge_hex": encrypted_blob.hex(),
        "message": "Challenge sent."
    })

@app.route('/auth/verify', methods=['POST'])
def verify_otp():
    data = request.json
    user_id = data.get('user_id')
    submitted_otp = data.get('otp')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 1. Check Lock Status
    c.execute("SELECT failed_attempts, locked_until FROM user_security WHERE user_id=?", (user_id,))
    sec_row = c.fetchone()
    if sec_row:
        failed_attempts = sec_row[0]
        locked_until = sec_row[1]
    else:
        failed_attempts = 0
        locked_until = None

    if locked_until:
        locked_until_dt = datetime.datetime.fromisoformat(locked_until)
        if datetime.datetime.now() < locked_until_dt:
            conn.close()
            log_and_record("AUTH", user_id, "BLOCK", "User Locked")
            return jsonify({"error": "Account temporarily locked."}), 403
        else:
            # Lock expired, reset
            failed_attempts = 0
            c.execute("UPDATE user_security SET locked_until=NULL, failed_attempts=0 WHERE user_id=?", (user_id,))
            conn.commit()

    # 2. Get Challenge
    c.execute("SELECT otp, created_at FROM active_challenges WHERE user_id=?", (user_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        log_and_record("AUTH", user_id, "FAIL", "No active challenge")
        return jsonify({"error": "No active challenge found"}), 400

    original_otp = row[0]
    created_at = datetime.datetime.fromisoformat(row[1]) if row[1] else datetime.datetime.now()

    # 3. Check TTL (5 minutes)
    if datetime.datetime.now() - created_at > datetime.timedelta(minutes=5):
        conn.close()
        log_and_record("AUTH", user_id, "FAIL", "OTP Expired")
        return jsonify({"error": "OTP Expired. Please request a new one."}), 400

    # 4. Verify OTP (Standard or Duress)
    status = verifier.verify_otp(original_otp, submitted_otp)

    if status == VerificationStatus.VALID or status == VerificationStatus.DURESS:
        # Success (or Duress Success)
        c.execute("DELETE FROM active_challenges WHERE user_id=?", (user_id,))
        # Reset security failures
        c.execute("INSERT OR REPLACE INTO user_security (user_id, failed_attempts, locked_until) VALUES (?, 0, NULL)", (user_id,))
        conn.commit()
        conn.close()

        if status == VerificationStatus.DURESS:
            log_and_record("AUTH", user_id, "DURESS", "Silent Alarm: User authenticated with Duress Code")
        else:
            log_and_record("AUTH", user_id, "SUCCESS", "Authentication Verified")

        return jsonify({"status": "success", "message": "Authentication Successful"}), 200
    else:
        # Failure: Increment count
        failed_attempts += 1
        new_locked_until = None

        if failed_attempts >= 5:
            # Lock for 15 mins
            new_locked_until = (datetime.datetime.now() + datetime.timedelta(minutes=15)).isoformat()
            log_and_record("AUTH", user_id, "BLOCK", "Too many failures - Account Locked")
            msg = "Too many failed attempts. Account locked for 15 minutes."
        else:
             log_and_record("AUTH", user_id, "FAIL", f"Invalid OTP (Attempt {failed_attempts}/5)")
             msg = "Invalid OTP"

        c.execute("INSERT OR REPLACE INTO user_security (user_id, failed_attempts, locked_until) VALUES (?, ?, ?)",
                  (user_id, failed_attempts, new_locked_until))
        conn.commit()
        conn.close()

        return jsonify({"status": "failure", "message": msg}), 401 if failed_attempts < 5 else 403

# --- Revocation Route ---
@app.route('/user/<user_id>/revoke', methods=['DELETE'])
def revoke_user(user_id):
    # In prod, add Admin Auth check here!

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE user_id=?", (user_id,))
    deleted = c.rowcount
    c.execute("DELETE FROM active_challenges WHERE user_id=?", (user_id,))
    c.execute("DELETE FROM user_security WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()

    if deleted > 0:
        log_and_record("REVOKE", user_id, "SUCCESS", "Key revoked by admin")
        return jsonify({"message": f"User {user_id} revoked."}), 200
    else:
        return jsonify({"error": "User not found"}), 404

# --- Dashboard Routes ---

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 1. Total Counts
    c.execute("SELECT COUNT(*) FROM audit_logs WHERE event_type='REGISTER' AND status='SUCCESS'")
    total_users = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM audit_logs WHERE event_type='AUTH' AND status='SUCCESS'")
    successful_auths = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM audit_logs WHERE event_type='AUTH' AND status='FAIL'")
    failed_auths = c.fetchone()[0]

    # 2. Blocked Users
    c.execute("SELECT COUNT(*) FROM user_security WHERE locked_until IS NOT NULL")
    blocked_users = c.fetchone()[0]

    # 3. Threats (Duress)
    c.execute("SELECT COUNT(*) FROM audit_logs WHERE status='DURESS'")
    threat_count = c.fetchone()[0]

    # 4. Recent Logs
    c.execute("SELECT timestamp, event_type, user_id, status, details FROM audit_logs ORDER BY id DESC LIMIT 10")
    recent_logs = [{"timestamp": r[0], "event": r[1], "user": r[2], "status": r[3], "details": r[4]} for r in c.fetchall()]

    conn.close()

    return jsonify({
        "total_users": total_users,
        "blocked_users": blocked_users,
        "threat_count": threat_count,
        "auth_stats": [successful_auths, failed_auths],
        "logs": recent_logs
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
