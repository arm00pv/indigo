import sys
import os
import sqlite3
from flask import Flask, request, jsonify

# Add project root to path so we can import mfa_sdk
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mfa_sdk.verifier import Verifier
from mfa_sdk.crypto import CryptoUtils

app = Flask(__name__)

# Initialize Verifier SDK (In-memory cache of connected users for this process)
# In production with multiple workers, state must be in DB/Redis.
verifier = Verifier(verifier_id="Corporate-Backend")

# Database Setup (SQLite for demo)
DB_PATH = os.path.join(os.path.dirname(__file__), 'mfa.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (user_id TEXT PRIMARY KEY, public_key_pem BLOB)''')
    c.execute('''CREATE TABLE IF NOT EXISTS active_challenges
                 (user_id TEXT PRIMARY KEY, otp TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return "MFA Backend API is running."

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user_id = data.get('user_id')
    public_key_pem_hex = data.get('public_key_pem_hex') # Sending as hex to avoid JSON encoding issues with PEM newlines

    if not user_id or not public_key_pem_hex:
        return jsonify({"error": "Missing user_id or public_key_pem_hex"}), 400

    try:
        public_key_pem = bytes.fromhex(public_key_pem_hex)

        # Verify Key format
        CryptoUtils.load_public_key(public_key_pem)

        # Save to DB
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO users (user_id, public_key_pem) VALUES (?, ?)",
                  (user_id, public_key_pem))
        conn.commit()
        conn.close()

        # Update in-memory verifier
        verifier.register_user(user_id, public_key_pem)

        return jsonify({"message": f"User {user_id} registered successfully."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/auth/challenge', methods=['POST'])
def get_challenge():
    data = request.json
    user_id = data.get('user_id')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT public_key_pem FROM users WHERE user_id=?", (user_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    public_key_pem = row[0]
    conn.close()

    # Ensure Verifier has the key loaded
    verifier.register_user(user_id, public_key_pem)

    # Generate OTP
    otp = verifier.generate_otp()

    # Store OTP (In real world, use Redis with TTL)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO active_challenges (user_id, otp) VALUES (?, ?)", (user_id, otp))
    conn.commit()
    conn.close()

    # Encrypt OTP
    encrypted_blob = verifier.encrypt_otp_for_user(user_id, otp)

    return jsonify({
        "encrypted_challenge_hex": encrypted_blob.hex(),
        "message": "Challenge sent. Decrypt this on your mobile device."
    })

@app.route('/auth/verify', methods=['POST'])
def verify_otp():
    data = request.json
    user_id = data.get('user_id')
    submitted_otp = data.get('otp')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT otp FROM active_challenges WHERE user_id=?", (user_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "No active challenge found"}), 400

    original_otp = row[0]

    if verifier.verify_otp(original_otp, submitted_otp):
        # Invalidate OTP after use
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM active_challenges WHERE user_id=?", (user_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Authentication Successful"}), 200
    else:
        return jsonify({"status": "failure", "message": "Invalid OTP"}), 401

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
