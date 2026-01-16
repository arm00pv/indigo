import sys
import os
import logging
import datetime
import csv
import io
import json
import ipaddress
import functools
from flask import Flask, request, jsonify, render_template, Response
from backend.models import db, User, ActiveChallenge, AuditLog, UserSecurity, SystemSetting, IPBlacklist

# Add project root to path so we can import mfa_sdk
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mfa_sdk.verifier import Verifier, VerificationStatus
from mfa_sdk.crypto import CryptoUtils
from backend.notifications import send_webhook_alert

app = Flask(__name__)

# --- Configuration ---
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "secret-admin-key")
# Default to SQLite if not provided, for backward compatibility
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f"sqlite:///{os.path.join(os.path.dirname(__file__), 'mfa.db')}")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

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

# Initialize Verifier SDK (Stateless logic mostly, but we need to ensure keys are loaded when needed)
verifier = Verifier(verifier_id="Indigo-MFA-Backend")

# --- Helper Functions ---

def init_db_data():
    """Initialize DB tables if not exist."""
    with app.app_context():
        db.create_all()
        # Seed default settings if needed
        if not SystemSetting.query.filter_by(key='business_hours_enabled').first():
            db.session.add(SystemSetting(key='business_hours_enabled', value='false'))
            db.session.commit()

# Call init on startup
init_db_data()

# --- Decorators ---
def require_admin(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        key = request.headers.get('X-Admin-Key')
        if key == ADMIN_API_KEY:
            return f(*args, **kwargs)
        if request.args.get('key') == ADMIN_API_KEY:
            return f(*args, **kwargs)
        logger.warning(f"[AUTH] Admin access denied from {request.remote_addr}")
        return jsonify({"error": "Unauthorized. Invalid Admin Key."}), 401
    return decorated_function

def log_and_record(event_type, user_id, status, details=""):
    ip_address = request.remote_addr if request else "unknown"
    log_msg = f"[{event_type}] User: {user_id} | IP: {ip_address} | Status: {status} | {details}"

    if status == "SUCCESS":
        logger.info(log_msg)
    elif status == "DURESS" or status == "ABUSE":
        logger.critical(f"🚨 {status} SIGNAL: {log_msg}")
        send_webhook_alert(event_type, user_id, status, details)
    else:
        logger.warning(log_msg)

    try:
        log_entry = AuditLog(
            event_type=event_type,
            user_id=user_id,
            status=status,
            details=details,
            ip_address=ip_address,
            timestamp=datetime.datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to write to audit log: {e}")
        db.session.rollback()

def check_policy_compliance(ip_addr):
    try:
        # 1. IP Blacklist Check
        blacklist = IPBlacklist.query.all()
        req_ip = ipaddress.ip_address(ip_addr)

        for entry in blacklist:
            try:
                if req_ip in ipaddress.ip_network(entry.cidr):
                    return False, f"IP Blacklisted: {entry.reason}"
            except ValueError:
                continue

        # 2. Business Hours Check
        setting = SystemSetting.query.filter_by(key='business_hours_enabled').first()
        if setting and setting.value == 'true':
            current_hour = datetime.datetime.now().hour
            if current_hour < 8 or current_hour >= 18:
                return False, "Access denied outside business hours (08:00 - 18:00)"

        return True, None
    except Exception as e:
        logger.error(f"Policy check error: {e}")
        return True, None # Fail open or closed? Let's fail open to avoid outage on DB error for now

# --- Routes ---

@app.route('/')
def home():
    return "Indigo MFA Backend API is running. <a href='/dashboard'>View Dashboard</a>"

@app.route('/health')
def health():
    try:
        # Simple DB check
        db.session.execute(db.text("SELECT 1"))
        return jsonify({"status": "healthy"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user_id = data.get('user_id')
    public_key_pem_hex = data.get('public_key_pem_hex')

    allowed, reason = check_policy_compliance(request.remote_addr)
    if not allowed:
        log_and_record("REGISTER", user_id or "unknown", "BLOCK", reason)
        return jsonify({"error": reason}), 403

    if not user_id or not public_key_pem_hex:
        log_and_record("REGISTER", "unknown", "FAIL", "Missing data")
        return jsonify({"error": "Missing user_id or public_key_pem_hex"}), 400

    try:
        public_key_pem = bytes.fromhex(public_key_pem_hex)
        CryptoUtils.load_public_key(public_key_pem)

        # Save User
        user = User.query.get(user_id)
        if not user:
            user = User(user_id=user_id, public_key_pem=public_key_pem)
            db.session.add(user)
        else:
            user.public_key_pem = public_key_pem

        # Clear security stats
        UserSecurity.query.filter_by(user_id=user_id).delete()

        db.session.commit()
        verifier.register_user(user_id, public_key_pem) # Update in-memory if needed

        log_and_record("REGISTER", user_id, "SUCCESS", "User registered")
        return jsonify({"message": f"User {user_id} registered successfully."}), 201
    except Exception as e:
        db.session.rollback()
        log_and_record("REGISTER", user_id, "FAIL", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/auth/challenge', methods=['POST'])
def get_challenge():
    data = request.json
    user_id = data.get('user_id')

    allowed, reason = check_policy_compliance(request.remote_addr)
    if not allowed:
        log_and_record("CHALLENGE", user_id, "BLOCK", reason)
        return jsonify({"error": reason}), 403

    # Check Security Status
    sec_record = UserSecurity.query.get(user_id)
    if sec_record:
        if sec_record.lock_type == 'PERMANENT':
            log_and_record("CHALLENGE", user_id, "BLOCK", "User Soft Locked (Abuse)")
            return jsonify({"error": "Device Soft Locked due to abuse. Contact Admin."}), 403

        if sec_record.locked_until and datetime.datetime.now() < sec_record.locked_until:
            log_and_record("CHALLENGE", user_id, "BLOCK", "User Locked")
            return jsonify({"error": "Account temporarily locked."}), 403

    user = User.query.get(user_id)
    if not user:
        log_and_record("CHALLENGE", user_id, "FAIL", "User not found")
        return jsonify({"error": "User not found"}), 404

    # Generate OTP
    otp = verifier.generate_otp()

    # Save Challenge
    challenge = ActiveChallenge.query.get(user_id)
    if not challenge:
        challenge = ActiveChallenge(user_id=user_id)
        db.session.add(challenge)
    challenge.otp = otp
    challenge.created_at = datetime.datetime.now()
    db.session.commit()

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

    allowed, reason = check_policy_compliance(request.remote_addr)
    if not allowed:
        log_and_record("AUTH", user_id, "BLOCK", reason)
        return jsonify({"error": reason}), 403

    # Get Security State
    sec_record = UserSecurity.query.get(user_id)
    failed_attempts = 0

    if sec_record:
        failed_attempts = sec_record.failed_attempts
        if sec_record.lock_type == 'PERMANENT':
            log_and_record("AUTH", user_id, "BLOCK", "User Soft Locked (Abuse)")
            return jsonify({"error": "Device Soft Locked."}), 403

        if sec_record.locked_until:
            if datetime.datetime.now() < sec_record.locked_until:
                log_and_record("AUTH", user_id, "BLOCK", "User Locked")
                return jsonify({"error": "Account temporarily locked."}), 403
            else:
                # Lock expired
                failed_attempts = 0
    else:
        sec_record = UserSecurity(user_id=user_id)
        db.session.add(sec_record)

    # Get Challenge
    challenge = ActiveChallenge.query.get(user_id)
    if not challenge:
        log_and_record("AUTH", user_id, "FAIL", "No active challenge")
        return jsonify({"error": "No active challenge found"}), 400

    # TTL Check (5 min)
    if datetime.datetime.now() - challenge.created_at > datetime.timedelta(minutes=5):
        log_and_record("AUTH", user_id, "FAIL", "OTP Expired")
        return jsonify({"error": "OTP Expired."}), 400

    # Verify
    # Load Key manually because Verifier registry might be empty in stateless mode
    user = User.query.get(user_id)
    # We need to register it in verifier again to ensure key is available for verification check logic
    # (Though verifier.verify_otp is simple string comparison, so key load isn't strictly needed for verify,
    # but verifier class structure suggests it. Wait, `verify_otp` compares strings.
    # Key is needed for ENCRYPTION. Decryption happens on client.
    # So `verify_otp` is just `original_otp == submitted`.

    original_otp = challenge.otp
    status = verifier.verify_otp(original_otp, submitted_otp)

    if status == VerificationStatus.VALID or status == VerificationStatus.DURESS:
        # Success
        db.session.delete(challenge)
        sec_record.failed_attempts = 0
        sec_record.locked_until = None
        sec_record.lock_type = 'NONE'
        db.session.commit()

        if status == VerificationStatus.DURESS:
            log_and_record("AUTH", user_id, "DURESS", "Silent Alarm: User authenticated with Duress Code")
        else:
            log_and_record("AUTH", user_id, "SUCCESS", "Authentication Verified")

        return jsonify({"status": "success", "message": "Authentication Successful"}), 200
    else:
        # Fail
        failed_attempts += 1
        sec_record.failed_attempts = failed_attempts
        msg = "Invalid OTP"
        code = 401

        if failed_attempts >= 10:
            sec_record.lock_type = 'PERMANENT'
            log_and_record("AUTH", user_id, "ABUSE", "Soft Lock Activated")
            msg = "Device Soft Locked due to abuse."
            code = 403
        elif failed_attempts >= 5:
            sec_record.locked_until = datetime.datetime.now() + datetime.timedelta(minutes=15)
            sec_record.lock_type = 'TEMP'
            log_and_record("AUTH", user_id, "BLOCK", "Temp Lock Activated")
            msg = "Too many failures. Locked for 15 mins."
            code = 403
        else:
            log_and_record("AUTH", user_id, "FAIL", f"Invalid OTP (Attempt {failed_attempts}/10)")

        db.session.commit()
        return jsonify({"status": "failure", "message": msg}), code

# --- Admin Routes ---
@app.route('/admin/user/<user_id>/lock', methods=['POST'])
@require_admin
def admin_lock_user(user_id):
    sec = UserSecurity.query.get(user_id)
    if not sec:
        sec = UserSecurity(user_id=user_id)
        db.session.add(sec)
    sec.lock_type = 'PERMANENT'
    sec.failed_attempts = 0
    sec.locked_until = None
    db.session.commit()
    log_and_record("ADMIN", user_id, "BLOCK", "Admin manually locked user")
    return jsonify({"message": f"User {user_id} soft locked."}), 200

@app.route('/admin/user/<user_id>/unlock', methods=['POST'])
@require_admin
def admin_unlock_user(user_id):
    sec = UserSecurity.query.get(user_id)
    if sec:
        sec.lock_type = 'NONE'
        sec.failed_attempts = 0
        sec.locked_until = None
        db.session.commit()
    log_and_record("ADMIN", user_id, "SUCCESS", "Admin unlocked user")
    return jsonify({"message": f"User {user_id} unlocked."}), 200

@app.route('/admin/users', methods=['GET'])
@require_admin
def admin_users():
    results = db.session.query(User, UserSecurity).outerjoin(UserSecurity, User.user_id == UserSecurity.user_id).all()
    users_list = []
    for u, s in results:
        status = "Active"
        fails = 0
        if s:
            fails = s.failed_attempts
            if s.lock_type == 'PERMANENT':
                status = "Soft Locked"
            elif s.locked_until and datetime.datetime.now() < s.locked_until:
                status = "Temp Locked"
        users_list.append({
            "user_id": u.user_id,
            "status": status,
            "failed_attempts": fails
        })
    return jsonify(users_list)

@app.route('/admin/settings', methods=['GET', 'POST'])
@require_admin
def admin_settings():
    if request.method == 'POST':
        data = request.json
        for key, val in data.items():
            setting = SystemSetting.query.get(key)
            if not setting:
                setting = SystemSetting(key=key)
                db.session.add(setting)
            setting.value = str(val)
        db.session.commit()
        return jsonify({"message": "Settings updated"}), 200
    else:
        settings = SystemSetting.query.all()
        return jsonify({s.key: s.value for s in settings})

@app.route('/admin/policy/blacklist', methods=['GET', 'POST', 'DELETE'])
@require_admin
def admin_blacklist():
    if request.method == 'POST':
        data = request.json
        cidr = data.get('cidr')
        reason = data.get('reason', 'Manually Blocked')
        try:
            ipaddress.ip_network(cidr)
            entry = IPBlacklist(cidr=cidr, reason=reason)
            db.session.merge(entry)
            db.session.commit()
            return jsonify({"message": "IP Blocked"}), 201
        except ValueError:
            return jsonify({"error": "Invalid CIDR"}), 400
    elif request.method == 'DELETE':
        cidr = request.json.get('cidr')
        IPBlacklist.query.filter_by(cidr=cidr).delete()
        db.session.commit()
        return jsonify({"message": "IP Unblocked"}), 200
    else:
        items = IPBlacklist.query.order_by(IPBlacklist.created_at.desc()).all()
        return jsonify([{"cidr": i.cidr, "reason": i.reason, "created_at": i.created_at} for i in items])

@app.route('/admin/export/logs')
@require_admin
def admin_export_logs():
    fmt = request.args.get('format', 'csv')
    filter_type = request.args.get('filter', 'all')

    query = AuditLog.query
    if filter_type == 'threats':
        query = query.filter(AuditLog.status.in_(['DURESS', 'ABUSE', 'BLOCK']))
    elif filter_type == 'errors':
        query = query.filter(AuditLog.status.in_(['FAIL', 'BLOCK', 'ABUSE', 'DURESS']))

    logs = query.order_by(AuditLog.id.desc()).all()

    if fmt == 'json':
        data = [{
            "id": l.id, "timestamp": l.timestamp, "event": l.event_type,
            "user": l.user_id, "ip": l.ip_address, "status": l.status, "details": l.details
        } for l in logs]
        return jsonify(data)
    else:
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID', 'Timestamp', 'Event', 'User', 'IP Address', 'Status', 'Details'])
        for l in logs:
            cw.writerow([l.id, l.timestamp, l.event_type, l.user_id, l.ip_address, l.status, l.details])

        return Response(
            si.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename=indigo_logs_{filter_type}.csv"}
        )

@app.route('/api/stats')
def api_stats():
    # 1. Counts
    total_users = AuditLog.query.filter_by(event_type='REGISTER', status='SUCCESS').count()
    success_auth = AuditLog.query.filter_by(event_type='AUTH', status='SUCCESS').count()
    fail_auth = AuditLog.query.filter_by(event_type='AUTH', status='FAIL').count()

    blocked = UserSecurity.query.filter(
        (UserSecurity.locked_until != None) | (UserSecurity.lock_type == 'PERMANENT')
    ).count()

    threats = AuditLog.query.filter(AuditLog.status.in_(['DURESS', 'ABUSE'])).count()

    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(10).all()
    recent_logs = [{
        "timestamp": l.timestamp.isoformat(),
        "event": l.event_type,
        "user": l.user_id,
        "status": l.status,
        "details": l.details,
        "ip": l.ip_address or "unknown"
    } for l in logs]

    soft_locked = UserSecurity.query.filter_by(lock_type='PERMANENT').all()
    soft_locked_list = [{"user_id": u.user_id, "fails": u.failed_attempts} for u in soft_locked]

    # Policies
    biz_hours_setting = SystemSetting.query.get('business_hours_enabled')
    biz_hours = (biz_hours_setting.value == 'true') if biz_hours_setting else False
    blacklist = IPBlacklist.query.all()
    blacklist_data = [{"cidr": b.cidr, "reason": b.reason} for b in blacklist]

    # Advanced: Activity (SQLAlchemy specific for SQLite vs Postgres difference requires care)
    # Using python-side processing for simplicity in this DB-agnostic POC
    # Production would use db.func.date_trunc for Postgres

    one_day_ago = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    recent_auths = AuditLog.query.filter(
        AuditLog.event_type == 'AUTH',
        AuditLog.timestamp > one_day_ago
    ).all()

    # Group by Hour
    activity_map = {}
    for log in recent_auths:
        h = log.timestamp.strftime('%Y-%m-%d %H:00')
        activity_map[h] = activity_map.get(h, 0) + 1

    activity_data = [{"hour": k, "count": v} for k, v in sorted(activity_map.items())]

    # Failure Breakdown
    failures = AuditLog.query.filter(AuditLog.status != 'SUCCESS').all()
    fail_map = {}
    for log in failures:
        label = log.details
        if "Invalid OTP" in label: label = "Invalid OTP"
        elif "Expired" in label: label = "OTP Expired"
        elif "Locked" in label: label = "Account Locked"
        fail_map[label] = fail_map.get(label, 0) + 1

    # Sort top 5
    failure_data = [{"label": k, "count": v} for k, v in sorted(fail_map.items(), key=lambda item: item[1], reverse=True)[:5]]

    return jsonify({
        "total_users": total_users,
        "blocked_users": blocked,
        "threat_count": threats,
        "auth_stats": [success_auth, fail_auth],
        "logs": recent_logs,
        "soft_locked_users": soft_locked_list,
        "activity_over_time": activity_data,
        "failure_breakdown": failure_data,
        "policies": {
            "business_hours_enabled": biz_hours,
            "blacklist": blacklist_data
        }
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
