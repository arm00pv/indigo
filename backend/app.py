import sys
import os
import logging
import datetime
import csv
import io
import json
import ipaddress
import functools
import hashlib
import requests
import secrets
import time
import base64
import io
import qrcode
from flask import Flask, request, jsonify, render_template, Response, g
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from backend.models import db, User, ActiveChallenge, AuditLog, UserSecurity, SystemSetting, IPBlacklist, Tenant, ApiKey
from backend.utils import generate_backup_codes

# Add project root to path so we can import mfa_sdk
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mfa_sdk.verifier import Verifier, VerificationStatus
from mfa_sdk.crypto import CryptoUtils
from backend.notifications import send_webhook_alert

app = Flask(__name__)

# --- Configuration ---
# MASTER_KEY is for System Admins to create Tenants
MASTER_KEY = os.environ.get("MASTER_KEY", "master-secret-key")

# Default to SQLite if not provided
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

# --- Prometheus Metrics ---
HTTP_REQUESTS = Counter('http_requests_total', 'Total HTTP Requests', ['method', 'endpoint', 'status'])
HTTP_LATENCY = Histogram('http_request_duration_seconds', 'HTTP Request Latency', ['endpoint'])
MFA_EVENTS = Counter('mfa_events_total', 'MFA Security Events', ['event_type', 'status', 'tenant'])
ACTIVE_THREATS = Counter('mfa_threats_total', 'Active Security Threats', ['type', 'tenant'])

# Initialize Verifier SDK
verifier = Verifier(verifier_id="Indigo-MFA-Backend")

# --- Helper Functions ---

def init_db_data():
    """Initialize DB tables if not exist."""
    # Ensure app context if not present (handled by caller usually, but safe to check)
    # But db.create_all() needs it.
    # The CLI command provides context.

    db.create_all()
    # Ensure Default Tenant exists for backward compatibility or initial setup
    if not Tenant.query.filter_by(name="Default Organization").first():
        default_tenant = Tenant(id="default", name="Default Organization")
        db.session.add(default_tenant)

        # Create a default API Key for it (hashed)
        # Check env var for seed
        k = os.environ.get("ADMIN_API_KEY", "secret-admin-key")
        h = hashlib.sha256(k.encode()).hexdigest()
        db.session.add(ApiKey(key_hash=h, tenant_id="default"))

        # Default Settings
        db.session.add(SystemSetting(key='business_hours_enabled', value='false', tenant_id="default"))
        db.session.add(SystemSetting(key='log_retention_days', value='90', tenant_id="default"))
        db.session.commit()
        logger.info(f"Initialized Database with Admin Key hash: {h[:8]}...")

@app.cli.command("init-db")
def init_db_command():
    """Initialize the database."""
    init_db_data()
    print("Initialized the database.")

# --- Decorators & Middleware ---

def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()

def get_tenant_from_key(key):
    """Resolves Tenant ID from API Key."""
    h = hash_key(key)
    api_key = ApiKey.query.get(h)
    if api_key:
        return api_key.tenant_id
    return None

def authenticate_request():
    """
    Middleware logic to set g.tenant_id.
    """

    # 1. Master Key (SysAdmin)
    master_key = request.headers.get('X-Master-Key')
    if master_key == MASTER_KEY:
        g.is_master = True
        g.tenant_id = None # Master operates globally or specifies tenant in payload
        return

    # 2. Admin Key (Tenant Admin)
    admin_key = request.headers.get('X-Admin-Key') or request.args.get('key')
    if admin_key:
        tenant_id = get_tenant_from_key(admin_key)
        if tenant_id:
            g.tenant_id = tenant_id
            g.is_admin = True
            return

    # 3. Client Requests (Register/Auth)
    g.tenant_id = request.headers.get('X-Tenant-ID', 'default')
    g.is_admin = False

@app.before_request
def before_request():
    request.start_time = time.time()
    authenticate_request()

@app.after_request
def after_request(response):
    if request.endpoint == 'metrics':
        return response

    latency = time.time() - request.start_time
    endpoint = request.endpoint if request.endpoint else 'unknown'

    HTTP_REQUESTS.labels(request.method, endpoint, response.status_code).inc()
    HTTP_LATENCY.labels(endpoint).observe(latency)
    return response

def require_sysadmin(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not getattr(g, 'is_master', False):
             return jsonify({"error": "Unauthorized. System Admin required."}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if getattr(g, 'is_master', False):
            return f(*args, **kwargs)
        if getattr(g, 'is_admin', False) and g.tenant_id:
            return f(*args, **kwargs)

        logger.warning(f"[AUTH] Admin access denied from {request.remote_addr}")
        return jsonify({"error": "Unauthorized. Invalid Admin Key."}), 401
    return decorated_function

def log_and_record(event_type, user_id, status, details=""):
    ip_address = request.remote_addr if request else "unknown"
    tenant_id = getattr(g, 'tenant_id', 'unknown')

    log_msg = f"[{event_type}] Tenant: {tenant_id} | User: {user_id} | IP: {ip_address} | Status: {status} | {details}"

    if status == "SUCCESS":
        logger.info(log_msg)
    elif status == "DURESS" or status == "ABUSE":
        logger.critical(f"🚨 {status} SIGNAL: {log_msg}")
        send_webhook_alert(event_type, user_id, status, details)
        ACTIVE_THREATS.labels(status, tenant_id).inc()
    else:
        logger.warning(log_msg)

    # Update Prometheus
    MFA_EVENTS.labels(event_type, status, tenant_id).inc()

    try:
        log_entry = AuditLog(
            tenant_id=tenant_id,
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
        # 1. IP Blacklist Check (Scoped to Tenant)
        blacklist = IPBlacklist.query.filter_by(tenant_id=g.tenant_id).all()
        req_ip = ipaddress.ip_address(ip_addr)

        for entry in blacklist:
            try:
                if req_ip in ipaddress.ip_network(entry.cidr):
                    return False, f"IP Blacklisted: {entry.reason}"
            except ValueError:
                continue

        # 2. Business Hours Check (Scoped to Tenant)
        setting = SystemSetting.query.filter_by(key='business_hours_enabled', tenant_id=g.tenant_id).first()
        if setting and setting.value == 'true':
            current_hour = datetime.datetime.now().hour
            if current_hour < 8 or current_hour >= 18:
                return False, "Access denied outside business hours (08:00 - 18:00)"

        return True, None
    except Exception as e:
        logger.error(f"Policy check error: {e}")
        return True, None

def send_push_notification(push_url, payload):
    """Sends simulated push to the client listener."""
    try:
        requests.post(push_url, json=payload, timeout=1)
        logger.info(f"Push notification sent to {push_url}")
    except Exception as e:
        logger.warning(f"Failed to send push: {e}")

# --- SysAdmin Routes (Multi-Tenancy Provisioning) ---

@app.route('/sys/tenants', methods=['POST'])
@require_sysadmin
def create_tenant():
    name = request.json.get('name')
    if not name: return jsonify({"error": "Missing name"}), 400

    tenant = Tenant(name=name)
    db.session.add(tenant)
    db.session.commit()
    return jsonify({"message": "Tenant created", "id": tenant.id}), 201

@app.route('/sys/keys', methods=['POST'])
@require_sysadmin
def create_api_key():
    tenant_id = request.json.get('tenant_id')
    raw_key = request.json.get('key') # Sysadmin provides the key secret, or we generate it

    if not tenant_id or not raw_key:
        return jsonify({"error": "Missing tenant_id or key"}), 400

    h = hash_key(raw_key)
    if ApiKey.query.get(h):
        return jsonify({"error": "Key already exists"}), 400

    db.session.add(ApiKey(key_hash=h, tenant_id=tenant_id))
    db.session.commit()
    return jsonify({"message": "Key registered for tenant"}), 201

@app.route('/admin/provision/qrcode', methods=['POST'])
@require_admin
def generate_provisioning_qr():
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    # Create Configuration Payload
    # Note: request.host_url includes scheme and port (e.g., http://127.0.0.1:5000/)
    config = {
        "url": request.host_url.rstrip('/'),
        "tenant_id": g.tenant_id,
        "user_id": user_id
    }
    payload_str = json.dumps(config)

    # Generate QR Code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(payload_str)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Save to Buffer
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    # Encode Base64
    b64_img = base64.b64encode(buf.getvalue()).decode('utf-8')
    data_uri = f"data:image/png;base64,{b64_img}"

    # Generate Smart Code (Base64 of Payload)
    smart_code = base64.b64encode(payload_str.encode('utf-8')).decode('utf-8')

    return jsonify({
        "user_id": user_id,
        "qr_image": data_uri,
        "payload": payload_str,
        "smart_code": smart_code
    })

# --- User Routes (Tenant Scoped) ---

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user_id = data.get('user_id')
    public_key_pem_hex = data.get('public_key_pem_hex')
    push_endpoint = data.get('push_endpoint')

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

        # Generate Backup Codes
        codes = generate_backup_codes()
        hashed_codes = [hash_key(c) for c in codes]

        # Save User (Composite PK)
        user = User.query.get((user_id, g.tenant_id))
        if not user:
            user = User(
                user_id=user_id,
                tenant_id=g.tenant_id,
                public_key_pem=public_key_pem,
                push_endpoint=push_endpoint,
                backup_codes=json.dumps(hashed_codes)
            )
            db.session.add(user)
        else:
            user.public_key_pem = public_key_pem
            user.push_endpoint = push_endpoint
            user.backup_codes = json.dumps(hashed_codes)

        # Clear security stats
        UserSecurity.query.filter_by(user_id=user_id, tenant_id=g.tenant_id).delete()

        db.session.commit()
        verifier.register_user(user_id, public_key_pem)

        log_and_record("REGISTER", user_id, "SUCCESS", "User registered")
        return jsonify({
            "message": f"User {user_id} registered successfully.",
            "backup_codes": codes
        }), 201
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

    sec_record = UserSecurity.query.get((user_id, g.tenant_id))
    if sec_record:
        if sec_record.lock_type == 'PERMANENT':
            log_and_record("CHALLENGE", user_id, "BLOCK", "User Soft Locked (Abuse)")
            return jsonify({"error": "Device Soft Locked due to abuse. Contact Admin."}), 403

        if sec_record.locked_until and datetime.datetime.now() < sec_record.locked_until:
            log_and_record("CHALLENGE", user_id, "BLOCK", "User Locked")
            return jsonify({"error": "Account temporarily locked."}), 403

    user = User.query.get((user_id, g.tenant_id))
    if not user:
        log_and_record("CHALLENGE", user_id, "FAIL", "User not found")
        return jsonify({"error": "User not found"}), 404

    otp = verifier.generate_otp()

    challenge = ActiveChallenge.query.get((user_id, g.tenant_id))
    if not challenge:
        challenge = ActiveChallenge(user_id=user_id, tenant_id=g.tenant_id)
        db.session.add(challenge)
    challenge.otp = otp
    challenge.created_at = datetime.datetime.now()
    db.session.commit()

    encrypted_blob = verifier.encrypt_otp_for_user(user_id, otp)
    log_and_record("CHALLENGE", user_id, "SUCCESS", "OTP generated")

    # Push Notification Simulation
    if user.push_endpoint:
        send_push_notification(user.push_endpoint, {
            "title": "Indigo MFA Login Request",
            "encrypted_challenge_hex": encrypted_blob.hex()
        })

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

    sec_record = UserSecurity.query.get((user_id, g.tenant_id))
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
                failed_attempts = 0
    else:
        sec_record = UserSecurity(user_id=user_id, tenant_id=g.tenant_id)
        db.session.add(sec_record)

    # 1. Check Backup Codes First (if user exists)
    user = User.query.get((user_id, g.tenant_id))
    used_backup = False

    if user and user.backup_codes:
        hashed_input = hash_key(submitted_otp)
        codes = json.loads(user.backup_codes)
        if hashed_input in codes:
            # Valid Backup Code!
            codes.remove(hashed_input)
            user.backup_codes = json.dumps(codes)

            # Reset security
            sec_record.failed_attempts = 0
            sec_record.locked_until = None
            sec_record.lock_type = 'NONE'
            db.session.commit()

            log_and_record("AUTH", user_id, "SUCCESS", "Used Emergency Backup Code")
            return jsonify({"status": "success", "message": "Authentication Successful (Backup Code)"}), 200

    # 2. Check Standard OTP
    challenge = ActiveChallenge.query.get((user_id, g.tenant_id))
    if not challenge:
        log_and_record("AUTH", user_id, "FAIL", "No active challenge")
        return jsonify({"error": "No active challenge found"}), 400

    if datetime.datetime.now() - challenge.created_at > datetime.timedelta(minutes=5):
        log_and_record("AUTH", user_id, "FAIL", "OTP Expired")
        return jsonify({"error": "OTP Expired."}), 400

    original_otp = challenge.otp
    status = verifier.verify_otp(original_otp, submitted_otp)

    if status == VerificationStatus.VALID or status == VerificationStatus.DURESS:
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

# --- Admin Routes (Tenant Scoped) ---

@app.route('/admin/user/<user_id>/lock', methods=['POST'])
@require_admin
def admin_lock_user(user_id):
    sec = UserSecurity.query.get((user_id, g.tenant_id))
    if not sec:
        sec = UserSecurity(user_id=user_id, tenant_id=g.tenant_id)
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
    sec = UserSecurity.query.get((user_id, g.tenant_id))
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
    # Filter by Tenant
    results = db.session.query(User, UserSecurity)\
        .filter(User.tenant_id == g.tenant_id)\
        .outerjoin(UserSecurity, (User.user_id == UserSecurity.user_id) & (User.tenant_id == UserSecurity.tenant_id))\
        .all()

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

        # Get count of codes
        codes_count = 0
        if u.backup_codes:
            codes_count = len(json.loads(u.backup_codes))

        users_list.append({
            "user_id": u.user_id,
            "status": status,
            "failed_attempts": fails,
            "push_enabled": bool(u.push_endpoint),
            "backup_codes_count": codes_count
        })
    return jsonify(users_list)

@app.route('/admin/settings', methods=['GET', 'POST'])
@require_admin
def admin_settings():
    if request.method == 'POST':
        data = request.json
        for key, val in data.items():
            setting = SystemSetting.query.get((key, g.tenant_id))
            if not setting:
                setting = SystemSetting(key=key, tenant_id=g.tenant_id)
                db.session.add(setting)
            setting.value = str(val)
        db.session.commit()
        return jsonify({"message": "Settings updated"}), 200
    else:
        settings = SystemSetting.query.filter_by(tenant_id=g.tenant_id).all()
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
            entry = IPBlacklist(cidr=cidr, tenant_id=g.tenant_id, reason=reason)
            db.session.merge(entry)
            db.session.commit()
            return jsonify({"message": "IP Blocked"}), 201
        except ValueError:
            return jsonify({"error": "Invalid CIDR"}), 400
    elif request.method == 'DELETE':
        cidr = request.json.get('cidr')
        IPBlacklist.query.filter_by(cidr=cidr, tenant_id=g.tenant_id).delete()
        db.session.commit()
        return jsonify({"message": "IP Unblocked"}), 200
    else:
        items = IPBlacklist.query.filter_by(tenant_id=g.tenant_id).order_by(IPBlacklist.created_at.desc()).all()
        return jsonify([{"cidr": i.cidr, "reason": i.reason, "created_at": i.created_at} for i in items])

@app.route('/admin/export/logs')
@require_admin
def admin_export_logs():
    fmt = request.args.get('format', 'csv')
    filter_type = request.args.get('filter', 'all')

    query = AuditLog.query.filter_by(tenant_id=g.tenant_id)
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

@app.route('/admin/maintenance/prune', methods=['POST'])
@require_admin
def admin_prune_logs():
    days = request.json.get('days', 30)
    try:
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=int(days))
        deleted = AuditLog.query.filter(
            AuditLog.tenant_id == g.tenant_id,
            AuditLog.timestamp < cutoff
        ).delete()
        db.session.commit()
        log_and_record("MAINTENANCE", "admin", "SUCCESS", f"Pruned {deleted} logs older than {days} days")
        return jsonify({"message": f"Deleted {deleted} old logs."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user/<user_id>/revoke', methods=['DELETE'])
@require_admin
def revoke_user(user_id):
    User.query.filter_by(user_id=user_id, tenant_id=g.tenant_id).delete()
    ActiveChallenge.query.filter_by(user_id=user_id, tenant_id=g.tenant_id).delete()
    UserSecurity.query.filter_by(user_id=user_id, tenant_id=g.tenant_id).delete()
    db.session.commit()

    log_and_record("REVOKE", user_id, "SUCCESS", "Key revoked by admin")
    return jsonify({"message": f"User {user_id} revoked."}), 200

@app.route('/api/stats')
@require_admin
def api_stats():
    # Only Admin can see Stats now, for their Tenant
    tenant_id = g.tenant_id

    total_users = AuditLog.query.filter_by(tenant_id=tenant_id, event_type='REGISTER', status='SUCCESS').count()
    success_auth = AuditLog.query.filter_by(tenant_id=tenant_id, event_type='AUTH', status='SUCCESS').count()
    fail_auth = AuditLog.query.filter_by(tenant_id=tenant_id, event_type='AUTH', status='FAIL').count()

    blocked = UserSecurity.query.filter(
        UserSecurity.tenant_id == tenant_id,
        (UserSecurity.locked_until != None) | (UserSecurity.lock_type == 'PERMANENT')
    ).count()

    threats = AuditLog.query.filter(AuditLog.tenant_id == tenant_id, AuditLog.status.in_(['DURESS', 'ABUSE'])).count()

    logs = AuditLog.query.filter_by(tenant_id=tenant_id).order_by(AuditLog.id.desc()).limit(10).all()
    recent_logs = [{
        "timestamp": l.timestamp.isoformat(),
        "event": l.event_type,
        "user": l.user_id,
        "status": l.status,
        "details": l.details,
        "ip": l.ip_address or "unknown"
    } for l in logs]

    soft_locked = UserSecurity.query.filter_by(tenant_id=tenant_id, lock_type='PERMANENT').all()
    soft_locked_list = [{"user_id": u.user_id, "fails": u.failed_attempts} for u in soft_locked]

    biz_hours_setting = SystemSetting.query.get(('business_hours_enabled', tenant_id))
    biz_hours = (biz_hours_setting.value == 'true') if biz_hours_setting else False
    blacklist = IPBlacklist.query.filter_by(tenant_id=tenant_id).all()
    blacklist_data = [{"cidr": b.cidr, "reason": b.reason} for b in blacklist]

    # Advanced
    one_day_ago = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    recent_auths = AuditLog.query.filter(
        AuditLog.tenant_id == tenant_id,
        AuditLog.event_type == 'AUTH',
        AuditLog.timestamp > one_day_ago
    ).all()

    activity_map = {}
    for log in recent_auths:
        h = log.timestamp.strftime('%Y-%m-%d %H:00')
        activity_map[h] = activity_map.get(h, 0) + 1
    activity_data = [{"hour": k, "count": v} for k, v in sorted(activity_map.items())]

    failures = AuditLog.query.filter(AuditLog.tenant_id == tenant_id, AuditLog.status != 'SUCCESS').all()
    fail_map = {}
    for log in failures:
        label = log.details
        if "Invalid OTP" in label: label = "Invalid OTP"
        elif "Expired" in label: label = "OTP Expired"
        elif "Locked" in label: label = "Account Locked"
        fail_map[label] = fail_map.get(label, 0) + 1
    failure_data = [{"label": k, "count": v} for k, v in sorted(fail_map.items(), key=lambda item: item[1], reverse=True)[:5]]

    return jsonify({
        "tenant_id": tenant_id,
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

# Unsecured Dashboard endpoint (Serves HTML)
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/health')
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify({"status": "healthy"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

if __name__ == "__main__":
    with app.app_context():
        init_db_data()
    app.run(host='0.0.0.0', port=5000)
