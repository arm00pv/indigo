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
import math
import qrcode
import click
from flask import Flask, request, jsonify, render_template, Response, g, send_file
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from backend.models import db, User, ActiveChallenge, AuditLog, UserSecurity, SystemSetting, IPBlacklist, Tenant, ApiKey, NotificationChannel
from backend.utils import generate_backup_codes

# Add project root to path so we can import mfa_sdk
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mfa_sdk.verifier import Verifier, VerificationStatus
from mfa_sdk.crypto import CryptoUtils
from backend.notifications import send_alert, send_legacy_webhook

app = Flask(__name__)

# --- Configuration ---
# MASTER_KEY is for System Admins to create Tenants
MASTER_KEY = os.environ.get("MASTER_KEY", "master-secret-key")

# Default to SQLite if not provided
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f"sqlite:///{os.path.join(os.path.dirname(__file__), 'mfa.db')}")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# --- Logging Setup ---
if not os.path.exists("logs"):
    try:
        os.makedirs("logs")
    except:
        pass

from logging.handlers import RotatingFileHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler("logs/app.log", maxBytes=10*1024*1024, backupCount=5),
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

def get_ip_location(ip):
    # Mock/Real implementation
    if ip in ["127.0.0.1", "localhost", "::1"] or ip.startswith("192.168.") or ip.startswith("10."):
        return "Local Network", None, None
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                loc_str = f"{data.get('city')}, {data.get('country')}"
                return loc_str, data.get('lat'), data.get('lon')
    except Exception as e:
        logger.warning(f"IP Location lookup failed for {ip}: {e}")
    return "Unknown", None, None

def calculate_distance(lat1, lon1, lat2, lon2):
    # Haversine formula
    R = 6371 # Earth radius in km
    dLat = math.radians(lat2 - lat1)
    dLon = math.radians(lon2 - lon1)
    a = math.sin(dLat/2) * math.sin(dLat/2) + \
        math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * \
        math.sin(dLon/2) * math.sin(dLon/2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    d = R * c
    return d

def init_db_data():
    """Initialize DB tables if not exist."""

    db.create_all()
    # Ensure Default Tenant exists
    if not db.session.get(Tenant, "default"):
        default_tenant = Tenant(id="default", name="Default Organization")
        db.session.add(default_tenant)
        db.session.flush()

        # Check env var for seed (Optional: Only create if ENV is set)
        k = os.environ.get("ADMIN_API_KEY")
        if k:
            h = hashlib.sha256(k.encode()).hexdigest()
            if not db.session.get(ApiKey, h):
                db.session.add(ApiKey(key_hash=h, tenant_id="default"))
                logger.info(f"Initialized Database with Provided Admin Key.")
        else:
            # Final check: If NO keys exist, log it clearly
            count = db.session.query(ApiKey).count()
            if count == 0:
                logger.warning("!!! SYSTEM UNINITIALIZED: No Admin Keys found. Access / to see Setup Wizard. !!!")
            else:
                logger.info(f"System Initialized ({count} keys found).")

        # Default Settings
        if not db.session.get(SystemSetting, ('business_hours_enabled', 'default')):
            db.session.add(SystemSetting(key='business_hours_enabled', value='false', tenant_id="default"))
        if not db.session.get(SystemSetting, ('log_retention_days', 'default')):
            db.session.add(SystemSetting(key='log_retention_days', value='90', tenant_id="default"))

        db.session.commit()

    # Check for missing columns (manual migration)
    try:
        inspector = db.inspect(db.engine)
        columns = [c['name'] for c in inspector.get_columns('user_security')]
        if 'last_ip' not in columns:
            logger.info("Migrating DB: Adding last_ip to user_security")
            db.session.execute(db.text("ALTER TABLE user_security ADD COLUMN last_ip TEXT"))
        if 'last_user_agent' not in columns:
            logger.info("Migrating DB: Adding last_user_agent to user_security")
            db.session.execute(db.text("ALTER TABLE user_security ADD COLUMN last_user_agent TEXT"))
        if 'last_login_at' not in columns:
            logger.info("Migrating DB: Adding last_login_at to user_security")
            db.session.execute(db.text("ALTER TABLE user_security ADD COLUMN last_login_at DATETIME"))
        if 'last_lat' not in columns:
            logger.info("Migrating DB: Adding last_lat to user_security")
            db.session.execute(db.text("ALTER TABLE user_security ADD COLUMN last_lat FLOAT"))
        if 'last_lon' not in columns:
            logger.info("Migrating DB: Adding last_lon to user_security")
            db.session.execute(db.text("ALTER TABLE user_security ADD COLUMN last_lon FLOAT"))
        db.session.commit()
    except Exception as e:
        logger.warning(f"Migration check failed: {e}")

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
    api_key = db.session.get(ApiKey, h)
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

def dispatch_alerts(event_type, user_id, status, details):
    tenant_id = getattr(g, 'tenant_id', None)
    if not tenant_id or tenant_id == 'unknown':
        return

    try:
        channels = NotificationChannel.query.filter_by(tenant_id=tenant_id).all()
        for ch in channels:
            try:
                events = json.loads(ch.events)
                if status not in events and event_type not in events:
                    continue

                channel_config = {
                    "type": ch.channel_type,
                    "config": json.loads(ch.config)
                }
                send_alert(tenant_id, event_type, user_id, status, details, channel_config)
            except Exception as e:
                logger.error(f"Channel {ch.id} error: {e}")
    except Exception as e:
        logger.error(f"Dispatch error: {e}")

def log_and_record(event_type, user_id, status, details=""):
    ip_address = request.remote_addr if request else "unknown"
    tenant_id = getattr(g, 'tenant_id', 'unknown')

    # Enrich with Location if Auth related
    if status in ["SUCCESS", "DURESS", "ABUSE"] and event_type in ["AUTH", "CHALLENGE"]:
        loc_str, _, _ = get_ip_location(ip_address)
        if loc_str != "Unknown":
            details = f"{details} [{loc_str}]"

    log_msg = f"[{event_type}] Tenant: {tenant_id} | User: {user_id} | IP: {ip_address} | Status: {status} | {details}"

    if status == "SUCCESS":
        logger.info(log_msg)
    elif status == "DURESS" or status == "ABUSE":
        logger.critical(f"🚨 {status} SIGNAL: {log_msg}")
        # Legacy Global Webhook
        send_legacy_webhook(event_type, user_id, status, details)
        # Multi-Channel Alerts
        ACTIVE_THREATS.labels(status, tenant_id).inc()
        dispatch_alerts(event_type, user_id, status, details)
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
            timestamp=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
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
    if db.session.get(ApiKey, h):
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
        user = db.session.get(User, (user_id, g.tenant_id))
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
    context = data.get('context')

    allowed, reason = check_policy_compliance(request.remote_addr)
    if not allowed:
        log_and_record("CHALLENGE", user_id, "BLOCK", reason)
        return jsonify({"error": reason}), 403

    sec_record = db.session.get(UserSecurity, (user_id, g.tenant_id))
    if sec_record:
        if sec_record.lock_type == 'PERMANENT':
            log_and_record("CHALLENGE", user_id, "BLOCK", "User Soft Locked (Abuse)")
            return jsonify({"error": "Device Soft Locked due to abuse. Contact Admin."}), 403

        if sec_record.locked_until and datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) < sec_record.locked_until:
            log_and_record("CHALLENGE", user_id, "BLOCK", "User Locked")
            remaining = int((sec_record.locked_until - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).total_seconds())
            resp = jsonify({"error": f"Account temporarily locked. Try again in {remaining}s."})
            resp.status_code = 403
            resp.headers['Retry-After'] = remaining
            return resp

    user = db.session.get(User, (user_id, g.tenant_id))
    if not user:
        log_and_record("CHALLENGE", user_id, "FAIL", "User not found")
        return jsonify({"error": "User not found"}), 404

    otp = verifier.generate_otp()

    challenge = db.session.get(ActiveChallenge, (user_id, g.tenant_id))
    if not challenge:
        challenge = ActiveChallenge(user_id=user_id, tenant_id=g.tenant_id)
        db.session.add(challenge)
    challenge.otp = otp
    challenge.created_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    db.session.commit()

    encrypted_blob = verifier.encrypt_otp_for_user(user_id, otp, context=context)
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

    sec_record = db.session.get(UserSecurity, (user_id, g.tenant_id))
    failed_attempts = 0

    if sec_record:
        failed_attempts = sec_record.failed_attempts
        if sec_record.lock_type == 'PERMANENT':
            log_and_record("AUTH", user_id, "BLOCK", "User Soft Locked (Abuse)")
            return jsonify({"error": "Device Soft Locked."}), 403

        if sec_record.locked_until:
            if datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) < sec_record.locked_until:
                log_and_record("AUTH", user_id, "BLOCK", "User Locked")
                return jsonify({"error": "Account temporarily locked."}), 403
            else:
                failed_attempts = 0
    else:
        sec_record = UserSecurity(user_id=user_id, tenant_id=g.tenant_id)
        db.session.add(sec_record)

    # 1. Check Backup Codes First (if user exists)
    user = db.session.get(User, (user_id, g.tenant_id))
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
    challenge = db.session.get(ActiveChallenge, (user_id, g.tenant_id))
    if not challenge:
        log_and_record("AUTH", user_id, "FAIL", "No active challenge")
        return jsonify({"error": "No active challenge found"}), 400

    if datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - challenge.created_at > datetime.timedelta(minutes=5):
        log_and_record("AUTH", user_id, "FAIL", "OTP Expired")
        return jsonify({"error": "OTP Expired."}), 400

    original_otp = challenge.otp
    status = verifier.verify_otp(original_otp, submitted_otp)

    if status == VerificationStatus.VALID or status == VerificationStatus.DURESS:
        db.session.delete(challenge)
        sec_record.failed_attempts = 0
        sec_record.locked_until = None
        sec_record.lock_type = 'NONE'

        # Security Tracking
        current_ip = request.remote_addr
        current_ua = request.headers.get('User-Agent')
        loc_str, lat, lon = get_ip_location(current_ip)

        # Impossible Travel Check
        if sec_record.last_lat and sec_record.last_lon and lat and lon and sec_record.last_login_at:
            # Calculate time diff in hours
            time_diff = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - sec_record.last_login_at).total_seconds() / 3600
            dist = calculate_distance(sec_record.last_lat, sec_record.last_lon, lat, lon)

            if dist > 100: # Ignore small jumps
                speed = dist / time_diff if time_diff > 0 else 99999
                if speed > 800: # 800 km/h
                    log_and_record("AUTH", user_id, "ABUSE", f"Impossible Travel: {dist:.0f}km in {time_diff:.1f}h ({speed:.0f} km/h)")

        if sec_record.last_ip and sec_record.last_ip != current_ip:
            log_and_record("AUTH", user_id, "WARN", f"IP Change: {sec_record.last_ip} -> {current_ip}")

        sec_record.last_ip = current_ip
        sec_record.last_user_agent = current_ua
        sec_record.last_login_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        sec_record.last_lat = lat
        sec_record.last_lon = lon

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

        # Load Policy Settings
        s_soft = db.session.get(SystemSetting, ('policy_max_failures_soft_lock', g.tenant_id))
        limit_soft = int(s_soft.value) if s_soft else 10

        s_temp = db.session.get(SystemSetting, ('policy_max_failures_temp_lock', g.tenant_id))
        limit_temp = int(s_temp.value) if s_temp else 5

        s_dur = db.session.get(SystemSetting, ('policy_temp_lock_duration_seconds', g.tenant_id))
        duration = int(s_dur.value) if s_dur else 900

        if failed_attempts >= limit_soft:
            sec_record.lock_type = 'PERMANENT'
            log_and_record("AUTH", user_id, "ABUSE", "Soft Lock Activated")
            msg = "Device Soft Locked due to abuse."
            code = 403
        elif failed_attempts >= limit_temp:
            sec_record.locked_until = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(seconds=duration)
            sec_record.lock_type = 'TEMP'
            log_and_record("AUTH", user_id, "BLOCK", "Temp Lock Activated")
            msg = f"Too many failures. Locked for {duration}s."

            # Return Retry-After header
            response = jsonify({"status": "failure", "message": msg})
            response.status_code = 403
            response.headers['Retry-After'] = duration

            db.session.commit()
            return response
        else:
            log_and_record("AUTH", user_id, "FAIL", f"Invalid OTP (Attempt {failed_attempts}/{limit_soft})")

        db.session.commit()
        return jsonify({"status": "failure", "message": msg}), code

# --- Admin Routes (Tenant Scoped) ---

@app.route('/admin/user/<user_id>/lock', methods=['POST'])
@require_admin
def admin_lock_user(user_id):
    sec = db.session.get(UserSecurity, (user_id, g.tenant_id))
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
    sec = db.session.get(UserSecurity, (user_id, g.tenant_id))
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
            elif s.locked_until and datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) < s.locked_until:
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
            "backup_codes_count": codes_count,
            "last_ip": s.last_ip if s else None,
            "last_user_agent": s.last_user_agent if s else None,
            "last_login_at": s.last_login_at.isoformat() if s and s.last_login_at else None
        })
    return jsonify(users_list)

@app.route('/admin/settings', methods=['GET', 'POST'])
@require_admin
def admin_settings():
    if request.method == 'POST':
        data = request.json
        for key, val in data.items():
            setting = db.session.get(SystemSetting, (key, g.tenant_id))
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
    elif filter_type == 'admin':
        query = query.filter(AuditLog.event_type.in_(['ADMIN', 'MAINTENANCE', 'REVOKE', 'POLICY']))

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

def model_to_dict(obj):
    d = {}
    for c in obj.__table__.columns:
        val = getattr(obj, c.name)
        if isinstance(val, bytes):
            val = base64.b64encode(val).decode('utf-8')
        d[c.name] = val
    return d

@app.cli.command("doctor")
def doctor_command():
    """Checks system health and configuration."""
    print("=== Indigo MFA Doctor ===")

    # 1. DB Connection
    try:
        db.session.execute(db.text("SELECT 1"))
        print("[PASS] Database Connection")
    except Exception as e:
        print(f"[FAIL] Database Connection: {e}")

    # 2. Key Check
    try:
        keys = db.session.query(ApiKey).count()
        if keys > 0:
            print(f"[PASS] {keys} Admin Keys found.")
        else:
            print("[FAIL] No Admin Keys found! Run 'flask add-admin'.")
    except Exception as e:
        print(f"[FAIL] Key Check Error: {e}")

    # 3. Permissions
    for d in ["logs", "backups"]:
        path = os.path.join(os.getcwd(), d)
        if not os.path.exists(path):
            try:
                os.makedirs(path)
                print(f"[PASS] Created directory {d}")
            except:
                print(f"[FAIL] Could not create {d}")
        elif os.access(path, os.W_OK):
            print(f"[PASS] Write access to {d}")
        else:
            print(f"[FAIL] No write access to {d}")

    print("=== Done ===")

@app.cli.command("backup")
def backup_command():
    """Backs up the entire database to a JSON file."""
    backup_dir = os.path.join(os.getcwd(), "backups")
    os.makedirs(backup_dir, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    data = {
        "tenants": [model_to_dict(x) for x in Tenant.query.all()],
        "api_keys": [model_to_dict(x) for x in ApiKey.query.all()],
        "users": [model_to_dict(x) for x in User.query.all()],
        "user_security": [model_to_dict(x) for x in UserSecurity.query.all()],
        "system_settings": [model_to_dict(x) for x in SystemSetting.query.all()],
        "ip_blacklist": [model_to_dict(x) for x in IPBlacklist.query.all()],
        "notification_channels": [model_to_dict(x) for x in NotificationChannel.query.all()],
        "audit_logs": [model_to_dict(x) for x in AuditLog.query.all()],
    }

    path = os.path.join(backup_dir, f"indigo_full_backup_{ts}.json")
    with open(path, 'w') as f:
        json.dump(data, f, default=str, indent=2)
    print(f"Backup saved to {path}")

@app.cli.command("restore")
@click.argument("filename")
def restore_command(filename):
    """Restores the database from a JSON backup file."""
    if not os.path.exists(filename):
        print(f"Error: File {filename} not found.")
        return

    with open(filename, 'r') as f:
        data = json.load(f)

    print(f"Restoring from {filename}...")

    # Order matters due to Foreign Keys
    models_map = [
        ('tenants', Tenant),
        ('api_keys', ApiKey),
        ('users', User),
        ('user_security', UserSecurity),
        ('system_settings', SystemSetting),
        ('ip_blacklist', IPBlacklist),
        ('notification_channels', NotificationChannel),
        ('audit_logs', AuditLog)
    ]

    try:
        for key, model in models_map:
            items = data.get(key, [])
            print(f"Restoring {len(items)} {key}...")
            for item in items:
                # Convert dict to model
                row_data = {}
                for c in model.__table__.columns:
                    if c.name in item:
                        val = item[c.name]
                        # Helper inline
                        if isinstance(c.type, db.LargeBinary) and isinstance(val, str):
                            try:
                                val = base64.b64decode(val)
                            except:
                                pass

                        if isinstance(c.type, db.DateTime) and isinstance(val, str):
                            try:
                                val = datetime.datetime.fromisoformat(val)
                            except:
                                pass

                        row_data[c.name] = val

                db.session.merge(model(**row_data))
            db.session.commit()
        print("Restore complete.")
    except Exception as e:
        db.session.rollback()
        print(f"Restore failed: {e}")

@app.cli.command("add-admin")
@click.option("--key", prompt=True, hide_input=True, confirmation_prompt=True, help="The Admin API Key.")
@click.option("--tenant", default="default", help="The Tenant ID (default: default).")
def add_admin_command(key, tenant):
    """Adds a new Admin API Key."""
    h = hash_key(key)

    # Check if tenant exists
    t = db.session.get(Tenant, tenant)
    if not t:
        print(f"Error: Tenant '{tenant}' does not exist.")
        return

    if db.session.get(ApiKey, h):
        print("Error: Key already exists.")
        return

    db.session.add(ApiKey(key_hash=h, tenant_id=tenant))
    db.session.commit()
    print(f"Admin Key added for tenant '{tenant}'.")

@app.cli.command("prune-logs")
@click.option("--days", default=30, help="Retention days.")
def prune_logs_command(days):
    """Delete old audit logs."""
    try:
        cutoff = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(days=int(days))
        deleted = AuditLog.query.filter(AuditLog.timestamp < cutoff).delete()
        db.session.commit()
        print(f"Pruned {deleted} logs older than {days} days.")
    except Exception as e:
        print(f"Error: {e}")

@app.route('/api/system/status', methods=['GET'])
def system_status():
    """Checks if the system is initialized (has admin keys)."""
    try:
        count = db.session.query(ApiKey).count()
        return jsonify({"initialized": count > 0})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/setup', methods=['POST'])
def setup_admin():
    """Initial Setup Wizard: Create the first admin key."""
    # Security Check: Only allow if NO keys exist
    if db.session.query(ApiKey).count() > 0:
        return jsonify({"error": "System already initialized."}), 403

    raw_key = request.json.get('key')
    if not raw_key or len(raw_key) < 8:
        return jsonify({"error": "Invalid key provided (min 8 chars)."}), 400

    # Create Key
    h = hash_key(raw_key)
    # Ensure tenant exists (it should from init-db)
    if not db.session.get(Tenant, "default"):
        db.session.add(Tenant(id="default", name="Default Organization"))

    db.session.add(ApiKey(key_hash=h, tenant_id="default"))
    db.session.commit()

    log_and_record("ADMIN", "system", "SUCCESS", "System Initialized via Setup Wizard")
    return jsonify({"message": "Setup Complete. You can now login."}), 201

@app.route('/admin/system/health', methods=['GET'])
@require_admin
def admin_system_health():
    """Returns system health status."""
    status = "healthy"
    checks = []

    # DB
    try:
        db.session.execute(db.text("SELECT 1"))
        checks.append({"name": "Database", "status": "pass"})
    except Exception as e:
        status = "unhealthy"
        checks.append({"name": "Database", "status": "fail", "error": str(e)})

    # Keys
    try:
        keys = db.session.query(ApiKey).count()
        if keys > 0:
            checks.append({"name": "Admin Keys", "status": "pass", "count": keys})
        else:
            status = "unhealthy"
            checks.append({"name": "Admin Keys", "status": "fail", "error": "No keys found"})
    except:
        pass

    # Permissions
    for d in ["logs", "backups"]:
        path = os.path.join(os.getcwd(), d)
        if os.path.exists(path) and os.access(path, os.W_OK):
            checks.append({"name": f"Permission: {d}", "status": "pass"})
        else:
            status = "unhealthy"
            checks.append({"name": f"Permission: {d}", "status": "fail"})

    return jsonify({"status": status, "checks": checks})

@app.route('/admin/maintenance/backup', methods=['GET'])
@require_admin
def admin_backup_tenant():
    data = {
        "tenant_id": g.tenant_id,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "users": [model_to_dict(x) for x in User.query.filter_by(tenant_id=g.tenant_id).all()],
        "user_security": [model_to_dict(x) for x in UserSecurity.query.filter_by(tenant_id=g.tenant_id).all()],
        "system_settings": [model_to_dict(x) for x in SystemSetting.query.filter_by(tenant_id=g.tenant_id).all()],
        "ip_blacklist": [model_to_dict(x) for x in IPBlacklist.query.filter_by(tenant_id=g.tenant_id).all()],
        "notification_channels": [model_to_dict(x) for x in NotificationChannel.query.filter_by(tenant_id=g.tenant_id).all()],
        "audit_logs": [model_to_dict(x) for x in AuditLog.query.filter_by(tenant_id=g.tenant_id).all()],
    }
    return jsonify(data)

@app.route('/admin/maintenance/restore', methods=['POST'])
@require_admin
def admin_restore_tenant():
    # Placeholder for restore logic
    return jsonify({"message": "Restore functionality implemented via CLI import only currently."}), 501

@app.route('/admin/maintenance/prune', methods=['POST'])
@require_admin
def admin_prune_logs():
    days = request.json.get('days', 30)
    try:
        cutoff = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(days=int(days))
        deleted = AuditLog.query.filter(
            AuditLog.tenant_id == g.tenant_id,
            AuditLog.timestamp < cutoff
        ).delete()
        db.session.commit()
        log_and_record("MAINTENANCE", "admin", "SUCCESS", f"Pruned {deleted} logs older than {days} days")
        return jsonify({"message": f"Deleted {deleted} old logs."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/provision/pdf', methods=['POST'])
@require_admin
def generate_pdf_provisioning():
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    # Generate Config
    config = {
        "url": request.host_url.rstrip('/'),
        "tenant_id": g.tenant_id,
        "user_id": user_id
    }
    payload_str = json.dumps(config)
    smart_code = base64.b64encode(payload_str.encode('utf-8')).decode('utf-8')

    # Generate PDF
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 24)
    c.drawString(72, height - 72, "Indigo MFA - Enrollment")

    c.setFont("Helvetica", 14)
    c.drawString(72, height - 100, f"Organization: {g.tenant_id}")
    c.drawString(72, height - 120, f"User ID: {user_id}")

    c.drawString(72, height - 160, "Instructions:")
    c.setFont("Helvetica", 12)
    c.drawString(90, height - 180, "1. Download the Indigo Authenticator App.")
    c.drawString(90, height - 200, "2. Select 'Setup via QR / Smart Code'.")
    c.drawString(90, height - 220, "3. Scan the QR code below or enter the Smart Code.")

    # QR Code
    qr = qrcode.QRCode(box_size=5, border=2)
    qr.add_data(payload_str)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    qr_buf = io.BytesIO()
    img.save(qr_buf, format='PNG')
    qr_buf.seek(0)

    c.drawImage(ImageReader(qr_buf), 72, height - 450, width=200, height=200)

    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, height - 480, "Smart Code (Manual Entry):")

    text_obj = c.beginText(72, height - 500)
    text_obj.setFont("Courier", 10)
    # Split smart code into chunks
    chunks = [smart_code[i:i+60] for i in range(0, len(smart_code), 60)]
    for chunk in chunks:
        text_obj.textLine(chunk)
    c.drawText(text_obj)

    c.showPage()
    c.save()
    buf.seek(0)

    return send_file(buf, as_attachment=True, download_name=f"indigo_enroll_{user_id}.pdf", mimetype='application/pdf')

@app.route('/admin/provision/bulk', methods=['POST'])
@require_admin
def bulk_provision():
    raw_text = request.json.get('user_ids')
    if not raw_text:
        return jsonify({"error": "Missing user_ids"}), 400

    user_ids = [u.strip() for u in raw_text.replace(',', '\n').split('\n') if u.strip()]
    results = []

    for uid in user_ids:
        # Check if exists (Optional, not strictly required for provisioning payload)
        user = db.session.get(User, (uid, g.tenant_id))
        status = "Existing" if user else "Ready to Enroll"

        config = {
            "url": request.host_url.rstrip('/'),
            "tenant_id": g.tenant_id,
            "user_id": uid
        }
        payload = json.dumps(config)
        smart = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
        results.append({"user_id": uid, "status": status, "smart_code": smart})

    return jsonify(results)

@app.route('/admin/notifications', methods=['GET', 'POST'])
@require_admin
def admin_notifications():
    if request.method == 'POST':
        data = request.json
        ch_type = data.get('type')
        config = data.get('config') # JSON object
        events = data.get('events', []) # List of strings

        if not ch_type or not config:
            return jsonify({"error": "Missing type or config"}), 400

        channel = NotificationChannel(
            tenant_id=g.tenant_id,
            channel_type=ch_type,
            config=json.dumps(config),
            events=json.dumps(events)
        )
        db.session.add(channel)
        db.session.commit()
        return jsonify({"message": "Channel created", "id": channel.id}), 201
    else:
        channels = NotificationChannel.query.filter_by(tenant_id=g.tenant_id).all()
        return jsonify([{
            "id": c.id,
            "type": c.channel_type,
            "config": json.loads(c.config),
            "events": json.loads(c.events)
        } for c in channels])

@app.route('/admin/notifications/<channel_id>', methods=['DELETE'])
@require_admin
def admin_delete_notification(channel_id):
    NotificationChannel.query.filter_by(id=channel_id, tenant_id=g.tenant_id).delete()
    db.session.commit()
    return jsonify({"message": "Channel deleted"}), 200

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

    biz_hours_setting = db.session.get(SystemSetting, ('business_hours_enabled', tenant_id))
    biz_hours = (biz_hours_setting.value == 'true') if biz_hours_setting else False
    blacklist = IPBlacklist.query.filter_by(tenant_id=tenant_id).all()
    blacklist_data = [{"cidr": b.cidr, "reason": b.reason} for b in blacklist]

    # Advanced
    one_day_ago = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(hours=24)
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
            "blacklist": blacklist_data,
            "policy_max_failures_soft_lock": int(db.session.get(SystemSetting, ('policy_max_failures_soft_lock', tenant_id)).value) if db.session.get(SystemSetting, ('policy_max_failures_soft_lock', tenant_id)) else 10,
            "policy_max_failures_temp_lock": int(db.session.get(SystemSetting, ('policy_max_failures_temp_lock', tenant_id)).value) if db.session.get(SystemSetting, ('policy_max_failures_temp_lock', tenant_id)) else 5,
            "policy_temp_lock_duration_seconds": int(db.session.get(SystemSetting, ('policy_temp_lock_duration_seconds', tenant_id)).value) if db.session.get(SystemSetting, ('policy_temp_lock_duration_seconds', tenant_id)) else 900
        }
    })

# Unsecured Dashboard endpoint (Serves HTML)
@app.route('/')
def index():
    return render_template('dashboard.html')

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
