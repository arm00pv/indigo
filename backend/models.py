from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()

def gen_uuid():
    return str(uuid.uuid4())

class Tenant(db.Model):
    __tablename__ = 'tenants'
    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ApiKey(db.Model):
    __tablename__ = 'api_keys'
    key_hash = db.Column(db.String(64), primary_key=True) # SHA256 of the key
    tenant_id = db.Column(db.String(36), db.ForeignKey('tenants.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.String(255), primary_key=True)
    tenant_id = db.Column(db.String(36), db.ForeignKey('tenants.id'), primary_key=True) # Composite PK
    public_key_pem = db.Column(db.LargeBinary, nullable=False)
    push_endpoint = db.Column(db.String(500), nullable=True) # Webhook for Push Simulation
    backup_codes = db.Column(db.Text, nullable=True) # JSON list of hashed backup codes

class ActiveChallenge(db.Model):
    __tablename__ = 'active_challenges'
    user_id = db.Column(db.String(255), primary_key=True)
    tenant_id = db.Column(db.String(36), db.ForeignKey('tenants.id'), primary_key=True)
    otp = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String(36), db.ForeignKey('tenants.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(50))
    user_id = db.Column(db.String(255))
    status = db.Column(db.String(50))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))

class UserSecurity(db.Model):
    __tablename__ = 'user_security'
    user_id = db.Column(db.String(255), primary_key=True)
    tenant_id = db.Column(db.String(36), db.ForeignKey('tenants.id'), primary_key=True)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    lock_type = db.Column(db.String(20), default='NONE') # NONE, TEMP, PERMANENT
    last_ip = db.Column(db.String(50), nullable=True)
    last_user_agent = db.Column(db.String(255), nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_lat = db.Column(db.Float, nullable=True)
    last_lon = db.Column(db.Float, nullable=True)

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    key = db.Column(db.String(100), primary_key=True)
    tenant_id = db.Column(db.String(36), db.ForeignKey('tenants.id'), primary_key=True)
    value = db.Column(db.Text)

class IPBlacklist(db.Model):
    __tablename__ = 'ip_blacklist'
    cidr = db.Column(db.String(50), primary_key=True)
    tenant_id = db.Column(db.String(36), db.ForeignKey('tenants.id'), primary_key=True)
    reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class NotificationChannel(db.Model):
    __tablename__ = 'notification_channels'
    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    tenant_id = db.Column(db.String(36), db.ForeignKey('tenants.id'), nullable=False)
    channel_type = db.Column(db.String(20), nullable=False) # WEBHOOK, EMAIL
    config = db.Column(db.Text, nullable=False) # JSON
    events = db.Column(db.Text, nullable=False) # JSON List
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
