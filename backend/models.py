from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.String(255), primary_key=True)
    public_key_pem = db.Column(db.LargeBinary, nullable=False)

class ActiveChallenge(db.Model):
    __tablename__ = 'active_challenges'
    user_id = db.Column(db.String(255), primary_key=True)
    otp = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(50))
    user_id = db.Column(db.String(255))
    status = db.Column(db.String(50))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))

class UserSecurity(db.Model):
    __tablename__ = 'user_security'
    user_id = db.Column(db.String(255), primary_key=True)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    lock_type = db.Column(db.String(20), default='NONE') # NONE, TEMP, PERMANENT

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text)

class IPBlacklist(db.Model):
    __tablename__ = 'ip_blacklist'
    cidr = db.Column(db.String(50), primary_key=True)
    reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
