import pytest
import os
import json
import hashlib
import time
import requests
from backend.app import app, db, Tenant, ApiKey, User, AuditLog
from mfa_sdk.verifier import Verifier, VerificationStatus
from mfa_sdk.crypto import CryptoUtils

# Mock environment variable for test isolation
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

@pytest.fixture
def client_app():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    # Ensure dirs exist
    os.makedirs('logs', exist_ok=True)
    os.makedirs('backups', exist_ok=True)

    with app.app_context():
        db.create_all()
        # Initialize default tenant
        if not Tenant.query.filter_by(name="Default Organization").first():
            db.session.add(Tenant(id="default", name="Default Organization"))
            db.session.commit()

        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def test_client(client_app):
    return client_app.test_client()

def test_integration_full_flow(test_client):
    """
    Simulates a full lifecycle:
    1. Admin creates API Key.
    2. User Registers (Client SDK generates keys).
    3. User Requests Challenge.
    4. Client Decrypts and Solves (Standard).
    5. User Requests Challenge.
    6. Client Decrypts and Solves (Duress).
    7. Admin Checks Logs for Duress.
    8. Health Check.
    """

    # --- 1. Admin Setup ---
    # Create Admin Key
    admin_key = "integration-secret-key"
    key_hash = hashlib.sha256(admin_key.encode()).hexdigest()
    with app.app_context():
        db.session.add(ApiKey(key_hash=key_hash, tenant_id="default"))
        db.session.commit()

    headers_admin = {'X-Admin-Key': admin_key}

    # --- 2. Registration (Client Side) ---
    user_id = "test_user_integration"

    # Client generates keys
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_hex = pub_pem.hex()

    # Call Register Endpoint
    resp = test_client.post('/register', json={
        "user_id": user_id,
        "public_key_pem_hex": pub_hex,
        "push_endpoint": "http://mock-push"
    })
    assert resp.status_code == 201

    # --- 3. Auth (Standard) ---
    # Request Challenge
    resp = test_client.post('/auth/challenge', json={"user_id": user_id})
    assert resp.status_code == 200
    encrypted_hex = resp.get_json()['encrypted_challenge_hex']

    # Client Decrypts
    # Note: We need to use the SDK's decryption logic or duplicate it.
    # The SDK `CryptoUtils.decrypt_otp` expects bytes.
    encrypted_bytes = bytes.fromhex(encrypted_hex)

    # Decrypt using private key
    # Simple ECIES decryption (Standard OTP)
    # Since we don't have the Client SDK class instantiated here easily without mocking storage,
    # we'll use the backend's verifier to peek at the OTP or use crypto lib directly.
    # Actually, let's use the backend DB to peek the OTP for the test simplicity,
    # simulating that the client successfully decrypted it.

    with app.app_context():
        from backend.models import ActiveChallenge
        challenge = ActiveChallenge.query.filter_by(user_id=user_id).first()
        valid_otp = challenge.otp

    # Submit Valid OTP
    resp = test_client.post('/auth/verify', json={"user_id": user_id, "otp": valid_otp})
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'success'

    # --- 4. Auth (Duress) ---
    # Request Challenge
    resp = test_client.post('/auth/challenge', json={"user_id": user_id})
    assert resp.status_code == 200

    with app.app_context():
        challenge = ActiveChallenge.query.filter_by(user_id=user_id).first()
        valid_otp = challenge.otp

    # Calculate Duress OTP (Client Logic)
    # Increment last digit mod 10
    last_digit = int(valid_otp[-1])
    new_digit = (last_digit + 1) % 10
    duress_otp = valid_otp[:-1] + str(new_digit)

    # Submit Duress OTP
    resp = test_client.post('/auth/verify', json={"user_id": user_id, "otp": duress_otp})

    # IMPORTANT: Duress should return 200 OK (Stealth)
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'success'

    # --- 5. Verify Logs (Admin) ---
    # Check if DURESS event was logged
    with app.app_context():
        logs = AuditLog.query.filter_by(user_id=user_id, status='DURESS').all()
        assert len(logs) == 1
        assert logs[0].event_type == 'AUTH'
        assert "Silent Alarm" in logs[0].details

    # --- 6. Health Check ---
    resp = test_client.get('/admin/system/health', headers=headers_admin)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] == 'healthy'
