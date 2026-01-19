import pytest
import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
from backend.app import app, db
from backend.models import Tenant, ApiKey, SystemSetting
import hashlib

class TestCustomPolicy:
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with app.test_client() as client:
            with app.app_context():
                db.engine.dispose()
                db.create_all()
                db.session.merge(Tenant(id="default", name="Default"))
                db.session.merge(ApiKey(key_hash=hashlib.sha256("k".encode()).hexdigest(), tenant_id="default"))
                db.session.commit()
            yield client
            with app.app_context():
                db.session.remove()
                db.drop_all()
                db.engine.dispose()

    def test_strict_policy(self, client):
        # 1. Register User
        from mfa_sdk.crypto import CryptoUtils
        priv = CryptoUtils.generate_key_pair()
        pub = CryptoUtils.serialize_public_key(CryptoUtils.get_public_key(priv)).hex()
        client.post('/register', json={"user_id": "strict_user", "public_key_pem_hex": pub})

        # 2. Set Policy: Lock after 2 attempts
        client.post('/admin/settings', headers={'X-Admin-Key': 'k'}, json={
            "policy_max_failures_temp_lock": "2",
            "policy_temp_lock_duration_seconds": "10"
        })

        # 3. Get Challenge
        client.post('/auth/challenge', json={"user_id": "strict_user"})

        # 4. Fail 1 time (Allowed)
        r = client.post('/auth/verify', json={"user_id": "strict_user", "otp": "000000"})
        assert r.status_code == 401

        # 5. Fail 2nd time (Should Lock)
        r = client.post('/auth/verify', json={"user_id": "strict_user", "otp": "000000"})
        assert r.status_code == 403
        assert "Locked for 10s" in r.json['message']
        assert r.headers['Retry-After'] == '10'
