import pytest
import time
import datetime
import os
from flask import json
from backend.app import app, db
from backend.models import ActiveChallenge

class TestSecurityFeatures:

    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with app.test_client() as client:
            with app.app_context():
                db.engine.dispose()
                db.create_all()
            yield client
            with app.app_context():
                db.session.remove()
                db.drop_all()
                db.engine.dispose()

    def register_user(self, client, user_id):
        # Generate dummy key
        from mfa_sdk.crypto import CryptoUtils
        priv = CryptoUtils.generate_key_pair()
        pub = CryptoUtils.get_public_key(priv)
        pub_hex = CryptoUtils.serialize_public_key(pub).hex()

        client.post('/register', json={
            "user_id": user_id,
            "public_key_pem_hex": pub_hex
        })
        return priv

    def test_otp_expiry(self, client):
        user_id = "expiry_test"
        self.register_user(client, user_id)

        # Get Challenge
        resp = client.post('/auth/challenge', json={"user_id": user_id})
        assert resp.status_code == 200

        # Manually backdate the challenge in DB to 6 minutes ago
        with app.app_context():
            # Composite key: (user_id, tenant_id)
            challenge = db.session.get(ActiveChallenge, (user_id, "default"))
            challenge.created_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(minutes=6)
            db.session.commit()
            otp = challenge.otp

        # Verify
        verify_resp = client.post('/auth/verify', json={"user_id": user_id, "otp": otp})
        assert verify_resp.status_code == 400
        assert "OTP Expired" in verify_resp.json['error']

    def test_rate_limiting_lockout(self, client):
        user_id = "bruteforce_test"
        self.register_user(client, user_id)

        # Get Challenge
        client.post('/auth/challenge', json={"user_id": user_id})

        # Fail 5 times
        for i in range(5):
            resp = client.post('/auth/verify', json={"user_id": user_id, "otp": "000000"})
            if i < 4:
                assert resp.status_code == 401
            else:
                # 5th attempt triggers lock
                assert resp.status_code == 403
                # The logic in app.py says "Too many failures. Locked for 15 mins."
                assert "Locked" in resp.json['message']

        # 6th attempt should be blocked immediately
        resp = client.post('/auth/verify', json={"user_id": user_id, "otp": "000000"})
        assert resp.status_code == 403

        # Challenge request should also be blocked
        resp = client.post('/auth/challenge', json={"user_id": user_id})
        assert resp.status_code == 403
