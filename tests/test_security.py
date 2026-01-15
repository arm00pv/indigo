import pytest
import time
import datetime
import os
from flask import json
from backend.app import app, DB_PATH, init_db
import sqlite3

class TestSecurityFeatures:

    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            # Reset DB for tests
            if os.path.exists(DB_PATH):
                os.remove(DB_PATH)
            init_db()
            yield client

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
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        old_time = (datetime.datetime.now() - datetime.timedelta(minutes=6)).isoformat()
        c.execute("UPDATE active_challenges SET created_at=? WHERE user_id=?", (old_time, user_id))

        # Get the OTP to try
        c.execute("SELECT otp FROM active_challenges WHERE user_id=?", (user_id,))
        otp = c.fetchone()[0]
        conn.commit()
        conn.close()

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
                assert "Account locked" in resp.json['message']

        # 6th attempt should be blocked immediately
        resp = client.post('/auth/verify', json={"user_id": user_id, "otp": "000000"})
        assert resp.status_code == 403

        # Challenge request should also be blocked
        resp = client.post('/auth/challenge', json={"user_id": user_id})
        assert resp.status_code == 403
