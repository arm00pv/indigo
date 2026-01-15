import pytest
import sqlite3
import os
from backend.app import app, DB_PATH, init_db

class TestAbuseFeatures:

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
        from mfa_sdk.crypto import CryptoUtils
        priv = CryptoUtils.generate_key_pair()
        pub = CryptoUtils.get_public_key(priv)
        pub_hex = CryptoUtils.serialize_public_key(pub).hex()

        client.post('/register', json={
            "user_id": user_id,
            "public_key_pem_hex": pub_hex
        })
        return priv

    def test_abuse_lockout(self, client):
        user_id = "abuse_test"
        self.register_user(client, user_id)

        # Get Challenge
        client.post('/auth/challenge', json={"user_id": user_id})

        # Fail 9 times (Below limit)
        for i in range(9):
            resp = client.post('/auth/verify', json={"user_id": user_id, "otp": "000000"})
            if i < 4:
                assert resp.status_code == 401 # Invalid
            else:
                assert resp.status_code == 403 # Temp Lock (5-9)

        # 10th Attempt -> Soft Lock
        resp = client.post('/auth/verify', json={"user_id": user_id, "otp": "000000"})
        assert resp.status_code == 403
        assert "Device Soft Locked" in resp.json['message']

        # 11th Attempt -> Still Soft Locked
        resp = client.post('/auth/verify', json={"user_id": user_id, "otp": "000000"})
        assert resp.status_code == 403

        # Verify via Admin Unlock
        client.post(f'/admin/user/{user_id}/unlock')

        # Retry with Valid Logic (Mocked success)
        # We need a valid OTP to test success, but we can just check if we get 401 instead of 403 (meaning lock is gone)
        client.post('/auth/challenge', json={"user_id": user_id})
        resp = client.post('/auth/verify', json={"user_id": user_id, "otp": "000000"})
        assert resp.status_code == 401 # Invalid OTP, but NOT LOCKED
