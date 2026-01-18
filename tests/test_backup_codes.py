import unittest
import json
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import app, db, User
from mfa_sdk.crypto import CryptoUtils

class TestBackupCodes(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

        self.client = app.test_client()
        with app.app_context():
            db.engine.dispose() # Force engine reload
            db.create_all()

            # Setup Tenant
            from backend.models import Tenant, ApiKey
            import hashlib

            # Should be empty now
            t = Tenant(id="default", name="Default Org")
            db.session.merge(t)

            k = ApiKey(key_hash=hashlib.sha256("admin-key".encode()).hexdigest(), tenant_id="default")
            db.session.add(k)
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()

    def test_backup_codes_lifecycle(self):
        # 1. Register User
        print("\n--- Testing Registration & Backup Code Generation ---")

        # Generate dummy keys
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        resp = self.client.post('/register', json={
            "user_id": "test_user",
            "public_key_pem_hex": pub_pem.hex(),
            "push_endpoint": "http://localhost/push"
        })

        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn("backup_codes", data)
        codes = data["backup_codes"]
        self.assertEqual(len(codes), 5)
        print(f"Received {len(codes)} backup codes.")

        backup_code = codes[0]

        # 2. Verify Count via Admin
        print("--- Verifying Initial Count (Admin) ---")
        resp = self.client.get('/admin/users?key=admin-key')
        self.assertEqual(resp.status_code, 200)
        users = resp.get_json()
        target_user = next(u for u in users if u['user_id'] == 'test_user')
        self.assertEqual(target_user['backup_codes_count'], 5)

        # 3. Authenticate with Backup Code
        print(f"--- Authenticating with Code: {backup_code} ---")
        resp = self.client.post('/auth/verify', json={
            "user_id": "test_user",
            "otp": backup_code
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['status'], 'success')

        # 4. Verify Code Consumption (Reuse)
        print("--- Verifying Code Reuse Prevention ---")
        resp = self.client.post('/auth/verify', json={
            "user_id": "test_user",
            "otp": backup_code
        })
        # Should fail
        self.assertNotEqual(resp.status_code, 200)

        # 5. Verify Count Decrement
        print("--- Verifying Decremented Count (Admin) ---")
        resp = self.client.get('/admin/users?key=admin-key')
        target_user = next(u for u in resp.get_json() if u['user_id'] == 'test_user')
        self.assertEqual(target_user['backup_codes_count'], 4)

        print("Test Complete: Backup Codes Lifecycle Verified.")

if __name__ == '__main__':
    unittest.main()
