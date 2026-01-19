import unittest
import os
import glob
import json
import shutil
import hashlib
import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
from backend.app import app, db
from backend.models import Tenant, User, ApiKey

class TestBackupRestore(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

        self.runner = app.test_cli_runner()
        self.client = app.test_client()

        with app.app_context():
            db.engine.dispose()
            db.create_all()
            db.session.merge(Tenant(id="default", name="Default"))
            # public_key_pem must be bytes
            db.session.merge(User(user_id="u1", tenant_id="default", public_key_pem=b"pubkey"))
            db.session.merge(ApiKey(key_hash=hashlib.sha256("k".encode()).hexdigest(), tenant_id="default"))
            db.session.commit()

    def tearDown(self):
        if os.path.exists("backups"):
            shutil.rmtree("backups")
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_backup_cli(self):
        result = self.runner.invoke(args=["backup"])
        if result.exit_code != 0:
            print(result.output)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Backup saved to", result.output)

        files = glob.glob("backups/*.json")
        self.assertEqual(len(files), 1)

        with open(files[0]) as f:
            data = json.load(f)
            self.assertEqual(len(data['users']), 1)
            self.assertEqual(data['users'][0]['user_id'], "u1")
            # b'pubkey' -> base64 'cHVia2V5'
            self.assertEqual(data['users'][0]['public_key_pem'], "cHVia2V5")

    def test_api_backup(self):
        resp = self.client.get('/admin/maintenance/backup', headers={'X-Admin-Key': 'k'})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data['users']), 1)
        self.assertEqual(data['users'][0]['user_id'], 'u1')
