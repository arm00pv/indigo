import pytest
from backend.app import app, db
from backend.models import Tenant, ApiKey
import hashlib
import json
import base64

class TestProvisioning:
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with app.test_client() as client:
            with app.app_context():
                db.engine.dispose()
                db.create_all()
                # Setup
                db.session.add(Tenant(id="default", name="Default"))
                h = hashlib.sha256("admin-key".encode()).hexdigest()
                db.session.add(ApiKey(key_hash=h, tenant_id="default"))
                db.session.commit()
            yield client
            with app.app_context():
                db.session.remove()
                db.drop_all()
                db.engine.dispose()

    def test_qr_generation(self, client):
        resp = client.post('/admin/provision/qrcode',
            json={"user_id": "qr_test"},
            headers={'X-Admin-Key': 'admin-key'}
        )
        assert resp.status_code == 200
        data = resp.json
        assert "qr_image" in data
        assert data["qr_image"].startswith("data:image/png;base64,")

        # Verify payload
        payload = json.loads(data["payload"])
        assert payload["user_id"] == "qr_test"
        assert payload["tenant_id"] == "default"
