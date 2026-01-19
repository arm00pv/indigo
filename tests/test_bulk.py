import pytest
import json
import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
from backend.app import app, db
from backend.models import Tenant, ApiKey
import hashlib

class TestBulk:
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with app.test_client() as client:
            with app.app_context():
                db.engine.dispose()
                db.create_all()
                db.session.merge(Tenant(id="default", name="Default"))
                h = hashlib.sha256("admin-key".encode()).hexdigest()
                db.session.merge(ApiKey(key_hash=h, tenant_id="default"))
                db.session.commit()
            yield client
            with app.app_context():
                db.session.remove()
                db.drop_all()
                db.engine.dispose()

    def test_bulk_provision(self, client):
        payload = {"user_ids": "u1\nu2, u3"}
        resp = client.post('/admin/provision/bulk', json=payload, headers={'X-Admin-Key': 'admin-key'})
        assert resp.status_code == 200
        data = resp.json
        assert len(data) == 3
        assert data[0]['user_id'] == 'u1'
        assert data[1]['user_id'] == 'u2'
        assert data[2]['user_id'] == 'u3'
        assert "smart_code" in data[0]
