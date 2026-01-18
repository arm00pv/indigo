import pytest
from backend.app import app, db
from backend.models import Tenant, ApiKey
import hashlib
import json
from unittest.mock import patch

class TestNotifications:
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
                db.session.add(ApiKey(key_hash=h, tenant_id="default"))
                db.session.commit()
            yield client
            with app.app_context():
                db.session.remove()
                db.drop_all()
                db.engine.dispose()

    @patch('backend.app.requests.post')
    def test_webhook_dispatch(self, mock_post, client):
        # Create Channel
        resp = client.post('/admin/notifications',
            json={
                "type": "WEBHOOK",
                "config": {"url": "http://duress.site"},
                "events": ["DURESS"]
            },
            headers={'X-Admin-Key': 'admin-key'}
        )
        assert resp.status_code == 201

        # Trigger Event manually via log_and_record logic
        with app.app_context():
            from flask import g
            g.tenant_id = "default"
            from backend.app import log_and_record
            # This should trigger dispatch_alerts
            log_and_record("AUTH", "u1", "DURESS", "Testing")

        # Verify
        mock_post.assert_called()
        args, kwargs = mock_post.call_args
        assert args[0] == "http://duress.site"
        assert "DURESS" in kwargs['json']['text']
