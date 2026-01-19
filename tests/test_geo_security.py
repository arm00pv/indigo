import pytest
import datetime
from unittest.mock import patch, MagicMock
import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
from backend.app import app, db
from backend.models import User, UserSecurity, AuditLog, Tenant, ApiKey, ActiveChallenge
from mfa_sdk.verifier import VerificationStatus
import hashlib

class TestGeoSecurity:
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

    @patch('backend.app.verifier.verify_otp')
    @patch('backend.app.get_ip_location')
    def test_impossible_travel(self, mock_geo, mock_verify, client):
        user_id = "traveler"
        with app.app_context():
            # Setup UserSecurity with "Previous Login" in NY 1 hour ago
            sec = UserSecurity(
                user_id=user_id,
                tenant_id="default",
                last_login_at=datetime.datetime.now() - datetime.timedelta(hours=1),
                last_lat=40.7128, # NY
                last_lon=-74.0060,
                last_ip="1.2.3.4"
            )
            user = User(user_id=user_id, tenant_id="default", public_key_pem=b"mock", backup_codes="[]")
            ac = ActiveChallenge(user_id=user_id, tenant_id="default", otp="123456")

            db.session.add(user)
            db.session.add(sec)
            db.session.add(ac)
            db.session.commit()

        # Login from London (Lat 51.5074, Lon -0.1278) - Distance ~5500km
        mock_geo.return_value = ("London, UK", 51.5074, -0.1278)
        mock_verify.return_value = VerificationStatus.VALID

        resp = client.post('/auth/verify', json={"user_id": user_id, "otp": "123456"})
        assert resp.status_code == 200

        # Check Logs for ABUSE event due to Impossible Travel
        with app.app_context():
            # We expect an ABUSE log AND a SUCCESS log (since we only warn currently)
            # Or wait, log_and_record logs to DB.
            # verify_otp logic:
            # if dist > 100... log ABUSE
            # then log SUCCESS (via log_and_record call inside verify_otp? No, existing verify_otp does log SUCCESS)

            abuse_log = AuditLog.query.filter_by(event_type="AUTH", status="ABUSE", user_id=user_id).first()
            assert abuse_log is not None
            assert "Impossible Travel" in abuse_log.details
            print(f"Detected: {abuse_log.details}")
