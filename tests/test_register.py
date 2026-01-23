import pytest
import os
import json
from backend.app import app, db, init_db_data
from backend.models import User, SystemSetting

@pytest.fixture
def client():
    app.config['TESTING'] = True
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            init_db_data()
            yield client
        db.drop_all()

def test_register_page_disabled_by_default(client):
    """Test that the page shows an error when disabled."""
    # Default setting in init_db_data is False? Actually init_db_data doesn't set it explicitly in the snippet I saw,
    # but the code says "if not setting or setting.value != 'true'".
    # Let's ensure it's not set or set to false

    res = client.get('/register-user')
    assert res.status_code == 200
    assert b"Self-registration is disabled" in res.data

def test_register_page_flow(client):
    """Enable feature and test flow."""
    # Enable
    with app.app_context():
        # Ensure default tenant exists from init_db_data
        s = SystemSetting(key='allow_self_registration', value='true', tenant_id='default')
        db.session.merge(s)
        db.session.commit()

    # GET - Form
    res = client.get('/register-user')
    assert res.status_code == 200
    assert b"Self-registration is disabled" not in res.data
    assert b"Self-Service Enrollment" in res.data

    # POST - Create
    res = client.post('/register-user', data={'email': 'newuser@example.com'})
    assert res.status_code == 200
    assert b"Registration Started" in res.data
    assert b"newuser@example.com" in res.data
    assert b"data:image/png;base64" in res.data

def test_sso_stub(client):
    res = client.get('/auth/sso/login')
    assert res.status_code == 501
    assert b"SSO Login Flow Placeholder" in res.data
