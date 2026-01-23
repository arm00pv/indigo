import pytest
import os
import hashlib
from backend.app import app, db, ApiKey

# Mock DB
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    # Force empty env
    if "ADMIN_API_KEY" in os.environ:
        del os.environ["ADMIN_API_KEY"]

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()

def test_setup_flow(client):
    """Test the First Run Setup Wizard logic."""

    # 1. Check Status (Should be False initially)
    # Note: init-db runs in app context usually, here we simulate a fresh start
    # By default, init_db_data is called in main block, or CLI.
    # Here, we rely on db.create_all() but init_db_data logic (which creates default key IF env var set)
    # We cleared Env var, so no key should exist.

    # We need to manually run the logic of init_db_data (minus the default key part)
    # to ensure Tenant exists. Or rely on Setup to create Tenant.
    # The setup_admin endpoint handles Tenant creation if missing.

    resp = client.get('/api/system/status')
    assert resp.status_code == 200
    assert resp.get_json()['initialized'] == False

    # 2. Setup Admin (Success)
    new_key = "secure-setup-key-123"
    username = "SysMaster"
    resp = client.post('/api/setup', json={"key": new_key, "role": "enterprise", "username": username})
    assert resp.status_code == 201
    assert "Setup Complete" in resp.get_json()['message']

    # Check Role Storage & Username
    from backend.models import SystemSetting
    with app.app_context():
        # Check Username
        h = hashlib.sha256(new_key.encode()).hexdigest()
        key_obj = db.session.get(ApiKey, h)
        assert key_obj.username == username

        role = db.session.get(SystemSetting, ('system_installation_role', 'default'))
        assert role.value == 'enterprise'

        # Check Policy Adjustment
        pol = db.session.get(SystemSetting, ('policy_max_failures_soft_lock', 'default'))
        assert pol.value == '5'

    # 3. Check Status (Should be True)
    resp = client.get('/api/system/status')
    assert resp.get_json()['initialized'] == True

    # 4. Try Setup Again (Fail - Idempotency/Security)
    resp = client.post('/api/setup', json={"key": "hacker-key"})
    assert resp.status_code == 403
    assert "already initialized" in resp.get_json()['error']

    # 5. Verify Key Works
    headers = {'X-Admin-Key': new_key}
    resp = client.get('/admin/system/health', headers=headers)
    assert resp.status_code == 200
