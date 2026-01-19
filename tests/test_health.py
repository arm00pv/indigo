import pytest
import json
import os
import shutil
import hashlib
from backend.app import app, db, Tenant, ApiKey

# Mock environment variable for test isolation
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    # Create necessary directories for health check
    os.makedirs('logs', exist_ok=True)
    os.makedirs('backups', exist_ok=True)

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()

    # Cleanup (optional, but good practice if running locally)
    # shutil.rmtree('backups', ignore_errors=True)
    # Don't delete logs as other tests might need them or the app expects them

def test_health_check_endpoint(client):
    """Test the /admin/system/health endpoint."""

    # 1. Setup Admin Key
    tenant = Tenant(id="health_test_tenant", name="Health Test")
    db.session.add(tenant)

    raw_key = "test-health-key"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    api_key = ApiKey(key_hash=key_hash, tenant_id="health_test_tenant")
    db.session.add(api_key)
    db.session.commit()

    # 2. Call Health Endpoint
    headers = {'X-Admin-Key': raw_key}
    response = client.get('/admin/system/health', headers=headers)

    assert response.status_code == 200
    data = response.get_json()

    assert data['status'] == 'healthy'
    assert len(data['checks']) >= 3 # DB, Keys, Permissions

    # Verify specific checks
    checks_map = {c['name']: c['status'] for c in data['checks']}
    assert checks_map['Database'] == 'pass'
    assert checks_map['Admin Keys'] == 'pass'
    assert checks_map.get('Permission: logs') == 'pass'
    assert checks_map.get('Permission: backups') == 'pass'

def test_health_check_unauthorized(client):
    """Test access without admin key."""
    response = client.get('/admin/system/health')
    assert response.status_code == 401
