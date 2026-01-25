import pytest
import os
import json
from backend.app import app, db, init_db_data, hash_key
from backend.models import ApiKey

@pytest.fixture
def client():
    app.config['TESTING'] = True
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            init_db_data()

            # Reset keys first (init_db_data might add one if env var is set, though we cleared it?)
            # Wait, os.environ changes in fixture might leak or not apply if init_db_data reads from os directly
            # and it was imported before.
            # Safe bet: Clear keys.
            ApiKey.query.delete()

            # Create Master Admin
            h = hash_key('master-key')
            db.session.add(ApiKey(key_hash=h, tenant_id='default', username='MasterAdmin'))
            db.session.commit()

            yield client
        db.drop_all()

def test_admin_management(client):
    headers = {'X-Admin-Key': 'master-key', 'Content-Type': 'application/json'}

    # 1. List Admins
    res = client.get('/admin/system/admins', headers=headers)
    assert res.status_code == 200
    data = res.json
    assert len(data) == 1
    assert data[0]['username'] == 'MasterAdmin'

    # 2. Create Admin
    res = client.post('/admin/system/admins', headers=headers, json={"username": "Alice"})
    assert res.status_code == 200
    new_key = res.json['key']
    assert len(new_key) > 10

    # 3. Verify List
    res = client.get('/admin/system/admins', headers=headers)
    assert len(res.json) == 2

    # 4. Revoke Admin
    # Get hash from list
    alice = next(a for a in res.json if a['username'] == 'Alice')
    alice_hash = alice['key_hash']

    res = client.delete(f'/admin/system/admins?hash={alice_hash}', headers=headers)
    assert res.status_code == 200

    # 5. Verify Revocation
    res = client.get('/admin/system/admins', headers=headers)
    assert len(res.json) == 1

    # 6. Self Revoke Check (Should Fail)
    master = next(a for a in res.json if a['username'] == 'MasterAdmin')
    res = client.delete(f'/admin/system/admins?hash={master["key_hash"]}', headers=headers)
    assert res.status_code == 400
    assert "Cannot revoke your own key" in res.json['error']
