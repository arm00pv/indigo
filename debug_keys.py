from backend.app import app, db, ApiKey
import hashlib

with app.app_context():
    print(f"Keys in DB: {[k.key_hash for k in ApiKey.query.all()]}")
    # Check new-admin-key
    h = hashlib.sha256("new-admin-key".encode()).hexdigest()
    print(f"Expected: {h}")
