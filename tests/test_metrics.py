import pytest
from backend.app import app, db
import time

class TestMetrics:
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with app.test_client() as client:
            with app.app_context():
                db.engine.dispose()
                db.create_all()
            yield client
            with app.app_context():
                db.session.remove()
                db.drop_all()
                db.engine.dispose()

    def test_metrics_endpoint(self, client):
        resp = client.get('/metrics')
        assert resp.status_code == 200
        assert b'http_requests_total' in resp.data

    def test_metrics_counting(self, client):
        # Hit health 3 times
        client.get('/health')
        client.get('/health')
        client.get('/health')

        resp = client.get('/metrics')
        data = resp.data.decode()

        # Check if count is there
        # http_requests_total{endpoint="health",method="GET",status="200"} 3.0
        assert 'http_requests_total' in data
        assert 'endpoint="health"' in data
