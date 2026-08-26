import os
import tempfile

import pytest

from app import create_app
from app.monitor import check_tcp


@pytest.fixture
def client():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    app = create_app({
        "TESTING": True,
        "DB_PATH": path,
        "ADMIN_PASSWORD": "TestPassword!123",
        "SECRET_KEY": "test-secret-key",
    })
    with app.test_client() as client:
        yield client
    os.unlink(path)


def login(client):
    return client.post("/login", data={"username": "admin", "password": "TestPassword!123"})


def test_login_and_dashboard(client):
    response = login(client)
    assert response.status_code == 302
    response = client.get("/")
    assert response.status_code == 200
    assert b"NetGuardian" in response.data


def test_bad_login_is_rejected(client):
    response = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert response.status_code == 401
    assert b"Invalid username or password" in response.data


def test_target_api_requires_authentication(client):
    response = client.post("/targets", json={"name":"Example","host":"127.0.0.1","port":5000})
    assert response.status_code == 401


def test_target_can_be_created_after_login(client):
    login(client)
    response = client.post("/targets", json={"name":"Example","host":"127.0.0.1","port":5000})
    assert response.status_code == 201
    data = client.get("/api/overview")
    assert data.status_code == 200
    assert b"Example" in data.data


def test_tcp_check_rejects_invalid_port():
    status, latency, error = check_tcp("127.0.0.1", 0, timeout=0.1)
    assert status == "DOWN"
    assert latency is None
    assert error
