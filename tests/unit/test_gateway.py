"""API-Gateway: проверка пароля, JWT и отклонение запросов на входе."""
import base64
import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from conftest import TEST_ENV, load_service, pbkdf2

gw = load_service("gateway")


@pytest.fixture
def client(audit_calls, monkeypatch):
    calls, fake = audit_calls
    monkeypatch.setattr(gw, "audit_event", fake)
    return TestClient(gw.app), calls


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def test_correct_password_is_accepted():
    assert gw.check_password("Alice-2026", pbkdf2("Alice-2026"))


def test_wrong_password_is_rejected():
    assert not gw.check_password("alice2026", pbkdf2("Alice-2026"))


def test_issued_token_is_valid():
    claims = gw.verify_jwt(gw.issue_jwt("alice", "user"))
    assert claims["sub"] == "alice" and claims["role"] == "user"


def test_token_with_alg_none_is_rejected():
    token = b64({"alg": "none"}) + "." + b64({"sub": "alice", "role": "user", "exp": 9999999999}) + "."
    assert gw.verify_jwt(token) is None


def test_token_signed_with_other_key_is_rejected():
    token = jwt.encode({"sub": "alice", "role": "user", "exp": int(time.time()) + 60},
                       "guessed-secret-0123456789abcdef0123456789", algorithm="HS256")
    assert gw.verify_jwt(token) is None


def test_token_without_role_is_rejected():
    token = jwt.encode({"sub": "alice", "exp": int(time.time()) + 60},
                       TEST_ENV["JWT_SECRET"], algorithm="HS256")
    assert gw.verify_jwt(token) is None


def test_expired_token_is_rejected():
    token = jwt.encode({"sub": "alice", "role": "user", "exp": int(time.time()) - 10},
                       TEST_ENV["JWT_SECRET"], algorithm="HS256")
    assert gw.verify_jwt(token) is None


def test_request_without_token_returns_401(client):
    c, calls = client
    r = c.get("/records")
    assert r.status_code == 401 and r.json()["detail"] == "missing_jwt"
    assert calls[-1]["type"] == "missing_jwt"


def test_request_with_forged_token_returns_403(client):
    c, calls = client
    r = c.get("/records", headers={"Authorization": "Bearer abc.def.ghi"})
    assert r.status_code == 403 and r.json()["detail"] == "invalid_jwt"


def test_login_with_wrong_password_returns_401(client):
    c, calls = client
    r = c.post("/login", json={"username": "alice", "password": "qwerty"})
    assert r.status_code == 401 and calls[-1]["type"] == "bad_credentials"


def test_login_returns_token_with_role_from_server(client):
    c, _ = client
    r = c.post("/login", json={"username": "operator", "password": "Operator-2026"})
    assert gw.verify_jwt(r.json()["access_token"])["role"] == "support"


def test_latency_metric_is_exported(client):
    c, _ = client
    c.get("/records")
    text = c.get("/metrics/").text
    assert 'gateway_request_duration_seconds_count{route="list"}' in text
