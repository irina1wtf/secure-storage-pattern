"""Authz-Service: ролевая политика с запретом по умолчанию."""
import pytest
from fastapi.testclient import TestClient

from conftest import TEST_ENV, load_service
from common.security import sign_context

authz = load_service("authz")
KEY = TEST_ENV["CTX_GATEWAY_KEY"].encode()


@pytest.fixture
def client(audit_calls, monkeypatch):
    calls, fake = audit_calls
    monkeypatch.setattr(authz, "audit_event", fake)
    return TestClient(authz.app), calls


@pytest.mark.parametrize("role,operation,allowed", [
    ("user", "write", True), ("user", "read", True), ("user", "list", True),
    ("user", "delete", False), ("support", "read", False), ("support", "list", False),
    ("admin", "read", False), (None, "read", False),
])
def test_policy_matrix(role, operation, allowed):
    assert authz.is_allowed(role, operation) is allowed


def ctx(role):
    return {"request_id": "r1", "subject": "alice", "role": role, "operation": "read",
            "resource": "records/1"}


def test_user_role_is_allowed(client):
    c, _ = client
    r = c.post("/authorize", json={"ctx": sign_context(ctx("user"), "gateway", KEY)})
    assert r.status_code == 200 and r.json() == {"decision": "ALLOW"}


def test_support_role_gets_policy_violation(client):
    c, calls = client
    r = c.post("/authorize", json={"ctx": sign_context(ctx("support"), "gateway", KEY)})
    assert r.status_code == 403 and r.json()["detail"] == "policy_violation"
    assert calls[-1]["type"] == "policy_violation"


def test_forged_context_is_checked_before_policy(client):
    c, calls = client
    forged = {**ctx("user"), "caller": "gateway", "ts": 0, "sig": "fake"}
    r = c.post("/authorize", json={"ctx": forged})
    assert r.status_code == 403 and r.json()["detail"] == "forged_context"


def test_call_not_from_gateway_is_rejected(client):
    c, _ = client
    r = c.post("/authorize", json={"ctx": sign_context(ctx("user"), "business", KEY)})
    assert r.json()["detail"] == "invalid_caller"
