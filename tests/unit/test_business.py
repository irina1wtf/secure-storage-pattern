"""Business-Service: проверка цепочки вызовов и валидация записей."""
import pytest
from fastapi.testclient import TestClient

from conftest import TEST_ENV, load_service
from common.security import sign_context, verify_context

biz = load_service("business")
GW_KEY = TEST_ENV["CTX_GATEWAY_KEY"].encode()
BIZ_KEY = TEST_ENV["CTX_BUSINESS_KEY"].encode()
CTX = {"request_id": "r1", "subject": "alice", "role": "user", "operation": "write",
       "resource": "records", "decision": "ALLOW"}


class FakeResponse:
    status_code = 200
    headers = {"content-type": "application/json"}

    def json(self):
        return {"id": "abc"}


class FakeClient:
    """Подменяет обращение к Data-Service и запоминает, что было отправлено."""
    sent = []

    def __init__(self, *a, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

    async def post(self, url, json):
        FakeClient.sent.append((url, json))
        return FakeResponse()


@pytest.fixture
def client(audit_calls, monkeypatch):
    calls, fake = audit_calls
    monkeypatch.setattr(biz, "audit_event", fake)
    monkeypatch.setattr(biz.httpx, "AsyncClient", FakeClient)
    FakeClient.sent.clear()
    return TestClient(biz.app), calls


@pytest.mark.parametrize("payload,problem", [
    ({"title": "Договор", "content": "текст"}, None),
    ({"title": "Договор"}, "bad_fields"),
    ({"title": "Договор", "content": "x", "owner": "bob"}, "bad_fields"),
    ({"title": "   ", "content": "x"}, "bad_title"),
    ({"title": "x" * 201, "content": "x"}, "bad_title"),
    ({"title": "Большая", "content": "x" * 5000}, "too_large"),
])
def test_validate_record(payload, problem):
    assert biz.validate_record(payload) == problem


def test_direct_call_with_forged_context_is_blocked(client):
    c, calls = client
    forged = {**CTX, "caller": "gateway", "ts": 0, "sig": "fake"}
    r = c.post("/process", json={"ctx": forged})
    assert r.status_code == 403 and r.json()["detail"] == "forged_context"
    assert not FakeClient.sent                      # до Data-Service запрос не дошёл


def test_context_without_authz_decision_is_blocked(client):
    c, _ = client
    ctx = {k: v for k, v in CTX.items() if k != "decision"}
    r = c.post("/process", json={"ctx": sign_context(ctx, "gateway", GW_KEY)})
    assert r.json()["detail"] == "no_authz_decision"


def test_invalid_record_returns_422(client):
    c, calls = client
    r = c.post("/process", json={"ctx": sign_context(CTX, "gateway", GW_KEY),
                                 "payload": {"title": " ", "content": "x"}})
    assert r.status_code == 422 and r.json()["detail"] == "validation_bad_title"


def test_forwarded_context_is_signed_by_business_without_role(client):
    c, _ = client
    r = c.post("/process", json={"ctx": sign_context(CTX, "gateway", GW_KEY),
                                 "payload": {"title": "Договор", "content": "текст"}})
    assert r.status_code == 200
    url, body = FakeClient.sent[-1]
    assert url.endswith("/store")
    assert verify_context(body["ctx"], BIZ_KEY, "business") is None
    assert "role" not in body["ctx"] and "decision" not in body["ctx"]


def test_disabled_validation_lets_invalid_record_through(monkeypatch):
    monkeypatch.setattr(biz, "VALIDATION_ENABLED", False)   # сценарий № 2: изменённая конфигурация
    monkeypatch.setattr(biz.httpx, "AsyncClient", FakeClient)
    r = TestClient(biz.app).post("/process", json={"ctx": sign_context(CTX, "gateway", GW_KEY),
                                                   "payload": {"title": " ", "content": "x"}})
    assert r.status_code == 200
