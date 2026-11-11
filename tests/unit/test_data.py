"""Data-Service: шифрование AES-256-GCM, проверка цепочки, изоляция владельцев."""
import base64

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from conftest import TEST_ENV, load_service
from common.security import sign_context

data = load_service("data")
BIZ_KEY = TEST_ENV["CTX_BUSINESS_KEY"].encode()
RECORD = {"title": "Договор №17", "content": "Сумма 120 000 руб."}


class FakePool:
    def __init__(self, blob): self.blob = blob
    async def fetchval(self, query, record_id, owner): return self.blob.get((record_id, owner))
    async def execute(self, *a): return None


def ctx(subject="alice", resource="records/r1"):
    return sign_context({"request_id": "r1", "subject": subject, "operation": "read",
                         "resource": resource}, "business", BIZ_KEY)


@pytest.fixture
def client(audit_calls, monkeypatch):
    calls, fake = audit_calls
    monkeypatch.setattr(data, "audit_event", fake)
    return TestClient(data.app), calls


def test_encrypt_decrypt_roundtrip():
    assert data.decrypt(data.encrypt(RECORD, "alice", "r1"), "alice", "r1") == RECORD


def test_ciphertext_does_not_contain_plaintext():
    raw = base64.b64decode(data.encrypt(RECORD, "alice", "r1"))
    assert "Договор".encode() not in raw


def test_same_record_gives_different_ciphertexts():
    assert data.encrypt(RECORD, "alice", "r1") != data.encrypt(RECORD, "alice", "r1")


def test_modified_ciphertext_is_detected():
    blob = data.encrypt(RECORD, "alice", "r1")
    tampered = ("AAAA" if not blob.startswith("AAAA") else "BBBB") + blob[4:]
    with pytest.raises(InvalidTag):
        data.decrypt(tampered, "alice", "r1")


def test_ciphertext_moved_to_other_owner_is_detected():
    with pytest.raises(InvalidTag):
        data.decrypt(data.encrypt(RECORD, "alice", "r1"), "bob", "r1")


def test_request_not_from_business_is_rejected(client):
    c, calls = client
    forged = {"request_id": "x", "subject": "alice", "operation": "read", "resource": "records/r1",
              "caller": "business", "ts": 0, "sig": "fake"}
    r = c.post("/fetch", json={"ctx": forged})
    assert r.status_code == 403 and r.json()["detail"] == "integrity_violation"
    assert calls[-1] == {"type": "integrity_violation", "severity": "CRITICAL", "reason": "forged_context"}


def test_tampered_record_returns_409(client, monkeypatch):
    c, calls = client
    blob = data.encrypt(RECORD, "alice", "r1")
    monkeypatch.setattr(data, "pool", FakePool({("r1", "alice"): "AAAA" + blob[4:]
                                                if not blob.startswith("AAAA") else "BBBB" + blob[4:]}))
    r = c.post("/fetch", json={"ctx": ctx()})
    assert r.status_code == 409 and calls[-1]["type"] == "data_tamper_detected"


def test_foreign_record_looks_like_missing(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(data, "pool", FakePool({("r1", "alice"): data.encrypt(RECORD, "alice", "r1")}))
    r = c.post("/fetch", json={"ctx": ctx(subject="bob")})
    assert r.status_code == 404


def test_own_record_is_decrypted(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(data, "pool", FakePool({("r1", "alice"): data.encrypt(RECORD, "alice", "r1")}))
    r = c.post("/fetch", json={"ctx": ctx()})
    assert r.status_code == 200 and r.json()["title"] == RECORD["title"]
