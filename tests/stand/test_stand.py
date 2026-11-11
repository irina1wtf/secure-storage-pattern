"""Автоматизированная приёмочная проверка развёрнутого стенда через API-шлюз.
Запуск на ВМ user: python3 -m pytest tests/stand -v
Нужен только pytest: запросы выполняются стандартной библиотекой urllib."""
import base64
import json
import os
import socket
import urllib.error
import urllib.request
import uuid

import pytest

GW = os.getenv("GW", "http://192.168.56.10:30080")
HOST = GW.split("//")[1].split(":")[0]


def call(method, path, body=None, token=None):
    req = urllib.request.Request(GW + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def login(user, password):
    status, body = call("POST", "/login", {"username": user, "password": password})
    assert status == 200, body
    return body["access_token"]


@pytest.fixture(scope="module")
def alice():
    return login("alice", "Alice-2026")


@pytest.fixture(scope="module")
def record(alice):
    title = f"Приёмочный тест {uuid.uuid4().hex[:6]}"
    status, body = call("POST", "/records", {"title": title, "content": "Сумма 120 000 руб."}, alice)
    assert status == 200
    return body["id"], title


def test_user_writes_and_reads_own_record(alice, record):
    rid, title = record
    status, body = call("GET", f"/records/{rid}", token=alice)
    assert status == 200 and body["title"] == title


def test_record_appears_in_users_list(alice, record):
    status, body = call("GET", "/records", token=alice)
    assert status == 200 and record[0] in [i["id"] for i in body["items"]]


def test_other_user_cannot_read_record(record):
    status, body = call("GET", f"/records/{record[0]}", token=login("bob", "Bob-2026"))
    assert status == 404 and body["detail"] == "not_found"


def test_provider_employee_has_no_access_to_data(record):
    token = login("operator", "Operator-2026")
    assert call("GET", "/records", token=token)[0] == 403
    assert call("GET", f"/records/{record[0]}", token=token)[0] == 403


def test_request_without_token_is_rejected():
    assert call("GET", "/records") == (401, {"detail": "missing_jwt"})


def test_unsigned_token_is_rejected():
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    token = b({"alg": "none"}) + "." + b({"sub": "alice", "role": "user", "exp": 9999999999}) + "."
    assert call("GET", "/records", token=token) == (403, {"detail": "invalid_jwt"})


def test_wrong_password_is_rejected():
    assert call("POST", "/login", {"username": "alice", "password": "qwerty"})[0] == 401


def test_invalid_record_is_rejected(alice):
    status, body = call("POST", "/records", {"title": " ", "content": "x"}, alice)
    assert status == 422 and body["detail"] == "validation_bad_title"


@pytest.mark.parametrize("port", [5432, 8000, 8001, 8002, 8003, 8004])
def test_internal_ports_are_closed(port):
    s = socket.socket(); s.settimeout(2)
    try:
        assert s.connect_ex((HOST, port)) != 0
    finally:
        s.close()
