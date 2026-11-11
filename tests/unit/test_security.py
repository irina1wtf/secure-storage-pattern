"""Общий модуль безопасности: подпись и проверка контекста запроса."""
import asyncio
import time

from conftest import TEST_ENV  # noqa: F401  (окружение задаётся при импорте conftest)
from common.security import audit_event, canonical, sign_context, verify_context

KEY, OTHER = b"gateway-key", b"other-key"
CTX = {"request_id": "r1", "subject": "alice", "role": "user", "operation": "read"}


def test_signed_context_is_accepted():
    assert verify_context(sign_context(CTX, "gateway", KEY), KEY, "gateway") is None


def test_wrong_caller_is_rejected():
    assert verify_context(sign_context(CTX, "business", KEY), KEY, "gateway") == "invalid_caller"


def test_caller_field_without_signature_is_rejected():
    forged = {**CTX, "caller": "gateway", "ts": int(time.time()), "sig": "fake"}
    assert verify_context(forged, KEY, "gateway") == "forged_context"


def test_modified_subject_breaks_signature():
    ctx = sign_context(CTX, "gateway", KEY)
    ctx["subject"] = "bob"
    assert verify_context(ctx, KEY, "gateway") == "forged_context"


def test_context_signed_with_other_key_is_rejected():
    assert verify_context(sign_context(CTX, "gateway", OTHER), KEY, "gateway") == "forged_context"


def test_expired_context_is_rejected(monkeypatch):
    ctx = sign_context(CTX, "gateway", KEY)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 60)   # TTL контекста 30 с
    assert verify_context(ctx, KEY, "gateway") == "expired_context"


def test_missing_context_is_rejected():
    assert verify_context(None, KEY, "gateway") == "missing_context"


def test_canonical_form_does_not_depend_on_key_order():
    assert canonical({"a": 1, "b": 2}) == canonical({"b": 2, "a": 1})


def test_audit_unavailable_does_not_break_service():
    # Audit-Service недоступен: функция не должна выбрасывать исключение
    asyncio.run(audit_event("test_event", "WARNING", CTX, "unit test"))
