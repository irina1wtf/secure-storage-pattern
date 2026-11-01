"""Общие функции безопасности паттерна: подпись контекста запроса
и отправка событий в сервис аудита."""
import hashlib
import hmac
import json
import logging
import os
import time

import httpx

AUDIT_URL = os.getenv("AUDIT_URL", "http://audit-service:8000")
SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown")
CONTEXT_TTL = int(os.getenv("CONTEXT_TTL", "30"))  # срок жизни контекста, сек

log = logging.getLogger(SERVICE_NAME)


def canonical(obj) -> bytes:
    """Каноническое представление JSON: одинаковые данные дают одинаковые байты."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode()


def sign_context(ctx: dict, caller: str, key: bytes) -> dict:
    """Ставит отметку источника вызова, время и HMAC-подпись контекста."""
    body = {k: v for k, v in ctx.items() if k != "sig"}
    body["caller"] = caller
    body["ts"] = int(time.time())
    body["sig"] = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    return body


def verify_context(ctx: dict, key: bytes, expected_caller: str):
    """Проверяет источник вызова, подпись и срок жизни контекста.
    Возвращает None, если всё в порядке, иначе причину отказа."""
    if not isinstance(ctx, dict):
        return "missing_context"
    if ctx.get("caller") != expected_caller:
        return "invalid_caller"
    body = {k: v for k, v in ctx.items() if k != "sig"}
    expected_sig = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, str(ctx.get("sig", ""))):
        return "forged_context"
    if abs(time.time() - int(ctx.get("ts", 0))) > CONTEXT_TTL:
        return "expired_context"
    return None


async def audit_event(event_type: str, severity: str = "WARNING",
                      ctx: dict | None = None, reason: str = "") -> None:
    """Отправляет событие безопасности в Audit-Service.
    Недоступность аудита не должна ронять сервис, поэтому ошибка только логируется."""
    ctx = ctx or {}
    event = {
        "type": event_type,
        "severity": severity,
        "service": SERVICE_NAME,
        "request_id": ctx.get("request_id"),
        "subject": ctx.get("subject"),
        "operation": ctx.get("operation"),
        "reason": reason,
    }
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            await client.post(f"{AUDIT_URL}/event", json=event)
    except httpx.HTTPError as exc:
        log.error("audit unavailable: %s | %s", exc, event)
