"""Загрузка микросервисов для модульных тестов. Каждый сервис читает ключи
из переменных окружения при импорте, поэтому окружение задаётся заранее
тестовыми значениями (настоящие секреты стенда в тестах не используются)."""
import base64
import importlib.util
import json
import os
import sys
from pathlib import Path

import hashlib

import pytest

SERVICES = Path(__file__).resolve().parents[2] / "services"
sys.path.insert(0, str(SERVICES))           # для импорта common.security

TEST_ENV = {
    "JWT_SECRET": "test-jwt-secret-0123456789abcdef0123456789",
    "CTX_GATEWAY_KEY": "test-gateway-key",
    "CTX_BUSINESS_KEY": "test-business-key",
    "DATA_KEY": base64.b64encode(b"k" * 32).decode(),
    "DB_USER": "test", "DB_PASSWORD": "test", "DB_NAME": "test",
    "POLICY_JSON": json.dumps({"user": ["write", "read", "list"], "support": []}),
    "VALIDATION_ENABLED": "true", "MAX_RECORD_BYTES": "4096",
    "AUDIT_URL": "http://127.0.0.1:9",      # аудит в тестах недоступен — проверяется устойчивость
}


def pbkdf2(password: str, salt: bytes = b"0123456789abcdef") -> str:
    """Хеш в формате секрета users: соль$хеш (PBKDF2-SHA256, 200 000 итераций)."""
    return salt.hex() + "$" + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


TEST_ENV["USERS_JSON"] = json.dumps({"alice": {"role": "user", "pwd": pbkdf2("Alice-2026")},
                                     "operator": {"role": "support", "pwd": pbkdf2("Operator-2026")}})


def load_service(name: str, extra_env: dict | None = None):
    os.environ.update(TEST_ENV)
    if extra_env:
        os.environ.update(extra_env)
    spec = importlib.util.spec_from_file_location(f"svc_{name}", SERVICES / name / "main.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def audit_calls(monkeypatch):
    """Перехват событий аудита: тесты проверяют, что отказ зарегистрирован."""
    calls = []

    async def fake_audit(event_type, severity="WARNING", ctx=None, reason=""):
        calls.append({"type": event_type, "severity": severity, "reason": reason})
    return calls, fake_audit
