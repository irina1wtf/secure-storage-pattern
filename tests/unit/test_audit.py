"""Audit-Service: журнал с цепочкой хешей и сверка конфигурации с эталоном."""
import asyncio
import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import load_service
from common.security import canonical

audit = load_service("audit")
CONFIG = {"POLICY_JSON": '{"user": ["write", "read", "list"], "support": []}',
          "VALIDATION_ENABLED": "true", "MAX_RECORD_BYTES": "4096", "TOKEN_TTL": "900"}


@pytest.fixture
def journal(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.log")
    monkeypatch.setattr(audit, "last_hash", audit.GENESIS)
    for i in range(5):
        asyncio.run(audit.write_event({"type": f"event_{i}", "severity": "WARNING",
                                       "service": "test", "request_id": None, "subject": None,
                                       "operation": None, "reason": ""}))
    return tmp_path / "audit.log"


def test_intact_journal_passes_check(journal):
    assert audit.verify_log() == {"status": "ok", "entries": 5}


def test_modified_line_is_detected(journal):
    lines = journal.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2]); entry["reason"] = "исправлено задним числом"
    lines[2] = json.dumps(entry, ensure_ascii=False)
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert audit.verify_log() == {"status": "broken", "line": 3}


def test_deleted_line_is_detected(journal):
    lines = journal.read_text(encoding="utf-8").splitlines()
    del lines[2]
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert audit.verify_log() == {"status": "broken", "line": 3}


@pytest.fixture
def config(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "app"; cfg_dir.mkdir()
    for k, v in CONFIG.items():
        (cfg_dir / k).write_text(v, encoding="utf-8")
    key = Ed25519PrivateKey.generate()
    pub = tmp_path / "public.pem"
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    body = {"version": 1, "config_sha256": hashlib.sha256(canonical(CONFIG)).hexdigest(),
            "signed_at": "2026-11-08T12:00:00+00:00"}
    etalon = tmp_path / "etalon.json"
    etalon.write_text(json.dumps({**body, "signature": base64.b64encode(key.sign(canonical(body))).decode()}))
    monkeypatch.setattr(audit, "CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(audit, "ETALON_FILE", etalon)
    monkeypatch.setattr(audit, "PUBKEY_FILE", pub)
    return cfg_dir, etalon


def test_config_matching_etalon_is_ok(config):
    assert audit.check_config()[0] == "ok"


def test_changed_config_is_violation(config):
    cfg_dir, _ = config
    (cfg_dir / "VALIDATION_ENABLED").write_text("false", encoding="utf-8")
    assert audit.check_config()[0] == "violation"


def test_etalon_with_replaced_hash_is_invalid(config):
    cfg_dir, etalon = config
    (cfg_dir / "VALIDATION_ENABLED").write_text("false", encoding="utf-8")
    e = json.loads(etalon.read_text())
    e["config_sha256"] = audit.config_digest()        # нарушитель «узаконивает» изменение
    etalon.write_text(json.dumps(e))
    assert audit.check_config()[0] == "etalon_invalid"
