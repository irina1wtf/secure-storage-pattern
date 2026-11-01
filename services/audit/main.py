"""Audit-Service — централизованный аудит и модуль контроля целостности конфигураций."""
import asyncio
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import FastAPI
from prometheus_client import Counter, Gauge, make_asgi_app
from pydantic import BaseModel

from common.security import canonical

LOG_PATH = Path(os.getenv("AUDIT_LOG", "/var/log/audit/audit.log"))
CONFIG_DIR = Path(os.getenv("CONFIG_DIR", "/config/app"))           # ConfigMap app-config
ETALON_FILE = Path(os.getenv("ETALON_FILE", "/config/etalon/etalon.json"))
PUBKEY_FILE = Path(os.getenv("PUBKEY_FILE", "/config/pubkey/public.pem"))
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "20"))
CHECK_ENABLED = os.getenv("CONFIG_CHECK_ENABLED", "true") == "true"

app = FastAPI(title="Audit-Service")
app.mount("/metrics", make_asgi_app())

events_total = Counter("security_events_total", "События безопасности", ["type", "severity"])
denies_total = Counter("security_denies_total", "Критичные и предупреждающие события")
config_ok = Gauge("config_integrity_ok", "1 - конфигурация совпадает с эталоном, 0 - нет")
config_checks = Counter("config_checks_total", "Выполненные сверки с эталоном")

GENESIS = "0" * 64
last_hash = GENESIS
lock = asyncio.Lock()
config_state = "unknown"


class Event(BaseModel):
    type: str
    severity: str = "WARNING"
    service: str = "unknown"
    request_id: str | None = None
    subject: str | None = None
    operation: str | None = None
    reason: str = ""


def chain_hash(prev: str, entry: dict) -> str:
    return hashlib.sha256(prev.encode() + canonical(entry)).hexdigest()


async def write_event(event: dict) -> dict:
    """Запись в журнал с цепочкой хешей: каждая строка содержит хеш предыдущей,
    поэтому удаление или правка строки задним числом обнаруживается."""
    global last_hash
    async with lock:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), **event, "prev": last_hash}
        entry["hash"] = chain_hash(last_hash, entry)
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        last_hash = entry["hash"]
    print(f"[AUDIT] {entry['severity']:<8} {entry['type']:<28} service={entry['service']} "
          f"subject={entry['subject']} reason={entry['reason']}", flush=True)
    events_total.labels(type=event["type"], severity=event["severity"]).inc()
    if event["severity"] in ("WARNING", "CRITICAL"):
        denies_total.inc()
    return entry


def verify_log() -> dict:
    prev = GENESIS
    if not LOG_PATH.exists():
        return {"status": "ok", "entries": 0}
    lines = LOG_PATH.read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, start=1):
        entry = json.loads(line)
        stored = entry.pop("hash")
        if entry.get("prev") != prev or chain_hash(prev, entry) != stored:
            return {"status": "broken", "line": number}
        prev = stored
    return {"status": "ok", "entries": len(lines)}


def config_digest() -> str:
    """SHA-256 текущей конфигурации: каждый ключ ConfigMap — отдельный файл."""
    data = {p.name: p.read_text(encoding="utf-8")
            for p in CONFIG_DIR.iterdir() if not p.name.startswith("..") and p.is_file()}
    return hashlib.sha256(canonical(data)).hexdigest()


def check_config() -> tuple[str, str]:
    """Сверка с эталоном. Сначала проверяется подпись администратора безопасности,
    затем совпадение хеша."""
    etalon = json.loads(ETALON_FILE.read_text(encoding="utf-8"))
    signed = {k: etalon[k] for k in ("version", "config_sha256", "signed_at")}
    public_key = load_pem_public_key(PUBKEY_FILE.read_bytes())
    try:
        public_key.verify(base64.b64decode(etalon["signature"]), canonical(signed))
    except (InvalidSignature, ValueError):
        return "etalon_invalid", "подпись эталона не прошла проверку"
    current = config_digest()
    if current != etalon["config_sha256"]:
        return "violation", f"current={current[:16]} etalon={etalon['config_sha256'][:16]}"
    return "ok", f"version={etalon['version']}"


async def config_watcher():
    """Периодическая проверка. В журнал пишется только смена состояния,
    чтобы одно нарушение не порождало сотни одинаковых записей."""
    global config_state
    events = {"violation": ("config_integrity_violation", "CRITICAL"),
              "etalon_invalid": ("etalon_signature_invalid", "CRITICAL"),
              "ok": ("config_integrity_ok", "INFO"),
              "error": ("config_check_error", "WARNING")}
    while True:
        try:
            state, details = check_config()
        except Exception as exc:  # нет файла эталона, битый JSON и т.п.
            state, details = "error", str(exc)[:200]
        config_checks.inc()
        config_ok.set(1 if state == "ok" else 0)
        if state != config_state:
            event_type, severity = events[state]
            await write_event({"type": event_type, "severity": severity,
                               "service": "audit/config-checker", "request_id": None,
                               "subject": None, "operation": "config_check",
                               "reason": details})
            config_state = state
        await asyncio.sleep(CHECK_INTERVAL)


@app.on_event("startup")
async def startup():
    global last_hash
    if LOG_PATH.exists():
        lines = LOG_PATH.read_text(encoding="utf-8").splitlines()
        if lines:
            last_hash = json.loads(lines[-1])["hash"]
    if CHECK_ENABLED:
        asyncio.create_task(config_watcher())


@app.post("/event")
async def receive(event: Event):
    entry = await write_event(event.model_dump())
    return {"stored": entry["hash"][:16]}


@app.get("/events")
async def last_events(limit: int = 20):
    if not LOG_PATH.exists():
        return []
    lines = LOG_PATH.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(line) for line in lines]


@app.get("/verify-log")
async def verify():
    return verify_log()


@app.get("/config-status")
async def config_status():
    return {"state": config_state}


@app.get("/health")
async def health():
    return {"status": "ok"}
