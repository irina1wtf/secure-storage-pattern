"""Data-Service — единственный компонент с доступом к данным потребителей.
Данные хранятся в PostgreSQL только в зашифрованном виде."""
import asyncio
import base64
import json
import os
import uuid
from contextlib import asynccontextmanager

import asyncpg
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException
from prometheus_client import Counter, make_asgi_app
from pydantic import BaseModel

from common.security import audit_event, verify_context

BUSINESS_KEY = os.environ["CTX_BUSINESS_KEY"].encode()
DATA_KEY = base64.b64decode(os.environ["DATA_KEY"])  # 256 бит, в VK Cloud — из KMS
DB = dict(host=os.getenv("DB_HOST", "postgres"), port=int(os.getenv("DB_PORT", "5432")),
          user=os.environ["DB_USER"], password=os.environ["DB_PASSWORD"],
          database=os.environ["DB_NAME"])

pool: asyncpg.Pool | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Подключение к PostgreSQL с повторами: база может стартовать позже сервиса."""
    global pool
    for attempt in range(30):
        try:
            pool = await asyncpg.create_pool(**DB, min_size=1, max_size=5)
            break
        except (OSError, asyncpg.PostgresError):
            await asyncio.sleep(2)
    else:
        raise RuntimeError("PostgreSQL недоступен")
    await pool.execute("CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, "
                       "owner TEXT NOT NULL, blob TEXT NOT NULL, "
                       "created TIMESTAMPTZ NOT NULL DEFAULT now())")
    yield
    await pool.close()


app = FastAPI(title="Data-Service", lifespan=lifespan)
app.mount("/metrics", make_asgi_app())

ops_total = Counter("data_operations_total", "Операции с данными", ["operation"])
integrity_failures = Counter("data_integrity_failures_total", "Нарушения цепочки вызовов")
tamper_total = Counter("data_tamper_detected_total", "Обнаруженные подмены записей")


class DataRequest(BaseModel):
    ctx: dict
    payload: dict | None = None


def encrypt(record: dict, owner: str, record_id: str) -> str:
    """AES-256-GCM. Владелец и id записи входят в AAD, поэтому
    перенос шифртекста в чужую запись тоже обнаруживается."""
    nonce = os.urandom(12)
    aad = f"{owner}:{record_id}".encode()
    ct = AESGCM(DATA_KEY).encrypt(nonce, json.dumps(record).encode(), aad)
    return base64.b64encode(nonce + ct).decode()


def decrypt(blob: str, owner: str, record_id: str) -> dict:
    raw = base64.b64decode(blob)
    aad = f"{owner}:{record_id}".encode()
    return json.loads(AESGCM(DATA_KEY).decrypt(raw[:12], raw[12:], aad))


async def check_chain(ctx: dict):
    """Принимаются только подписанные запросы от Business-Service."""
    reason = verify_context(ctx, BUSINESS_KEY, expected_caller="business")
    if reason:
        integrity_failures.inc()
        await audit_event("integrity_violation", "CRITICAL", ctx, reason)
        raise HTTPException(403, "integrity_violation")


@app.post("/store")
async def store(req: DataRequest):
    await check_chain(req.ctx)
    owner, record_id = req.ctx["subject"], uuid.uuid4().hex[:12]
    await pool.execute("INSERT INTO records (id, owner, blob) VALUES ($1, $2, $3)",
                       record_id, owner, encrypt(req.payload, owner, record_id))
    ops_total.labels(operation="write").inc()
    await audit_event("data_write", "INFO", req.ctx, record_id)
    return {"id": record_id}


@app.post("/fetch")
async def fetch(req: DataRequest):
    await check_chain(req.ctx)
    owner = req.ctx["subject"]
    record_id = req.ctx["resource"].split("/")[-1]
    blob = await pool.fetchval("SELECT blob FROM records WHERE id = $1 AND owner = $2",
                               record_id, owner)
    if blob is None:  # чужая запись выглядит так же, как несуществующая
        raise HTTPException(404, "not_found")
    try:
        record = decrypt(blob, owner, record_id)
    except (InvalidTag, ValueError):
        tamper_total.inc()
        await audit_event("data_tamper_detected", "CRITICAL", req.ctx, record_id)
        raise HTTPException(409, "data_integrity_error")
    ops_total.labels(operation="read").inc()
    await audit_event("data_read", "INFO", req.ctx, record_id)
    return {"id": record_id, **record}


@app.post("/list")
async def list_records(req: DataRequest):
    await check_chain(req.ctx)
    owner = req.ctx["subject"]
    rows = await pool.fetch("SELECT id, blob FROM records WHERE owner = $1 ORDER BY created",
                            owner)
    items = []
    for row in rows:
        try:
            items.append({"id": row["id"], "title": decrypt(row["blob"], owner, row["id"])["title"]})
        except (InvalidTag, ValueError):
            tamper_total.inc()
            await audit_event("data_tamper_detected", "CRITICAL", req.ctx, row["id"])
            items.append({"id": row["id"], "title": None, "integrity": "broken"})
    ops_total.labels(operation="list").inc()
    return {"items": items}


@app.get("/health")
async def health():
    return {"status": "ok"}
