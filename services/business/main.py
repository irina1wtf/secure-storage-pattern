"""Business-Service — бизнес-логика; к данным напрямую доступа не имеет."""
import os

import httpx
from fastapi import FastAPI, HTTPException
from prometheus_client import Counter, make_asgi_app
from pydantic import BaseModel

from common.security import audit_event, sign_context, verify_context

GATEWAY_KEY = os.environ["CTX_GATEWAY_KEY"].encode()
BUSINESS_KEY = os.environ["CTX_BUSINESS_KEY"].encode()
DATA_URL = os.getenv("DATA_URL", "http://data-service:8000")
# Параметры валидации приходят из ConfigMap app-config
VALIDATION_ENABLED = os.getenv("VALIDATION_ENABLED", "true") == "true"
MAX_RECORD_BYTES = int(os.getenv("MAX_RECORD_BYTES", "4096"))

app = FastAPI(title="Business-Service")
app.mount("/metrics", make_asgi_app())

blocked_total = Counter("business_blocked_total", "Заблокированные вызовы", ["reason"])
processed_total = Counter("business_processed_total", "Обработанные операции", ["operation"])

ROUTES = {"write": "/store", "read": "/fetch", "list": "/list"}


class ProcessRequest(BaseModel):
    ctx: dict
    payload: dict | None = None


def validate_record(payload: dict) -> str | None:
    """Проверка записи перед сохранением: состав полей, длина, размер."""
    if not payload or set(payload) != {"title", "content"}:
        return "bad_fields"
    if not payload["title"].strip() or len(payload["title"]) > 200:
        return "bad_title"
    if len(payload["content"].encode()) > MAX_RECORD_BYTES:
        return "too_large"
    return None


async def block(reason: str, ctx: dict, status: int = 403, detail: str = "chain check"):
    blocked_total.labels(reason=reason).inc()
    await audit_event(reason, "WARNING", ctx, detail)
    raise HTTPException(status, reason)


@app.post("/process")
async def process(req: ProcessRequest):
    ctx = req.ctx
    reason = verify_context(ctx, GATEWAY_KEY, expected_caller="gateway")
    if reason is None and ctx.get("decision") != "ALLOW":
        reason = "no_authz_decision"
    if reason:
        await block(reason, ctx)

    operation = ctx["operation"]
    if operation == "write" and VALIDATION_ENABLED:
        problem = validate_record(req.payload)
        if problem:
            await block(f"validation_{problem}", ctx, status=422, detail="record rejected")

    forward = {k: ctx[k] for k in ("request_id", "subject", "operation", "resource")}
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.post(f"{DATA_URL}{ROUTES[operation]}",
                                 json={"ctx": sign_context(forward, "business", BUSINESS_KEY),
                                       "payload": req.payload})
    if resp.status_code != 200:
        is_json = resp.headers.get("content-type", "").startswith("application/json")
        detail = resp.json().get("detail", "error") if is_json else "upstream_error"
        raise HTTPException(resp.status_code, detail)
    processed_total.labels(operation=operation).inc()
    return resp.json()


@app.get("/health")
async def health():
    return {"status": "ok"}
