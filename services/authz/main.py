"""Authz-Service — авторизация и контекстный контроль (точка принятия решений)."""
import json
import os

from fastapi import FastAPI, HTTPException
from prometheus_client import Counter, make_asgi_app
from pydantic import BaseModel

from common.security import audit_event, verify_context

CTX_KEY = os.environ["CTX_GATEWAY_KEY"].encode()
# Политика берётся из ConfigMap app-config, поэтому её изменение
# увидит модуль контроля целостности конфигураций
POLICY = json.loads(os.getenv("POLICY_JSON", "{}"))

app = FastAPI(title="Authz-Service")
app.mount("/metrics", make_asgi_app())

allow_total = Counter("authz_allow_total", "Разрешённые операции")
deny_total = Counter("authz_deny_total", "Запрещённые операции", ["reason"])


class AuthzRequest(BaseModel):
    ctx: dict


def is_allowed(role: str, operation: str) -> bool:
    """Запрет по умолчанию: разрешено только то, что явно есть в политике."""
    return operation in POLICY.get(role, [])


@app.post("/authorize")
async def authorize(req: AuthzRequest):
    ctx = req.ctx
    reason = verify_context(ctx, CTX_KEY, expected_caller="gateway")
    if reason is None and not is_allowed(ctx.get("role"), ctx.get("operation")):
        reason = "policy_violation"
    if reason:
        deny_total.labels(reason=reason).inc()
        await audit_event(reason, "WARNING", ctx, f"role={ctx.get('role')}")
        raise HTTPException(403, reason)
    allow_total.inc()
    return {"decision": "ALLOW"}


@app.get("/health")
async def health():
    return {"status": "ok"}
