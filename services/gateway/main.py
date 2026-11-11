"""API-Gateway — единая точка входа (точка применения решений)."""
import hashlib
import hmac
import json
import os
import time
import uuid

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request
from prometheus_client import Counter, Histogram, make_asgi_app
from pydantic import BaseModel

from common.security import audit_event, sign_context

JWT_SECRET = os.environ["JWT_SECRET"]
CTX_KEY = os.environ["CTX_GATEWAY_KEY"].encode()
USERS = json.loads(os.environ["USERS_JSON"])  # {"alice": {"role": ..., "pwd": "salt$hash"}}
AUTHZ_URL = os.getenv("AUTHZ_URL", "http://authz-service:8000")
BUSINESS_URL = os.getenv("BUSINESS_URL", "http://business-service:8000")
TOKEN_TTL = int(os.getenv("TOKEN_TTL", "900"))

app = FastAPI(title="API-Gateway")
app.mount("/metrics", make_asgi_app())

requests_total = Counter("gateway_requests_total", "Запросы через шлюз", ["result"])
rejected_total = Counter("gateway_rejected_total", "Отклонённые запросы", ["reason"])
# Время обработки запроса шлюзом (вся цепочка вызовов) — для оценки задержки,
# которую вносят проверки паттерна. Границы корзин в секундах
latency = Histogram("gateway_request_duration_seconds", "Время обработки запроса",
                    ["route"], buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5))
ROUTES = {("POST", "/login"): "login", ("POST", "/records"): "write",
          ("GET", "/records"): "list"}
# Ряды метрик создаются сразу с нулём, чтобы первое событие было видно в мониторинге
for r in ("login", "write", "list", "read"):
    latency.labels(route=r)
for r in ("missing_jwt", "invalid_jwt", "bad_credentials", "authz_deny"):
    rejected_total.labels(reason=r)
for r in ("ok", "rejected", "error"):
    requests_total.labels(result=r)


class LoginRequest(BaseModel):
    username: str
    password: str


class RecordIn(BaseModel):
    title: str
    content: str


def check_password(password: str, stored: str) -> bool:
    """Сверка пароля с хешем PBKDF2-SHA256 за постоянное время."""
    salt_hex, hash_hex = stored.split("$")
    calc = hashlib.pbkdf2_hmac("sha256", password.encode(),
                               bytes.fromhex(salt_hex), 200_000)
    return hmac.compare_digest(calc.hex(), hash_hex)


def issue_jwt(username: str, role: str) -> str:
    now = int(time.time())
    claims = {"sub": username, "role": role, "iat": now,
              "exp": now + TOKEN_TTL, "jti": uuid.uuid4().hex}
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")


def verify_jwt(token: str):
    """Проверка подписи и срока действия токена. Алгоритм задан жёстко,
    чтобы нельзя было подсунуть токен с alg=none."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"],
                          options={"require": ["sub", "role", "exp"]})
    except jwt.PyJWTError:
        return None


async def reject(status: int, reason: str, ctx: dict) -> None:
    rejected_total.labels(reason=reason).inc()
    requests_total.labels(result="rejected").inc()
    await audit_event(reason, "WARNING", ctx, reason)
    raise HTTPException(status, reason)


async def handle(request: Request, operation: str, resource: str, payload=None):
    request_id = uuid.uuid4().hex
    ctx = {"request_id": request_id, "operation": operation, "resource": resource}

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        await reject(401, "missing_jwt", ctx)
    claims = verify_jwt(auth.removeprefix("Bearer "))
    if not claims:
        await reject(403, "invalid_jwt", ctx)

    ctx.update(subject=claims["sub"], role=claims["role"])
    async with httpx.AsyncClient(timeout=5) as client:
        decision = await client.post(f"{AUTHZ_URL}/authorize",
                                     json={"ctx": sign_context(ctx, "gateway", CTX_KEY)})
        if decision.status_code != 200:
            await reject(403, "authz_deny", ctx)

        ctx["decision"] = "ALLOW"
        resp = await client.post(f"{BUSINESS_URL}/process",
                                 json={"ctx": sign_context(ctx, "gateway", CTX_KEY),
                                       "payload": payload})
    requests_total.labels(result="ok" if resp.status_code == 200 else "error").inc()
    if resp.status_code == 200:
        await audit_event("request_ok", "INFO", ctx, operation)
    if resp.status_code != 200:
        is_json = resp.headers.get("content-type", "").startswith("application/json")
        detail = resp.json().get("detail", "error") if is_json else "upstream_error"
        raise HTTPException(resp.status_code, detail)
    return {"request_id": request_id, **resp.json()}


@app.middleware("http")
async def measure_latency(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    path = request.url.path
    route = ROUTES.get((request.method, path))
    if route is None and request.method == "GET" and path.startswith("/records/"):
        route = "read"
    if route:
        latency.labels(route=route).observe(time.perf_counter() - start)
    return response


@app.post("/login")
async def login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user or not check_password(req.password, user["pwd"]):
        await reject(401, "bad_credentials", {"subject": req.username})
    return {"access_token": issue_jwt(req.username, user["role"]), "token_type": "bearer"}


@app.post("/records")
async def write_record(record: RecordIn, request: Request):
    return await handle(request, "write", "records", record.model_dump())


@app.get("/records")
async def list_records(request: Request):
    return await handle(request, "list", "records")


@app.get("/records/{record_id}")
async def read_record(record_id: str, request: Request):
    return await handle(request, "read", f"records/{record_id}")


@app.get("/health")
async def health():
    return {"status": "ok"}
