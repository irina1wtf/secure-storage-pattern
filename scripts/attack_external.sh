#!/usr/bin/env bash
# Нарушитель с отдельной ВМ (attacker): обращается к сервису снаружи.
GW=${GW:-http://192.168.56.10:30080}
HOST=${GW#http://}; HOST=${HOST%%:*}
code() { curl -s -o /tmp/body -w '%{http_code}' "$@"; echo " $(cat /tmp/body)"; }

echo "== A1. Запрос без токена (ожидается 401 missing_jwt)"
code "$GW/records"

echo "== A2. Поддельный JWT, подписанный чужим ключом (ожидается 403 invalid_jwt)"
FAKE=$(python3 - <<'PY'
import base64, hmac, hashlib, json, time
b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
head, body = b({"alg": "HS256", "typ": "JWT"}), b({"sub": "alice", "role": "user", "exp": int(time.time()) + 600})
sig = base64.urlsafe_b64encode(hmac.new(b"guessed-secret", f"{head}.{body}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
print(f"{head}.{body}.{sig}")
PY
)
code "$GW/records" -H "Authorization: Bearer $FAKE"

echo "== A3. Токен с alg=none (ожидается 403 invalid_jwt)"
NONE=$(python3 -c "import base64,json;b=lambda d:base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode();print(b({'alg':'none'})+'.'+b({'sub':'alice','role':'user','exp':9999999999})+'.')")
code "$GW/records" -H "Authorization: Bearer $NONE"

echo "== A4. Сотрудник поставщика operator входит своей учёткой и читает данные (ожидается 403 authz_deny)"
TOKEN=$(curl -s -X POST "$GW/login" -H 'Content-Type: application/json' \
  -d '{"username":"operator","password":"Operator-2026"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
code "$GW/records" -H "Authorization: Bearer $TOKEN"

echo "== A5. Поиск открытых портов облака: внутренние сервисы снаружи не видны"
if command -v nmap >/dev/null; then nmap -Pn -p 22,6443,8000-8004,30000-30100 "$HOST" | grep -E 'open|PORT'
else for p in 8000 8001 8002 8003 8004 30080; do timeout 2 bash -c "</dev/tcp/$HOST/$p" 2>/dev/null && echo "$p open" || echo "$p closed"; done; fi
