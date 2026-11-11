#!/usr/bin/env bash
# Внешний нарушитель с отдельной ВМ (attacker): обращается к сервису снаружи.
# Запуск: bash scripts/attack_external.sh
GW=${GW:-http://192.168.56.10:30080}
HOST=${GW#http://}; HOST=${HOST%%:*}
code() { curl -s -o /tmp/body -w '%{http_code}' "$@"; echo " $(cat /tmp/body)"; }
step() { echo; echo "== $1"; }

step "A1. Запрос к данным без токена (ожидается 401 missing_jwt)"
code "$GW/records"

step "A2. Поддельный JWT, подписанный подобранным ключом (ожидается 403 invalid_jwt)"
FAKE=$(python3 - <<'PY'
import base64, hmac, hashlib, json, time
b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
head, body = b({"alg": "HS256", "typ": "JWT"}), b({"sub": "alice", "role": "user", "exp": int(time.time()) + 600})
sig = base64.urlsafe_b64encode(hmac.new(b"guessed-secret", f"{head}.{body}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
print(f"{head}.{body}.{sig}")
PY
)
code "$GW/records" -H "Authorization: Bearer $FAKE"

step "A3. Токен без подписи, alg=none (ожидается 403 invalid_jwt)"
NONE=$(python3 -c "import base64,json;b=lambda d:base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode();print(b({'alg':'none'})+'.'+b({'sub':'alice','role':'user','exp':9999999999})+'.')")
code "$GW/records" -H "Authorization: Bearer $NONE"

step "A4. Подбор пароля alice, 5 попыток (ожидается 401 bad_credentials)"
for p in 123456 password alice2026 Alice2026 qwerty; do
  printf '%-10s ' "$p"
  code -X POST "$GW/login" -H 'Content-Type: application/json' -d "{\"username\":\"alice\",\"password\":\"$p\"}"
done

step "A5. Сотрудник поставщика operator входит своей учётной записью и читает данные (ожидается 403 authz_deny)"
TOKEN=$(curl -s -X POST "$GW/login" -H 'Content-Type: application/json' \
  -d '{"username":"operator","password":"Operator-2026"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
echo "токен operator получен: ${TOKEN:0:25}..."
code "$GW/records" -H "Authorization: Bearer $TOKEN"

step "A6. Поиск открытых портов облака: внутренние сервисы и PostgreSQL снаружи не видны"
if command -v nmap >/dev/null; then
  nmap -Pn -p 22,3000,5432,6443,8000-8004,9090,30000-32767 "$HOST" | grep -E '^[0-9]+/tcp|PORT'
else
  for p in 22 5432 6443 8000 8001 8002 8003 8004 30080 30300 30900; do
    timeout 2 bash -c "</dev/tcp/$HOST/$p" 2>/dev/null && echo "$p open" || echo "$p closed"
  done
fi
