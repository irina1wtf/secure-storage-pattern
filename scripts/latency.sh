#!/usr/bin/env bash
# Замер времени ответа сервиса (ВМ user). Запуск: bash scripts/latency.sh [число запросов]
GW=${GW:-http://192.168.56.10:30080}
N=${1:-100}
login() {
  curl -s -X POST "$GW/login" -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"Alice-2026"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])"
}
stats() {  # читает время в секундах, печатает среднее, медиану, 95-й процентиль и максимум в мс
  python3 -c "
import sys, statistics as s
v = sorted(float(x) * 1000 for x in sys.stdin if x.strip())
p95 = s.quantiles(v, n=20)[18] if len(v) >= 20 else v[-1]
print(f'{sys.argv[1]:<34}{len(v):>5}{s.mean(v):>9.1f}{s.median(v):>9.1f}{p95:>9.1f}{v[-1]:>9.1f}')" "$1"
}
TOKEN=$(login)
AUTH="Authorization: Bearer $TOKEN"
ID=$(curl -s -X POST "$GW/records" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"title":"Замер","content":"Запись для замера чтения"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

python3 -c "
print(f'{\"Запрос\":<34}{\"N\":>5}{\"сред.\":>9}{\"медиана\":>9}{\"95 %\":>9}{\"макс.\":>9}')
print(f'{\"\":<39}{\"мс\":>9}{\"мс\":>9}{\"мс\":>9}{\"мс\":>9}')"
for i in $(seq "$N"); do curl -s -o /dev/null -w '%{time_total}\n' "$GW/health"; done | stats "GET /health (без цепочки)"
for i in $(seq "$N"); do curl -s -o /dev/null -w '%{time_total}\n' "$GW/records/$ID" -H "$AUTH"; done | stats "GET /records/{id} (чтение)"
for i in $(seq "$N"); do curl -s -o /dev/null -w '%{time_total}\n' -X POST "$GW/records" -H "$AUTH" \
  -H 'Content-Type: application/json' -d "{\"title\":\"Замер $i\",\"content\":\"Текст записи для замера\"}"; done | stats "POST /records (запись)"
for i in $(seq "$N"); do curl -s -o /dev/null -w '%{time_total}\n' "$GW/records" -H "$AUTH"; done | stats "GET /records (список)"
for i in $(seq 20); do curl -s -o /dev/null -w '%{time_total}\n' -X POST "$GW/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice-2026"}'; done | stats "POST /login (PBKDF2)"
