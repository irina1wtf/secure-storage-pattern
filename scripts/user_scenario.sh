#!/usr/bin/env bash
# Легитимный пользователь (ВМ user). Запуск: GW=http://192.168.56.10:30080 ./user_scenario.sh
GW=${GW:-http://192.168.56.10:30080}
json() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }

echo "== 1. Вход alice"
TOKEN=$(curl -s -X POST "$GW/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice-2026"}' | json "['access_token']")
echo "токен получен: ${TOKEN:0:25}..."

echo "== 2. Запись данных"
ID=$(curl -s -X POST "$GW/records" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Договор №17","content":"Сумма 120 000 руб., срок 30 дней"}' | json "['id']")
echo "создана запись id=$ID"

echo "== 3. Список и чтение своих записей"
curl -s "$GW/records" -H "Authorization: Bearer $TOKEN"; echo
curl -s "$GW/records/$ID" -H "Authorization: Bearer $TOKEN"; echo

echo "== 4. bob пытается прочитать запись alice (ожидается 404)"
TOKEN_BOB=$(curl -s -X POST "$GW/login" -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"Bob-2026"}' | json "['access_token']")
curl -s -w '  HTTP %{http_code}\n' "$GW/records/$ID" -H "Authorization: Bearer $TOKEN_BOB"
echo "$ID" > /tmp/last_record_id
