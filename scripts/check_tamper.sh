#!/usr/bin/env bash
# Чтение записей alice после искажения в PostgreSQL (атака C3), ВМ user
GW=${GW:-http://192.168.56.10:30080}
TOKEN=$(curl -s -X POST "$GW/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice-2026"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
echo "== Список записей alice (искажённая запись помечена integrity: broken)"
LIST=$(curl -s "$GW/records" -H "Authorization: Bearer $TOKEN")
echo "$LIST" | python3 -c "
import sys, json
for item in json.load(sys.stdin)['items'][:5]: print(' ', item)"
BAD=$(echo "$LIST" | python3 -c "
import sys, json
print(next((i['id'] for i in json.load(sys.stdin)['items'] if i.get('integrity') == 'broken'), ''))")
if [ -z "$BAD" ]; then echo "искажённых записей нет"; exit 0; fi
echo "== Чтение искажённой записи $BAD (ожидается 409 data_integrity_error)"
curl -s -w '  HTTP %{http_code}\n' "$GW/records/$BAD" -H "Authorization: Bearer $TOKEN"
