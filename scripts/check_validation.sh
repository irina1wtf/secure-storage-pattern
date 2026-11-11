#!/usr/bin/env bash
# Проверка валидации записей в Business-Service (ВМ user).
# При VALIDATION_ENABLED=true обе записи отклоняются (422), после атаки B8 — сохраняются (200).
GW=${GW:-http://192.168.56.10:30080}
TOKEN=$(curl -s -X POST "$GW/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice-2026"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
post() { curl -s -w '  HTTP %{http_code}\n' -X POST "$GW/records" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "$1"; }
echo "== Запись с пустым заголовком"
post '{"title":"   ","content":"запись без заголовка"}'
echo "== Запись размером 5000 байт при ограничении MAX_RECORD_BYTES = 4096"
post "{\"title\":\"Большая запись\",\"content\":\"$(python3 -c "print('x' * 5000)")\"}"
