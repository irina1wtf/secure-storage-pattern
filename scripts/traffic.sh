#!/usr/bin/env bash
# Фоновая работа легитимного пользователя bob для графиков мониторинга (ВМ user).
# Запуск: bash scripts/traffic.sh   Остановка: Ctrl+C
GW=${GW:-http://192.168.56.10:30080}
PAUSE=${PAUSE:-2}
login() {
  curl -s -X POST "$GW/login" -H 'Content-Type: application/json' \
    -d '{"username":"bob","password":"Bob-2026"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])"
}
TOKEN=$(login); STARTED=$(date +%s); n=0; ID=""
while true; do
  if (( $(date +%s) - STARTED > 600 )); then TOKEN=$(login); STARTED=$(date +%s); fi  # токен живёт 15 минут
  if (( n % 5 == 0 )); then
    ID=$(curl -s -X POST "$GW/records" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d "{\"title\":\"Заметка $n\",\"content\":\"Плановая запись $n\"}" \
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  fi
  curl -s -o /dev/null "$GW/records" -H "Authorization: Bearer $TOKEN"
  [ -n "$ID" ] && curl -s -o /dev/null "$GW/records/$ID" -H "Authorization: Bearer $TOKEN"
  n=$((n + 1)); printf '\rциклов выполнено: %d' "$n"; sleep "$PAUSE"
done
