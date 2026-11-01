#!/usr/bin/env bash
# Нарушитель с полными правами администратора кластера (худший случай УБИ.054).
# Защита здесь не блокирует, а обнаруживает воздействие.
NS=secure-storage; K="kubectl -n $NS"

echo "== C1. Подмена эталона в обход RBAC (подпись не совпадёт)"
NEW=$($K get configmap config-etalon -o jsonpath='{.data.etalon\.json}' | python3 -c "
import sys, json; e = json.load(sys.stdin); e['config_sha256'] = 'f' * 64; print(json.dumps(e))")
$K create configmap config-etalon --from-literal=etalon.json="$NEW" --dry-run=client -o yaml | $K apply -f -
echo "Ожидается событие etalon_signature_invalid в журнале аудита (до 1–2 минут)."

PSQL='psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'

echo "== C2. Администратор СУБД читает таблицу: видит только шифртекст"
$K exec postgres-0 -- sh -c "$PSQL -c \"SELECT id, owner, left(blob, 48) AS blob FROM records\""

echo "== C3. Искажение зашифрованной записи прямо в PostgreSQL"
$K exec postgres-0 -- sh -c "$PSQL -c \"UPDATE records SET blob = CASE WHEN left(blob, 4) = 'AAAA' THEN 'BBBB' ELSE 'AAAA' END || substr(blob, 5) WHERE id = (SELECT id FROM records ORDER BY created LIMIT 1) RETURNING id\""
echo "Теперь пользователь при чтении получит 409 data_integrity_error, а аудит — data_tamper_detected."
