#!/usr/bin/env bash
# Нарушитель с полными правами администратора кластера (худший случай УБИ.054).
# Здесь защита не блокирует действия, а обнаруживает их. Запуск на ВМ cloud:
# bash scripts/attack_root.sh
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}
NS=secure-storage; K="kubectl -n $NS"
PSQL='psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
step() { echo; echo "== $1"; }

step "C1. Подмена эталона в обход RBAC: в эталон записывается хеш текущей (изменённой) конфигурации"
echo "время изменения (UTC): $(date -u +%T)"
NEW=$(CFG="$($K get configmap app-config -o json)" \
      ETALON="$($K get configmap config-etalon -o jsonpath='{.data.etalon\.json}')" python3 -c "
import os, json, hashlib
cfg = json.loads(os.environ['CFG'])['data']
e = json.loads(os.environ['ETALON'])
canon = json.dumps(cfg, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
e['config_sha256'] = hashlib.sha256(canon).hexdigest()   # хеш совпадёт, а подпись - нет
print(json.dumps(e))")
$K create configmap config-etalon --from-literal=etalon.json="$NEW" --dry-run=client -o yaml | $K apply -f -
echo "Ожидается событие etalon_signature_invalid в журнале аудита (обычно за 1–2 минуты)."

step "C2. Администратор СУБД читает таблицу records: видны только шифртексты"
$K exec postgres-0 -- sh -c "$PSQL -c \"SELECT id, owner, left(blob, 40) AS blob FROM records ORDER BY created LIMIT 5\""

step "C3. Искажение первой записи alice прямо в PostgreSQL"
$K exec postgres-0 -- sh -c "$PSQL -c \"UPDATE records SET blob = CASE WHEN left(blob, 4) = 'AAAA' THEN 'BBBB' ELSE 'AAAA' END || substr(blob, 5) WHERE id = (SELECT id FROM records WHERE owner = 'alice' ORDER BY created LIMIT 1) RETURNING id, owner\""
echo "При чтении этой записи alice получит 409 data_integrity_error, в журнал попадёт data_tamper_detected."
echo "Проверка на ВМ user: bash scripts/check_tamper.sh"
