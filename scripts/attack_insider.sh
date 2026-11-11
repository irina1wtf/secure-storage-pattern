#!/usr/bin/env bash
# Недобросовестный администратор приложений поставщика. Запускается на ВМ cloud,
# куда нарушитель заходит по SSH. Все команды выполняются от имени учётной записи
# app-admin (параметр --as), её права заданы ролью app-admin-role (k8s/02-rbac.yaml).
# Запуск: bash scripts/attack_insider.sh
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}
NS=secure-storage
ADMIN="--as=system:serviceaccount:$NS:app-admin"
K="kubectl -n $NS"
step() { echo; echo "== $1"; }
quiet() { grep -v -E 'pod .* deleted|^Warning: would violate|^If you don'"'"'t see a command prompt'; }

step "B1. Попытка прочитать ключ шифрования данных data-key (ожидается Forbidden)"
$K $ADMIN get secret data-key 2>&1 | tail -1

step "B2. Попытка изменить эталон конфигурации config-etalon (ожидается Forbidden)"
$K $ADMIN patch configmap config-etalon -p '{"data":{"etalon.json":"{}"}}' 2>&1 | tail -1

step "B3. Под без меток обращается к Data-Service напрямую (NetworkPolicy: соединение не устанавливается)"
$K $ADMIN run intruder --rm -i --restart=Never --image=secure-storage/business:1.0 \
  --image-pull-policy=Never --command -- python -c "
import httpx
try: print(httpx.post('http://data-service:8000/fetch', json={'ctx': {}}, timeout=5).text)
except Exception as e: print('соединение заблокировано:', type(e).__name__)" 2>&1 | quiet

step "B4. Под без меток подключается к PostgreSQL напрямую (NetworkPolicy: соединение не устанавливается)"
$K $ADMIN run intruder-db --rm -i --restart=Never --image=secure-storage/business:1.0 \
  --image-pull-policy=Never --command -- python -c "
import socket
s = socket.socket(); s.settimeout(5)
try: s.connect(('postgres', 5432)); print('порт 5432 доступен!')
except Exception as e: print('соединение с БД заблокировано:', type(e).__name__)" 2>&1 | quiet

step "B5. Под с меткой app=gateway вызывает Business-Service в обход цепочки (ожидается 403 forged_context)"
$K $ADMIN run fake-gateway --rm -i --restart=Never --labels=app=gateway \
  --image=secure-storage/business:1.0 --image-pull-policy=Never --command -- python -c "
import httpx, time
ctx = {'request_id': 'insider-1', 'subject': 'alice', 'role': 'user', 'operation': 'list',
       'resource': 'records', 'decision': 'ALLOW', 'caller': 'gateway', 'ts': int(time.time()), 'sig': 'fake'}
print(httpx.post('http://business-service:8000/process', json={'ctx': ctx}, timeout=5).text)" 2>&1 | quiet

step "B6. Под с меткой app=business-service читает хранилище (ожидается 403 integrity_violation)"
$K $ADMIN run fake-business --rm -i --restart=Never --labels=app=business-service \
  --image=secure-storage/business:1.0 --image-pull-policy=Never --command -- python -c "
import httpx, time
ctx = {'request_id': 'insider-2', 'subject': 'alice', 'operation': 'list', 'resource': 'records',
       'caller': 'business', 'ts': int(time.time()), 'sig': 'fake'}
print(httpx.post('http://data-service:8000/list', json={'ctx': ctx}, timeout=5).text)" 2>&1 | quiet

step "B7. Попытка удалить строку журнала аудита внутри контейнера (ожидается Forbidden)"
$K $ADMIN exec deploy/audit-service -- sh -c 'sed -i 3d /var/log/audit/audit.log' 2>&1 | tail -1

step "B8. Сценарий № 2: отключение валидации записей штатными средствами"
echo "время изменения (UTC): $(date -u +%T)"
$K $ADMIN patch configmap app-config -p '{"data":{"VALIDATION_ENABLED":"false"}}'
$K $ADMIN rollout restart deploy/business-service
echo "Изменение разрешено ролью app-admin, но обнаруживается сверкой с эталоном (обычно за 1–2 минуты)."
echo "Проверка: kubectl -n $NS logs deploy/audit-service --timestamps | grep config_integrity"
