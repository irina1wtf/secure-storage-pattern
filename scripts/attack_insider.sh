#!/usr/bin/env bash
# Недобросовестный администратор приложений поставщика. Запускается на ВМ cloud,
# куда нарушитель заходит по SSH. Его права — роль app-admin (k8s/02-rbac.yaml).
NS=secure-storage
ADMIN="--as=system:serviceaccount:$NS:app-admin"
K="kubectl -n $NS"
step() { echo; echo "== $1"; }

step "B1. Попытка прочитать ключ шифрования данных (ожидается Forbidden)"
$K $ADMIN get secret data-key 2>&1 | tail -1

step "B2. Попытка изменить эталон конфигурации (ожидается Forbidden)"
$K $ADMIN patch configmap config-etalon -p '{"data":{"etalon.json":"{}"}}' 2>&1 | tail -1

step "B3. Под без меток обращается к Data-Service напрямую (NetworkPolicy: таймаут)"
$K $ADMIN run intruder --rm -i --restart=Never --image=secure-storage/business:1.0 \
  --image-pull-policy=Never --command -- python -c "
import httpx
try: print(httpx.post('http://data-service:8000/fetch', json={'ctx': {}}, timeout=5).text)
except Exception as e: print('соединение заблокировано:', type(e).__name__)" 2>&1 | grep -v 'pod .* deleted'

step "B3a. Под без меток подключается к PostgreSQL напрямую (NetworkPolicy: таймаут)"
$K $ADMIN run intruder-db --rm -i --restart=Never --image=secure-storage/business:1.0 \
  --image-pull-policy=Never --command -- python -c "
import socket
s = socket.socket(); s.settimeout(5)
try: s.connect(('postgres', 5432)); print('порт 5432 доступен!')
except Exception as e: print('соединение с БД заблокировано:', type(e).__name__)" 2>&1 | grep -v 'pod .* deleted'

step "B4. Под маскируется под шлюз (app=gateway) и вызывает Business-Service в обход цепочки"
$K $ADMIN run fake-gateway --rm -i --restart=Never --labels=app=gateway \
  --image=secure-storage/business:1.0 --image-pull-policy=Never --command -- python -c "
import httpx, time
ctx = {'request_id': 'insider-1', 'subject': 'alice', 'role': 'user', 'operation': 'list',
       'resource': 'records', 'decision': 'ALLOW', 'caller': 'gateway', 'ts': int(time.time()), 'sig': 'fake'}
print(httpx.post('http://business-service:8000/process', json={'ctx': ctx}, timeout=5).text)" 2>&1 | grep -v 'pod .* deleted'

step "B5. Под маскируется под бизнес-логику (app=business-service) и читает хранилище"
$K $ADMIN run fake-business --rm -i --restart=Never --labels=app=business-service \
  --image=secure-storage/business:1.0 --image-pull-policy=Never --command -- python -c "
import httpx, time
ctx = {'request_id': 'insider-2', 'subject': 'alice', 'operation': 'list', 'resource': 'records',
       'caller': 'business', 'ts': int(time.time()), 'sig': 'fake'}
print(httpx.post('http://data-service:8000/list', json={'ctx': ctx}, timeout=5).text)" 2>&1 | grep -v 'pod .* deleted'

step "B6. Сценарий №2: отключение валидации штатными средствами"
$K $ADMIN patch configmap app-config -p '{"data":{"VALIDATION_ENABLED":"false"}}'
$K $ADMIN rollout restart deploy/business-service
echo "Изменение разрешено ролью, но будет обнаружено сверкой с эталоном (до 1–2 минут)."
echo "Смотрите: kubectl -n $NS logs deploy/audit-service | grep config_integrity"
