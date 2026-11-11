#!/usr/bin/env bash
# C4. Нарушитель с полными правами удаляет строку из журнала аудита, чтобы скрыть
# событие. Цепочка хешей после этого не сходится. ВНИМАНИЕ: журнал остаётся
# испорченным, поэтому запускать в последнюю очередь, а затем вернуть снимок ВМ.
# Запуск на ВМ cloud: bash scripts/attack_audit_log.sh
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}
K="kubectl -n secure-storage"
VERIFY="import httpx;print(httpx.get('http://localhost:8000/verify-log').text)"

echo "== Проверка журнала до вмешательства"
$K exec deploy/audit-service -- python -c "$VERIFY"
echo "== Удаляется строка 3 журнала:"
$K exec deploy/audit-service -- sed -n 3p /var/log/audit/audit.log | cut -c1-150
$K exec deploy/audit-service -- sed -i 3d /var/log/audit/audit.log
echo "== Проверка журнала после вмешательства (ожидается status broken, line 3)"
$K exec deploy/audit-service -- python -c "$VERIFY"
