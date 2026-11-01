#!/usr/bin/env bash
# Последние события журнала аудита и проверка цепочки хешей
K="kubectl -n secure-storage"
$K logs deploy/audit-service --tail=${1:-25} | grep '\[AUDIT\]'
echo "-- проверка целостности журнала:"
$K exec deploy/audit-service -- python -c "import httpx;print(httpx.get('http://localhost:8000/verify-log').text)"
