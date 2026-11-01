#!/usr/bin/env bash
# Полное развёртывание паттерна на машине «облако» (k3s). Запуск: bash scripts/deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."
SERVICES="gateway authz business data audit"
BASE_IMAGE=${BASE_IMAGE:-python:3.12-slim}

echo "== 1. Сборка образов"
for s in $SERVICES; do
  docker build -q -t "secure-storage/$s:1.0" --build-arg SERVICE="$s" \
    --build-arg BASE_IMAGE="$BASE_IMAGE" services
done

echo "== 2. Импорт образов в k3s (containerd)"
docker pull -q postgres:16-alpine >/dev/null
docker save postgres:16-alpine | sudo k3s ctr images import - >/dev/null
for s in $SERVICES; do
  docker save "secure-storage/$s:1.0" | sudo k3s ctr images import - >/dev/null
done

echo "== 3. Пространство имён, конфигурация, роли, тома"
kubectl apply -f k8s/00-namespace.yaml -f k8s/01-app-config.yaml \
              -f k8s/02-rbac.yaml -f k8s/03-storage.yaml

echo "== 4. Секреты (роль KMS в стенде)"
python3 scripts/gen_secrets.py

echo "== 5. PostgreSQL, микросервисы и сетевые политики"
kubectl apply -f k8s/
kubectl -n secure-storage rollout status statefulset/postgres --timeout=240s
for d in gateway authz-service business-service data-service; do
  kubectl -n secure-storage rollout status "deploy/$d" --timeout=180s
done
kubectl -n secure-storage get pods,svc
IP=$(hostname -I | tr ' ' '\n' | grep '^192\.168\.56\.' | head -1)
echo "Готово. Шлюз: http://${IP:-<IP машины cloud>}:30080"
if ! kubectl -n secure-storage get configmap config-etalon >/dev/null 2>&1; then
  echo
  echo "audit-service ждёт эталон конфигурации (ContainerCreating — это нормально)."
  echo "Подпишите эталон на ВМ user как администратор безопасности:"
  echo "  python3 sign_etalon.py init && python3 sign_etalon.py sign"
fi
