#!/usr/bin/env bash
# Восстановление после демонстрации атак: возврат рабочей конфигурации
set -e
cd "$(dirname "$0")/.."
kubectl apply -f k8s/01-app-config.yaml
kubectl -n secure-storage rollout restart deploy/business-service
echo "Конфигурация возвращена. Если эталон подменяли (attack_root.sh), переподпишите его"
echo "на ВМ user: python3 sign_etalon.py sign. Затем ждите config_integrity_ok в журнале."
