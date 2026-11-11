#!/usr/bin/env bash
# Возврат рабочей конфигурации после проверки атак (ВМ cloud)
set -e
cd "$(dirname "$0")/.."
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}
kubectl apply -f k8s/01-app-config.yaml
kubectl -n secure-storage rollout restart deploy/business-service
kubectl -n secure-storage rollout status deploy/business-service --timeout=120s
echo "Конфигурация app-config возвращена к исходной."
echo "Если эталон подменяли (атака C1), переподпишите его на ВМ user:"
echo "  python3 ~/secure-storage-pattern/security-admin/sign_etalon.py sign"
echo "Затем дождитесь события config_integrity_ok: bash scripts/show_audit.sh 300 | tail"
