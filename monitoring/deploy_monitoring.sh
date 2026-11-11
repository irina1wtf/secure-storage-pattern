#!/usr/bin/env bash
# Развёртывание мониторинга (Prometheus + Grafana) на ВМ cloud.
# Запуск из каталога репозитория: bash monitoring/deploy_monitoring.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}
NS=monitoring
IMAGES="prom/prometheus:v3.5.0 grafana/grafana:12.1.0"

echo "== 1. Загрузка образов и импорт в k3s (containerd)"
for i in $IMAGES; do
  docker pull -q "$i" >/dev/null
  docker save "$i" | sudo k3s ctr images import - >/dev/null
  echo "   $i"
done

echo "== 2. Пространство имён monitoring и разрешение сбора метрик"
kubectl apply -f monitoring/00-namespace.yaml -f monitoring/30-allow-prometheus.yaml

echo "== 3. Конфигурация Prometheus и Grafana"
kubectl -n $NS create configmap prometheus-config \
  --from-file=monitoring/prometheus.yml --from-file=monitoring/alerts.yml \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n $NS create configmap grafana-provisioning \
  --from-file=monitoring/grafana-datasource.yml --from-file=monitoring/grafana-dashboards.yml \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n $NS create configmap grafana-dashboards \
  --from-file=dashboard.json=monitoring/dashboard.json \
  --dry-run=client -o yaml | kubectl apply -f -
if ! kubectl -n $NS get secret grafana-admin >/dev/null 2>&1; then
  kubectl -n $NS create secret generic grafana-admin \
    --from-literal=password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
fi

echo "== 4. Prometheus и Grafana"
EXISTED=$(kubectl -n $NS get deploy prometheus -o name 2>/dev/null || true)
kubectl apply -f monitoring/10-prometheus.yaml -f monitoring/20-grafana.yaml
if [ -n "$EXISTED" ]; then   # повторный запуск: перечитать изменённую конфигурацию
  kubectl -n $NS rollout restart deploy/prometheus deploy/grafana
fi
kubectl -n $NS rollout status deploy/prometheus --timeout=300s
kubectl -n $NS rollout status deploy/grafana --timeout=300s
kubectl -n $NS get pods,svc

PASS=$(kubectl -n $NS get secret grafana-admin -o jsonpath='{.data.password}' | base64 -d)
echo
echo "Prometheus: http://192.168.56.10:30900"
echo "Grafana:    http://192.168.56.10:30300   логин admin, пароль $PASS"
