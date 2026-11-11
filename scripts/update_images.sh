#!/usr/bin/env bash
# Пересборка образов после изменения кода и перезапуск сервисов (ВМ cloud).
# Запуск: bash scripts/update_images.sh gateway   (можно перечислить несколько сервисов)
set -euo pipefail
cd "$(dirname "$0")/.."
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}
SERVICES=${*:-gateway}
for s in $SERVICES; do
  echo "== $s: сборка образа и импорт в k3s"
  docker build -q -t "secure-storage/$s:1.0" --build-arg SERVICE="$s" services >/dev/null
  docker save "secure-storage/$s:1.0" | sudo k3s ctr images import - >/dev/null
  if [ "$s" = gateway ]; then d=gateway; else d="$s-service"; fi
  kubectl -n secure-storage rollout restart "deploy/$d"
  kubectl -n secure-storage rollout status "deploy/$d" --timeout=180s
done
