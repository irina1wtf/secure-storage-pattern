#!/usr/bin/env bash
# Выдаёт kubeconfig для администратора безопасности. Запускается на ВМ cloud,
# результат выводится в stdout и сразу уходит на ВМ user, на cloud не сохраняется:
#   ssh student@192.168.56.10 'bash secure-storage-pattern/scripts/make_secadmin_kubeconfig.sh' > ~/.kube/config
set -euo pipefail
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}
NS=secure-storage
SERVER=${SERVER:-https://192.168.56.10:6443}
CA=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
TOKEN=$(kubectl -n "$NS" create token security-admin --duration=8760h)
cat <<CFG
apiVersion: v1
kind: Config
clusters:
  - name: stand
    cluster:
      server: $SERVER
      certificate-authority-data: $CA
users:
  - name: security-admin
    user:
      token: $TOKEN
contexts:
  - name: security-admin@stand
    context: {cluster: stand, user: security-admin, namespace: $NS}
current-context: security-admin@stand
CFG
