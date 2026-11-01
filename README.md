# Паттерн безопасности при угрозе УБИ.054

Курсовая работа: «Разработка паттерна для обеспечения безопасности приложения при угрозе
недобросовестного исполнения обязательств поставщиками облачных услуг» (УБИ.054 БДУ ФСТЭК).

Облачный сервис хранения данных из пяти микросервисов (Python 3.12, FastAPI):

| Сервис | Назначение |
| --- | --- |
| gateway | Единая точка входа: JWT, контекст запроса, подпись контекста |
| authz-service | Авторизация по политике ролей, запрет по умолчанию |
| business-service | Бизнес-логика, проверка цепочки вызовов, валидация записей |
| data-service | Доступ к данным: AES-256-GCM, изоляция владельцев, обнаружение подмены |
| postgres | PostgreSQL 16 (StatefulSet), доступен по сети только для data-service |
| audit-service | Журнал с цепочкой хешей, сверка конфигурации с подписанным эталоном |

## Быстрый старт (ВМ с Ubuntu Server 24.04 и k3s)

```bash
sudo apt -y install docker.io git curl python3-cryptography
sudo usermod -aG docker $USER   # затем перелогиниться
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644 --disable traefik
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
git clone https://github.com/<логин>/secure-storage-pattern.git && cd secure-storage-pattern
bash scripts/deploy.sh
```

Шлюз: `http://<IP>:30080`. Демо-пользователи: alice / Alice-2026, bob / Bob-2026 (роль user),
operator / Operator-2026 (support — сотрудник поставщика, доступа к данным нет).

## Структура

```
services/          код микросервисов и общий Dockerfile
k8s/               namespace, ConfigMap, RBAC, PVC, Deployment/Service, PostgreSQL, NetworkPolicy
security-admin/    sign_etalon.py — подпись эталона конфигурации (Ed25519)
scripts/           deploy.sh, gen_secrets.py, сценарии пользователя и нарушителя
docker-compose.yml локальная отладка без Kubernetes
```

## Сценарии проверки

- `scripts/user_scenario.sh` — легитимный пользователь (ВМ user)
- `scripts/attack_external.sh` — внешний нарушитель (ВМ attacker)
- `scripts/attack_insider.sh` — администратор приложений поставщика (роль app-admin)
- `scripts/attack_root.sh` — полные права на кластер: подмена эталона и данных
- `scripts/show_audit.sh`, `scripts/restore.sh` — журнал аудита и восстановление

Секреты в репозитории не хранятся: их создаёт `scripts/gen_secrets.py` при развёртывании.
