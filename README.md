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

## Быстрый старт (ВМ с Ubuntu Server 26.04 и k3s)

```bash
sudo apt -y install docker.io git curl python3-cryptography
sudo usermod -aG docker $USER   # затем перелогиниться
curl -fL https://raw.githubusercontent.com/k3s-io/k3s/master/install.sh -o install_k3s.sh
sudo sh install_k3s.sh --write-kubeconfig-mode 644 --disable traefik --node-ip 192.168.56.10 --flannel-iface enp0s8 --tls-san 192.168.56.10
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
monitoring/        Prometheus, Grafana, правила оповещения, панель мониторинга
tests/             модульные (unit) и приёмочные (stand) тесты pytest
docker-compose.yml локальная отладка без Kubernetes
```

## Тесты

```bash
bash scripts/run_unit_tests.sh          # ВМ cloud: 59 модульных тестов pytest в контейнере python:3.12-slim
python3 -m pytest tests/stand -v        # ВМ user: 14 приёмочных тестов через API-шлюз
```

## Мониторинг

```bash
bash monitoring/deploy_monitoring.sh
```

Prometheus: `http://<IP>:30900`, Grafana: `http://<IP>:30300` (логин admin, пароль выводит скрипт).
Сетевая политика `monitoring/30-allow-prometheus.yaml` разрешает Prometheus забирать метрики
микросервисов, правила оповещения — `monitoring/alerts.yml`.

## Сценарии проверки

| Скрипт | Где запускать | Что делает |
| --- | --- | --- |
| `scripts/user_scenario.sh` | user | работа легитимного пользователя alice |
| `scripts/traffic.sh` | user | фоновая работа пользователя bob для графиков |
| `scripts/latency.sh` | user | замер времени ответа |
| `scripts/check_validation.sh` | user | проверка валидации записей (422 / 200) |
| `scripts/check_tamper.sh` | user | чтение записи, искажённой в БД (409) |
| `scripts/attack_external.sh` | attacker | A1–A6: внешний нарушитель |
| `scripts/attack_insider.sh` | cloud | B1–B8: администратор приложений поставщика (app-admin) |
| `scripts/attack_root.sh` | cloud | C1–C3: полные права на кластер |
| `scripts/attack_audit_log.sh` | cloud | C4: удаление строки журнала аудита (запускать последним) |
| `scripts/show_audit.sh`, `scripts/restore.sh` | cloud | журнал аудита и восстановление |
| `scripts/run_unit_tests.sh`, `scripts/update_images.sh` | cloud | модульные тесты; пересборка образов |

Секреты в репозитории не хранятся: их создаёт `scripts/gen_secrets.py` при развёртывании.
