#!/usr/bin/env bash
# Автоматизированное модульное тестирование микросервисов (ВМ cloud).
# Тесты выполняются в одноразовом контейнере python:3.12-slim — в том же окружении,
# что и сами сервисы. Запуск: bash scripts/run_unit_tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD":/src -w /src -e COVERAGE_FILE=/tmp/.coverage python:3.12-slim sh -c "
  pip install -q --root-user-action=ignore --disable-pip-version-check \
      -r services/requirements.txt -r tests/requirements-test.txt &&
  python -m pytest tests/unit -v -p no:cacheprovider --cov=services --cov-report=term"
