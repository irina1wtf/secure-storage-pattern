#!/usr/bin/env python3
"""Генерация секретов паттерна и загрузка их в Kubernetes.
В VK Cloud эти значения хранятся в KMS и попадают в поды через External Secrets
Operator; в стенде их роль играют объекты Secret. Повторный запуск не
перезаписывает уже созданные секреты."""
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

NS = "secure-storage"
OUT = Path(__file__).resolve().parent.parent / "secrets"   # каталог в .gitignore

DEMO_USERS = {  # логин: (роль, пароль)
    "alice": ("user", "Alice-2026"),
    "bob": ("user", "Bob-2026"),
    "operator": ("support", "Operator-2026"),  # сотрудник поставщика
}


def exists(name: str) -> bool:
    return subprocess.run(["kubectl", "-n", NS, "get", "secret", name],
                          capture_output=True).returncode == 0


def create(name: str, **values: str) -> None:
    if exists(name):
        print(f"secret/{name} уже есть — пропускаю")
        return
    args = ["kubectl", "-n", NS, "create", "secret", "generic", name]
    args += [f"--from-literal={k}={v}" for k, v in values.items()]
    subprocess.run(args, check=True, capture_output=True)
    print(f"secret/{name} создан")


def pbkdf2(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def compose_env() -> None:
    """Файл .env с демо-пользователями для docker compose (отладка)."""
    users = {u: {"role": role, "pwd": pbkdf2(pwd)} for u, (role, pwd) in DEMO_USERS.items()}
    env = OUT.parent / ".env"
    env.write_text(f"USERS_JSON='{json.dumps(users)}'\n")
    print(f"записан {env}")


def main() -> None:
    if "--compose" in sys.argv:
        compose_env()
        return
    OUT.mkdir(exist_ok=True)
    create("jwt-secret", JWT_SECRET=secrets.token_hex(32))
    create("ctx-gateway-key", key=secrets.token_hex(32))
    create("ctx-business-key", key=secrets.token_hex(32))
    create("data-key", DATA_KEY=base64.b64encode(os.urandom(32)).decode())
    create("db-credentials", POSTGRES_USER="storage", POSTGRES_DB="storage",
           POSTGRES_PASSWORD=secrets.token_urlsafe(24))
    users = {u: {"role": role, "pwd": pbkdf2(pwd)} for u, (role, pwd) in DEMO_USERS.items()}
    create("users", USERS_JSON=json.dumps(users))
    (OUT / "demo-users.txt").write_text(
        "\n".join(f"{u}\t{role}\t{pwd}" for u, (role, pwd) in DEMO_USERS.items()) + "\n")
    print(f"демо-пользователи записаны в {OUT / 'demo-users.txt'}")


if __name__ == "__main__":
    main()
