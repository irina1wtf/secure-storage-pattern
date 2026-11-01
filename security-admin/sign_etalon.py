#!/usr/bin/env python3
"""Инструмент администратора безопасности. Запускается на ВМ user (сторона клиента)
с kubeconfig учётной записи security-admin (scripts/make_secadmin_kubeconfig.sh).

  python3 sign_etalon.py init   — создать пару ключей Ed25519 и загрузить открытый ключ в кластер
  python3 sign_etalon.py sign   — подписать текущую app-config как эталон

Закрытый ключ хранится только у администратора безопасности (KEY_DIR) и в
кластер не попадает. Администратор приложений не может ни изменить эталон
(нет прав RBAC), ни подделать подпись (нет закрытого ключа)."""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NS = "secure-storage"
KEY_DIR = Path(os.getenv("KEY_DIR", Path.home() / ".security-admin"))
PRIVATE = KEY_DIR / "etalon_private.pem"


def canonical(obj) -> bytes:  # то же правило, что в common/security.py
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def kubectl(*args: str, stdin: str | None = None) -> str:
    return subprocess.run(["kubectl", "-n", NS, *args], input=stdin, text=True,
                          check=True, capture_output=True).stdout


def init() -> None:
    KEY_DIR.mkdir(mode=0o700, exist_ok=True)
    if not PRIVATE.exists():
        key = Ed25519PrivateKey.generate()
        PRIVATE.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        PRIVATE.chmod(0o600)
        print(f"закрытый ключ создан: {PRIVATE}")
    key = serialization.load_pem_private_key(PRIVATE.read_bytes(), password=None)
    public_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
    with tempfile.NamedTemporaryFile("wb", suffix=".pem") as tmp:
        tmp.write(public_pem)
        tmp.flush()
        manifest = kubectl("create", "secret", "generic", "etalon-pubkey",
                           f"--from-file=public.pem={tmp.name}", "--dry-run=client", "-o", "yaml")
    kubectl("apply", "-f", "-", stdin=manifest)
    print("открытый ключ загружен в secret/etalon-pubkey")


def sign() -> None:
    key = serialization.load_pem_private_key(PRIVATE.read_bytes(), password=None)
    data = json.loads(kubectl("get", "configmap", "app-config", "-o", "json"))["data"]
    try:
        old = json.loads(json.loads(kubectl("get", "configmap", "config-etalon", "-o", "json"))
                         ["data"]["etalon.json"])["version"]
    except subprocess.CalledProcessError:
        old = 0
    body = {"version": old + 1,
            "config_sha256": hashlib.sha256(canonical(data)).hexdigest(),
            "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    etalon = {**body, "signature": base64.b64encode(key.sign(canonical(body))).decode()}
    manifest = kubectl("create", "configmap", "config-etalon",
                       f"--from-literal=etalon.json={json.dumps(etalon)}",
                       "--dry-run=client", "-o", "yaml")
    kubectl("apply", "-f", "-", stdin=manifest)
    print(f"эталон v{body['version']} подписан, sha256={body['config_sha256'][:16]}…")


if __name__ == "__main__":
    {"init": init, "sign": sign}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
