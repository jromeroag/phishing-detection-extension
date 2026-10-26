"""Configura la extensión para consumir una API local o de Cloud Run."""

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "extension" / "config.js"
MANIFEST_PATH = ROOT / "extension" / "manifest.json"
LOCAL_API_URL = "http://127.0.0.1:8765"
RUN_APP_PERMISSION = re.compile(r"^https://[^/]+\.run\.app/\*$")


def normalize_api_url(raw):
    value = raw.strip().rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("La URL debe comenzar con http:// o https:// y tener un dominio.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("La URL no puede contener credenciales, parámetros ni fragmentos.")
    if parsed.path not in {"", "/"}:
        raise ValueError("Usa solo el origen del servicio, sin /analyze ni otras rutas.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("El puerto de la URL no es válido.") from exc
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("Los servicios remotos deben utilizar HTTPS.")
    return value


def update_manifest(api_url):
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    current = manifest.get("host_permissions", [])
    preserved = [
        item for item in current
        if item != LOCAL_API_URL + "/*" and not RUN_APP_PERMISSION.match(item)
    ]
    permissions = preserved + [LOCAL_API_URL + "/*"]
    if api_url != LOCAL_API_URL:
        permissions.append(api_url + "/*")
    manifest["host_permissions"] = list(dict.fromkeys(permissions))
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def update_config(api_url):
    encoded = json.dumps(api_url, ensure_ascii=False)
    CONFIG_PATH.write_text(
        "// Este archivo no contiene secretos. El script de despliegue actualiza únicamente\n"
        "// la dirección pública de Cloud Run. El valor inicial conserva el modo local.\n"
        "globalThis.ESCUDO_CONFIG = Object.freeze({\n"
        f"  API_BASE_URL: {encoded}\n"
        "});\n",
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(
        description="Configura el endpoint remoto utilizado por Escudo Transparente."
    )
    parser.add_argument("api_url", help="Origen HTTPS de Cloud Run o URL local")
    args = parser.parse_args()
    try:
        api_url = normalize_api_url(args.api_url)
    except ValueError as exc:
        parser.error(str(exc))
    update_config(api_url)
    update_manifest(api_url)
    print(f"Extensión configurada para: {api_url}")


if __name__ == "__main__":
    main()
