"""API de análisis para ejecución local y despliegue en Google Cloud Run.

Las claves de reputación se obtienen únicamente desde variables de entorno.
Cloud Run inyecta ``PORT`` y el contenedor escucha en ``0.0.0.0``; durante el
desarrollo local se conservan los valores originales.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from model import probability
from threat_sources import lookup_all, lookup_virustotal


MODEL_PATH = Path(__file__).resolve().parent / "model.json"
MODEL = json.loads(MODEL_PATH.read_text(encoding="utf-8")) if MODEL_PATH.exists() else None
SERVICE_VERSION = "9.5.1"
DEFAULT_ALLOWED_EXTENSION_ORIGINS = "chrome-extension://*,moz-extension://*"


def origin_allowed(origin):
    """Comprueba el origen de la extensión sin convertir CORS en autenticación."""
    configured = os.environ.get(
        "ALLOWED_EXTENSION_ORIGINS", DEFAULT_ALLOWED_EXTENSION_ORIGINS
    )
    for candidate in (item.strip() for item in configured.split(",")):
        if not candidate:
            continue
        if candidate.endswith("*") and origin.startswith(candidate[:-1]):
            return True
        if origin == candidate:
            return True
    return False


def reputation(raw, key):
    """Alias de VirusTotal compatible con versiones y pruebas anteriores."""
    return lookup_virustotal(raw, key)


class Handler(BaseHTTPRequestHandler):
    server_version = "EscudoAPI/" + SERVICE_VERSION

    def allowed(self):
        origin = self.headers.get("Origin", "")
        return origin_allowed(origin) or (
            not origin and self.client_address[0] in {"127.0.0.1", "::1"}
        )

    def send_json(self, code, payload, include_cors=True):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin", "")
        if include_cors and origin_allowed(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        if urlsplit(self.path).path != "/analyze":
            self.send_error(404)
            return
        if not self.allowed():
            self.send_error(403)
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "null"))
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_GET(self):
        request_url = urlsplit(self.path)
        if request_url.path == "/health":
            self.send_json(200, {
                "status": "ok",
                "service": "escudo-transparente-api",
                "version": SERVICE_VERSION,
                "model_loaded": MODEL is not None,
                "virustotal_configured": bool(os.environ.get("VT_API_KEY")),
                "google_safe_browsing_configured": bool(
                    os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
                ),
                "phishtank_configured": bool(os.environ.get("PHISHTANK_API_KEY")),
                "ipqualityscore_configured": bool(os.environ.get("IPQS_API_KEY")),
            })
            return
        if request_url.path != "/analyze":
            self.send_error(404)
            return
        if not self.allowed():
            self.send_error(403)
            return

        raw = parse_qs(request_url.query).get("url", [""])[0]
        try:
            parsed = urlsplit(raw)
            parsed.port  # Valida formatos como :abc o :99999.
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or len(raw) > 2048:
                raise ValueError()
        except ValueError:
            self.send_json(400, {"error": "URL inválida"})
            return

        result = {
            "analysis_version": "evidence-v2",
            "model": {
                "probability": probability(raw, MODEL),
                "source": "local_model",
                "calibrated": False,
                "decision_role": "corroborating",
            } if MODEL else None,
        }
        result.update(lookup_all(raw, os.environ))
        self.send_json(200, result)

    def log_message(self, *_):
        pass  # No registrar URLs consultadas en la consola.


class EscudoHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def runtime_address():
    """Obtiene una dirección compatible con local y con el contrato de Cloud Run."""
    default_host = "0.0.0.0" if os.environ.get("K_SERVICE") else "127.0.0.1"
    host = os.environ.get("HOST", default_host)
    try:
        port = int(os.environ.get("PORT", "8765"))
    except ValueError as exc:
        raise SystemExit("PORT debe ser un número entero") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("PORT debe estar entre 1 y 65535")
    return host, port


if __name__ == "__main__":
    bind_host, bind_port = runtime_address()
    print(f"Escudo API {SERVICE_VERSION}: escuchando en {bind_host}:{bind_port}", flush=True)
    server = EscudoHTTPServer((bind_host, bind_port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
