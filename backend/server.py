"""API de análisis para ejecución local y despliegue en Google Cloud Run.

La clave de VirusTotal se obtiene únicamente desde la variable de entorno
``VT_API_KEY``. Cloud Run inyecta ``PORT`` y el contenedor escucha en
``0.0.0.0``; durante el desarrollo local se conservan los valores originales.
"""
import base64
import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from model import probability

MODEL_PATH = Path(__file__).resolve().parent / "model.json"
MODEL = json.loads(MODEL_PATH.read_text(encoding="utf-8")) if MODEL_PATH.exists() else None
REPORT_CACHE = {}
INFLIGHT = {}
REQUEST_TIMES = deque()
DAILY = {"date": "", "count": 0}
LOCK = threading.Lock()
SERVICE_VERSION = "9.4.0"
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


def reputation_result(status, **details):
    """Respuesta trazable sin incluir la URL ni la credencial consultada."""
    return {"status": status, "source": "virustotal", "scope": "scheme_host_port_path",
            "query_parameters_shared": False, **details}


def reputation(raw, key):
    if not key: return reputation_result("not_configured")
    parsed = urlsplit(raw)
    # Una consulta automática no comparte parámetros, fragmentos ni credenciales.
    clean = parsed.scheme + "://" + parsed.hostname + ((':' + str(parsed.port)) if parsed.port else '') + (parsed.path or '/')
    now = time.time()
    waiting = None
    with LOCK:
        cached = REPORT_CACHE.get(clean)
        if cached and cached[0] > now: return cached[1]
        waiting = INFLIGHT.get(clean)
        if not waiting: INFLIGHT[clean] = threading.Event()
    if waiting:
        waiting.wait(5.5)
        with LOCK:
            cached = REPORT_CACHE.get(clean)
            return cached[1] if cached else reputation_result("unavailable")
    with LOCK:
        while REQUEST_TIMES and REQUEST_TIMES[0] <= now - 60: REQUEST_TIMES.popleft()
        today = datetime.now(timezone.utc).date().isoformat()
        if DAILY["date"] != today: DAILY.update(date=today, count=0)
        if len(REQUEST_TIMES) >= 4 or DAILY["count"] >= 500:
            INFLIGHT.pop(clean).set()
            return reputation_result("rate_limited")
        REQUEST_TIMES.append(now)
        DAILY["count"] += 1
    url_id = base64.urlsafe_b64encode(clean.encode()).decode().rstrip("=")
    request = Request("https://www.virustotal.com/api/v3/urls/" + url_id,
                      headers={"x-apikey": key, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=4) as response:
            stats = json.load(response)["data"]["attributes"]["last_analysis_stats"]
        result = reputation_result("found", malicious=stats.get("malicious", 0),
                                   suspicious=stats.get("suspicious", 0), total=sum(stats.values()))
    except HTTPError as e:
        result = reputation_result("not_found" if e.code == 404 else "rate_limited" if e.code == 429 else "error")
    except (URLError, KeyError, ValueError, TimeoutError):
        result = reputation_result("unavailable")
    with LOCK:
        REPORT_CACHE[clean] = (time.time() + 1800, result)
        INFLIGHT.pop(clean).set()
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "EscudoAPI/" + SERVICE_VERSION

    def allowed(self):
        origin = self.headers.get("Origin", "")
        return origin_allowed(origin) or (
            not origin and self.client_address[0] in {"127.0.0.1", "::1"})

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
        u = urlsplit(self.path)
        if u.path == "/health":
            self.send_json(200, {
                "status": "ok",
                "service": "escudo-transparente-api",
                "version": SERVICE_VERSION,
                "model_loaded": MODEL is not None,
                "virustotal_configured": bool(os.environ.get("VT_API_KEY")),
            })
            return
        if u.path != "/analyze":
            self.send_error(404)
            return
        if not self.allowed():
            self.send_error(403)
            return
        raw = parse_qs(u.query).get("url", [""])[0]
        try:
            parsed = urlsplit(raw)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or len(raw) > 2048:
                raise ValueError()
        except ValueError:
            self.send_json(400, {"error": "URL inválida"})
            return
        result = {
            "analysis_version": "evidence-v1",
            "model": {"probability": probability(raw, MODEL), "source": "local_model",
                      "calibrated": False, "decision_role": "corroborating"} if MODEL else None,
            "reputation": reputation(raw, os.environ.get("VT_API_KEY"))
        }
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
