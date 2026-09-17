"""Servidor local de consulta bajo demanda. API key únicamente en el entorno."""
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


def reputation(raw, key):
    if not key: return {"status": "not_configured"}
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
            return cached[1] if cached else {"status": "unavailable"}
    with LOCK:
        while REQUEST_TIMES and REQUEST_TIMES[0] <= now - 60: REQUEST_TIMES.popleft()
        today = datetime.now(timezone.utc).date().isoformat()
        if DAILY["date"] != today: DAILY.update(date=today, count=0)
        if len(REQUEST_TIMES) >= 4 or DAILY["count"] >= 500:
            INFLIGHT.pop(clean).set()
            return {"status": "rate_limited"}
        REQUEST_TIMES.append(now)
        DAILY["count"] += 1
    url_id = base64.urlsafe_b64encode(clean.encode()).decode().rstrip("=")
    request = Request("https://www.virustotal.com/api/v3/urls/" + url_id,
                      headers={"x-apikey": key, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=4) as response:
            stats = json.load(response)["data"]["attributes"]["last_analysis_stats"]
        result = {"status": "found", "malicious": stats.get("malicious", 0),
                  "suspicious": stats.get("suspicious", 0), "total": sum(stats.values())}
    except HTTPError as e:
        result = {"status": "not_found" if e.code == 404 else "rate_limited" if e.code == 429 else "error"}
    except (URLError, KeyError, ValueError, TimeoutError):
        result = {"status": "unavailable"}
    with LOCK:
        REPORT_CACHE[clean] = (time.time() + 1800, result)
        INFLIGHT.pop(clean).set()
    return result


class Handler(BaseHTTPRequestHandler):
    def allowed(self):
        origin = self.headers.get("Origin", "")
        return origin.startswith(("chrome-extension://", "moz-extension://")) or (
            not origin and self.client_address[0] in {"127.0.0.1", "::1"})
    def headers_json(self, code):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        origin = self.headers.get("Origin", "")
        if origin.startswith(("chrome-extension://", "moz-extension://")):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
    def do_OPTIONS(self):
        if not self.allowed(): self.send_error(403); return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "null"))
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    def do_GET(self):
        if not self.allowed(): self.send_error(403); return
        u = urlsplit(self.path)
        if u.path != "/analyze": self.send_error(404); return
        raw = parse_qs(u.query).get("url", [""])[0]
        try:
            parsed = urlsplit(raw)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or len(raw) > 2048:
                raise ValueError()
        except ValueError:
            self.headers_json(400); self.wfile.write(b'{"error":"URL invalida"}'); return
        result = {"model": {"probability": probability(raw, MODEL)} if MODEL else None,
                  "reputation": reputation(raw, os.environ.get("VT_API_KEY"))}
        self.headers_json(200)
        self.wfile.write(json.dumps(result).encode())
    def log_message(self, *_):
        pass  # No registrar URLs consultadas en la consola.


if __name__ == "__main__":
    print("Escudo: servidor en http://127.0.0.1:8765")
    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
