"""Consultas de reputacion externas usadas por Escudo Transparente.

Las credenciales se reciben solo como argumentos desde variables de entorno.
Antes de consultar una fuente se eliminan usuario, contrasena, parametros y
fragmento de la URL. Los resultados se cachean en memoria para cuidar cuotas.
"""

import base64
import ipaddress
import json
import re
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


USER_AGENT = "EscudoTransparente/9.6.0 (academic phishing-defense prototype)"
CACHE = {}
INFLIGHT = {}
REQUEST_TIMES = {}
DAILY = {}
LOCK = threading.Lock()

# Limites conservadores por instancia. No sustituyen las cuotas del proveedor.
PROVIDER_LIMITS = {
    "virustotal": (4, 500),
    "google_safe_browsing": (30, 1000),
    "phishtank": (4, 500),
    "ipqualityscore": (4, 500),
}


def source_result(source, status, **details):
    """Crea una respuesta trazable sin devolver URL ni credenciales."""
    return {
        "status": status,
        "source": source,
        "scope": "scheme_host_port_path",
        "query_parameters_shared": False,
        **details,
    }


def sanitized_external_url(raw):
    """Devuelve solo esquema, host, puerto y ruta para consultas externas."""
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL invalida")
    port = parsed.port  # Tambien valida puertos mal formados.
    hostname = parsed.hostname
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = display_host + (f":{port}" if port else "")
    return f"{parsed.scheme}://{authority}{parsed.path or '/'}"


def is_public_target(raw):
    """Evita enviar direcciones locales o reservadas a terceros."""
    hostname = (urlsplit(raw).hostname or "").lower().rstrip(".")
    if not hostname or hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return True
    return not any((
        address.is_private,
        address.is_loopback,
        address.is_link_local,
        address.is_multicast,
        address.is_reserved,
        address.is_unspecified,
    ))


def _truthy(value):
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "y"}


def _duration_seconds(value, default=1800):
    match = re.fullmatch(r"(\d+(?:\.\d+)?)s", str(value or ""))
    if not match:
        return default
    return max(1, min(float(match.group(1)), 86400))


def _http_error_status(code):
    if code in {401, 403}:
        return "invalid_key"
    if code in {429, 509}:
        return "rate_limited"
    return "error"


def _take_quota(source, now):
    per_minute, per_day = PROVIDER_LIMITS[source]
    timestamps = REQUEST_TIMES.setdefault(source, deque())
    while timestamps and timestamps[0] <= now - 60:
        timestamps.popleft()
    today = datetime.now(timezone.utc).date().isoformat()
    daily = DAILY.setdefault(source, {"date": today, "count": 0})
    if daily["date"] != today:
        daily.update(date=today, count=0)
    if len(timestamps) >= per_minute or daily["count"] >= per_day:
        return False
    timestamps.append(now)
    daily["count"] += 1
    return True


def _cached_lookup(source, clean_url, fetcher):
    cache_key = (source, clean_url)
    now = time.time()
    with LOCK:
        cached = CACHE.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]
        waiting = INFLIGHT.get(cache_key)
        if waiting is None:
            INFLIGHT[cache_key] = threading.Event()
        else:
            waiting_event = waiting
    if waiting is not None:
        waiting_event.wait(6)
        with LOCK:
            cached = CACHE.get(cache_key)
            return cached[1] if cached else source_result(source, "unavailable")

    with LOCK:
        allowed = _take_quota(source, now)
    if not allowed:
        result = source_result(source, "rate_limited")
        ttl = 60
    else:
        try:
            result, ttl = fetcher()
        except HTTPError as exc:
            result = source_result(source, _http_error_status(exc.code))
            ttl = 300
        except (URLError, TimeoutError, OSError):
            result = source_result(source, "unavailable")
            ttl = 60
        except (KeyError, TypeError, ValueError):
            result = source_result(source, "error")
            ttl = 300
        except Exception:
            # Una fuente externa nunca debe derribar el análisis completo.
            result = source_result(source, "error")
            ttl = 60

    with LOCK:
        CACHE[cache_key] = (time.time() + ttl, result)
        event = INFLIGHT.pop(cache_key, None)
        if event:
            event.set()
    return result


def _prepare(raw, key, source):
    if not key:
        return None, source_result(source, "not_configured")
    clean = sanitized_external_url(raw)
    if not is_public_target(clean):
        return None, source_result(source, "not_applicable", reason="local_or_private_target")
    return clean, None


def lookup_virustotal(raw, key):
    clean, early = _prepare(raw, key, "virustotal")
    if early:
        return early

    def fetch():
        url_id = base64.urlsafe_b64encode(clean.encode()).decode().rstrip("=")
        request = Request(
            "https://www.virustotal.com/api/v3/urls/" + url_id,
            headers={"x-apikey": key, "Accept": "application/json", "User-Agent": USER_AGENT},
        )
        try:
            with urlopen(request, timeout=4) as response:
                stats = json.load(response)["data"]["attributes"]["last_analysis_stats"]
        except HTTPError as exc:
            if exc.code == 404:
                return source_result("virustotal", "not_found"), 1800
            raise
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        return source_result(
            "virustotal",
            "found",
            malicious=malicious,
            suspicious=suspicious,
            total=sum(int(value) for value in stats.values()),
        ), 1800

    return _cached_lookup("virustotal", clean, fetch)


def lookup_google_safe_browsing(raw, key):
    clean, early = _prepare(raw, key, "google_safe_browsing")
    if early:
        return early

    def fetch():
        query = urlencode({"key": key, "urls": clean})
        request = Request(
            "https://safebrowsing.googleapis.com/v5/urls:search?" + query,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        with urlopen(request, timeout=4) as response:
            payload = json.load(response)
        threats = payload.get("threats") or []
        threat_types = sorted({
            threat_type
            for threat in threats
            for threat_type in (threat.get("threatTypes") or [])
            if isinstance(threat_type, str)
        })
        status = "match" if threats else "no_match"
        result = source_result(
            "google_safe_browsing",
            status,
            threat_types=threat_types,
            match_count=len(threats),
        )
        return result, _duration_seconds(payload.get("cacheDuration"), 300)

    return _cached_lookup("google_safe_browsing", clean, fetch)


def lookup_phishtank(raw, key):
    clean, early = _prepare(raw, key, "phishtank")
    if early:
        return early

    def fetch():
        form = urlencode({"url": clean, "format": "json", "app_key": key}).encode()
        request = Request(
            "https://checkurl.phishtank.com/checkurl/",
            data=form,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": USER_AGENT,
            },
        )
        with urlopen(request, timeout=4) as response:
            payload = json.load(response)
        details = payload.get("results") or {}
        in_database = _truthy(details.get("in_database"))
        result = source_result(
            "phishtank",
            "found" if in_database else "not_found",
            in_database=in_database,
            verified=_truthy(details.get("verified")),
            valid=_truthy(details.get("valid")),
            phish_id=details.get("phish_id") if in_database else None,
        )
        return result, 1800

    return _cached_lookup("phishtank", clean, fetch)


def lookup_ipqualityscore(raw, key):
    clean, early = _prepare(raw, key, "ipqualityscore")
    if early:
        return early

    def fetch():
        form = urlencode({"url": clean, "strictness": 0, "fast": "true", "timeout": 3}).encode()
        request = Request(
            "https://ipqualityscore.com/api/json/url",
            data=form,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "IPQS-KEY": key,
                "User-Agent": USER_AGENT,
            },
        )
        with urlopen(request, timeout=4) as response:
            payload = json.load(response)
        if payload.get("success") is False:
            return source_result("ipqualityscore", "error"), 300
        result = source_result(
            "ipqualityscore",
            "found",
            risk_score=max(0, min(int(payload.get("risk_score", 0)), 100)),
            unsafe=_truthy(payload.get("unsafe")),
            suspicious=_truthy(payload.get("suspicious")),
            phishing=_truthy(payload.get("phishing")),
            malware=_truthy(payload.get("malware")),
            domain_trust=str(payload.get("domain_trust", "not rated"))[:32],
        )
        return result, 1800

    return _cached_lookup("ipqualityscore", clean, fetch)


def lookup_all(raw, environ):
    """Consulta todas las fuentes en paralelo y conserva nombres estables."""
    jobs = {
        "reputation": (lookup_virustotal, environ.get("VT_API_KEY")),
        "google_safe_browsing": (
            lookup_google_safe_browsing,
            environ.get("GOOGLE_SAFE_BROWSING_API_KEY"),
        ),
        "phishtank": (lookup_phishtank, environ.get("PHISHTANK_API_KEY")),
        "ipqualityscore": (lookup_ipqualityscore, environ.get("IPQS_API_KEY")),
    }
    with ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix="escudo-source") as executor:
        futures = {
            name: executor.submit(function, raw, key)
            for name, (function, key) in jobs.items()
        }
        return {name: future.result() for name, future in futures.items()}


def reset_runtime_state():
    """Limpia cache y contadores; se usa unicamente en pruebas automatizadas."""
    with LOCK:
        CACHE.clear()
        INFLIGHT.clear()
        REQUEST_TIMES.clear()
        DAILY.clear()
