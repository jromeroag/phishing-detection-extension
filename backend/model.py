"""Funciones compartidas de extracción y predicción. No descarga ni visita URLs."""
import math
from urllib.parse import urlsplit

LEGACY_FEATURES = ("length", "dots", "hyphens", "digits", "at", "punycode", "ip", "path_length", "query_length", "http")
FEATURES = LEGACY_FEATURES + ("host_length", "subdomains", "path_digits", "path_segments", "query_keys")


def features(raw):
    u = urlsplit(raw)
    host = (u.hostname or "").lower()
    values = [
        min(len(raw), 500), min(host.count("."), 20), min(host.count("-"), 20),
        min(sum(c.isdigit() for c in host), 50), int(bool(u.username)),
        int("xn--" in host), int(host.replace(".", "").isdigit()),
        min(len(u.path), 300), min(len(u.query), 300), int(u.scheme == "http")
    ]
    values.extend((
        min(len(host), 200), min(max(0, host.count(".") - 1), 15),
        min(sum(c.isdigit() for c in u.path), 50),
        min(len([segment for segment in u.path.split("/") if segment]), 30),
        min(len([item for item in u.query.split("&") if item]), 30),
    ))
    return values


def probability(raw, model):
    names = model.get("features", LEGACY_FEATURES)
    values = dict(zip(FEATURES, features(raw)))
    if not (len(names) == len(model["weights"]) == len(model["means"]) == len(model["stds"])):
        raise ValueError("El archivo del modelo tiene dimensiones incompatibles")
    vals = [values[name] for name in names]
    linear = model["bias"] + sum(w * (x - mean) / std for w, x, mean, std in zip(
        model["weights"], vals, model["means"], model["stds"]))
    return 1 / (1 + math.exp(-max(-30, min(30, linear))))
