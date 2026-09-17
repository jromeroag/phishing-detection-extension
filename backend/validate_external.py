"""Evalúa un modelo existente con URLs etiquetadas externas; no visita las páginas.

Uso: python backend/validate_external.py dataset/validacion.csv [dataset/urls.csv]
Columnas: url,label o domain,label (0 legítima; 1 phishing).
El segundo CSV opcional detecta dominios repetidos respecto al entrenamiento.
"""
import csv
import json
import sys
from collections import Counter
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlsplit

from model import probability


def csv_rows(path):
    for encoding in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            with path.open(encoding=encoding, newline="") as handle:
                sample = handle.read(8192)
                handle.seek(0)
                reader = csv.DictReader(handle, dialect=csv.Sniffer().sniff(sample, delimiters=",;\t"))
                reader.fieldnames = [field.strip().lower() for field in reader.fieldnames or ()]
                column = "url" if "url" in reader.fieldnames else "domain"
                if column not in reader.fieldnames or "label" not in reader.fieldnames:
                    raise ValueError("Se requieren url,label o domain,label")
                return list(reader), column, encoding
        except UnicodeDecodeError:
            continue
    raise ValueError("No se pudo leer la codificación del CSV")


def entries(path):
    rows, column, encoding = csv_rows(path)
    seen = set()
    valid = []
    omitted = Counter()
    assumed_https = 0
    for row in rows:
        raw = (row.get(column) or "").strip()
        label = (row.get("label") or "").strip()
        try:
            number = Decimal(label)
            if number not in (0, 1): raise ValueError()
            label = int(number)
        except (InvalidOperation, ValueError):
            omitted["etiqueta inválida"] += 1
            continue
        if not raw or (column == "domain" and "://" not in raw):
            if not raw:
                omitted["URL vacía"] += 1
                continue
            raw = "https://" + raw
            assumed_https += 1
        try:
            parsed = urlsplit(raw)
            if parsed.scheme not in ("http", "https") or not parsed.hostname: raise ValueError()
            # La clase de una URL contradictoria no se puede evaluar con fiabilidad.
            url_key = raw.lower()
            if url_key in seen:
                omitted["URL repetida"] += 1
                continue
            seen.add(url_key)
            valid.append((raw, label, parsed.hostname.lower()))
        except ValueError:
            omitted["URL inválida"] += 1
    return valid, dict(omitted), assumed_https, encoding


def evaluate(validation_path, training_path=None, model_path=None):
    model_path = model_path or Path(__file__).with_name("model.json")
    model = json.loads(model_path.read_text(encoding="utf-8"))
    validation, omitted, assumed, encoding = entries(validation_path)
    if not validation: raise ValueError("No hay URL válidas para evaluar")
    training_hosts = {host for _, _, host in entries(training_path)[0]} if training_path else set()
    overlap = sum(host in training_hosts for _, _, host in validation)
    if overlap:
        print(f"AVISO: {overlap} URLs comparten dominio con el CSV de entrenamiento; sepáralas antes de citar resultados externos.", file=sys.stderr)
    counts = Counter(label for _, label, _ in validation)
    thresholds = {}
    probabilities = []
    examples = []
    for raw, label, host in validation:
        score = probability(raw, model)
        probabilities.append((score, label, host in training_hosts))
        if label == 0 and score >= .8: examples.append({"url": raw, "model_score": round(score, 4),
            "shared_training_domain": host in training_hosts})
    independent = [(s, y) for s, y, shared in probabilities if not shared]
    independent_counts = Counter(y for _, y in independent)
    independent_thresholds = {}
    for threshold in (.4, .5, .8):
        for values, totals, destination in (([(s, y) for s, y, _ in probabilities], counts, thresholds),
                                            (independent, independent_counts, independent_thresholds)):
            tp = sum(score >= threshold and label == 1 for score, label in values)
            fp = sum(score >= threshold and label == 0 for score, label in values)
            fn, tn = totals[1] - tp, totals[0] - fp
            precision = tp / (tp + fp) if tp + fp else None
            recall = tp / totals[1] if totals[1] else None
            destination[str(threshold)] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "false_positive_rate": fp / totals[0] if totals[0] else None,
                "precision": precision, "recall": recall}
    buckets = []
    for start in range(0, 10, 2):
        values = [(s, y) for s, y, _ in probabilities if start / 10 <= s < (start + 2) / 10 or (start == 8 and s == 1)]
        buckets.append({"range": f"{start / 10:.1f}-{(start + 2) / 10:.1f}", "count": len(values),
            "mean_output": sum(s for s, _ in values) / len(values) if values else None,
            "observed_phishing_rate": sum(y for _, y in values) / len(values) if values else None})
    report = {"source": str(validation_path), "encoding": encoding,
        "valid": len(validation), "legitimate": counts[0], "phishing": counts[1],
        "skipped": omitted, "assumed_https": assumed, "training_domain_overlap": overlap,
        "independent": {"valid": len(independent), "legitimate": independent_counts[0],
            "phishing": independent_counts[1], "thresholds": independent_thresholds},
        "thresholds": thresholds, "calibration_buckets": buckets,
        "brier_score": sum((s - y) ** 2 for s, y, _ in probabilities) / len(probabilities),
        "legitimate_examples_score_ge_0_8": sorted(examples, key=lambda item: -item["model_score"])[:10]}
    return report


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit("Uso: python backend/validate_external.py dataset/validacion.csv [dataset/urls.csv]")
    try:
        print(json.dumps(evaluate(Path(sys.argv[1]), Path(sys.argv[2]) if len(sys.argv) == 3 else None), indent=2, ensure_ascii=False))
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit("Error: " + str(exc)) from exc
