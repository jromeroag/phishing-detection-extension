"""Evalúa un model.json existente con PhishStorm sin entrenar ni visitar enlaces.

Uso: python backend/evaluate_phishstorm.py dataset/urlset.csv
PhishStorm: domain = URL, label = 0 legítima / 1 phishing.
"""
import csv
import json
import sys
from collections import Counter
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlsplit

from model import probability


def read_rows(path):
    for encoding in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            with path.open("r", encoding=encoding, newline="") as handle:
                sample = handle.read(8192)
                handle.seek(0)
                delimiter = ";" if sample.splitlines()[0].count(";") > sample.splitlines()[0].count(",") else ","
                reader = csv.DictReader(handle, delimiter=delimiter)
                if reader.fieldnames is None:
                    raise ValueError("CSV vacío")
                reader.fieldnames = [field.strip().lower() for field in reader.fieldnames]
                if not {"domain", "label"}.issubset(reader.fieldnames):
                    raise ValueError("Se esperan las columnas domain y label de PhishStorm")
                return list(reader), encoding
        except UnicodeDecodeError:
            continue
    raise ValueError("No se pudo leer el CSV")


def evaluate(csv_path, model_path):
    model = json.loads(model_path.read_text(encoding="utf-8"))
    rows, encoding = read_rows(csv_path)
    counts = {"0": 0, "1": 0}
    positives = {threshold: {"fp": 0, "tp": 0} for threshold in (.4, .5, .8)}
    false_positives = []
    skipped = assumed_https = 0
    skip_reasons = Counter()
    raw_labels = Counter()
    for row in rows:
        raw = (row.get("domain") or "").strip()
        original_label = (row.get("label") or "").strip()
        raw_labels[original_label] += 1
        # Algunas exportaciones guardan etiquetas numéricas como 0.0 y 1.0.
        try:
            value = Decimal(original_label)
            label = str(int(value)) if value in (0, 1) else "?"
        except InvalidOperation:
            label = "?"
        if not raw or label not in counts:
            skipped += 1
            skip_reasons["etiqueta desconocida" if label not in counts else "URL vacía"] += 1
            continue
        if "://" not in raw:
            raw = "https://" + raw
            assumed_https += 1
        try:
            parsed = urlsplit(raw)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                skipped += 1
                skip_reasons["URL inválida"] += 1
                continue
            p = probability(raw, model)
        except (ValueError, TypeError, KeyError):
            skipped += 1
            skip_reasons["URL o modelo inválido"] += 1
            continue
        counts[label] += 1
        for threshold, result in positives.items():
            if p >= threshold:
                result["fp" if label == "0" else "tp"] += 1
        if label == "0" and p >= .8:
            false_positives.append((p, raw))

    print("Modelo:", model_path)
    print("CSV:", csv_path, "(codificación", encoding + ")")
    print("Filas evaluadas:", sum(counts.values()), "| legítimas:", counts["0"], "| phishing:", counts["1"])
    print("Filas omitidas:", skipped, "| URLs sin esquema a las que se supuso HTTPS:", assumed_https)
    if skipped:
        print("Motivos de omisión:", dict(skip_reasons))
    if not all(counts.values()):
        print("Valores de label encontrados:", raw_labels.most_common(8))
        raise ValueError("No hay URLs válidas de ambas clases; revisa las etiquetas anteriores")
    for threshold, result in positives.items():
        fp, tp = result["fp"], result["tp"]
        print(f"Umbral {threshold:.1f}: falsos positivos {fp}/{counts['0']} ({fp/counts['0']:.1%}); "
              f"phishing detectado {tp}/{counts['1']} ({tp/counts['1']:.1%})")
    print("Ejemplos legítimos con puntuación del modelo >= 0.8:")
    for p, url in sorted(false_positives, reverse=True)[:10]:
        print(f"  {p:.1%}  {url[:140]}")
    print("Nota: esta prueba mide solo el modelo, no el semáforo ni VirusTotal. "
          "PhishStorm se publicó en 2014; compara después con URLs actuales.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Uso: python backend/evaluate_phishstorm.py dataset/urlset.csv")
    try:
        evaluate(Path(sys.argv[1]), Path(__file__).with_name("model.json"))
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit("Error: " + str(exc)) from exc
