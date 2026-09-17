"""Entrenar con CSV url,label (0 legítimo; 1 phishing), sin dependencias externas."""
import csv
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit
from model import FEATURES, features, probability

ROOT = Path(__file__).resolve().parent
if len(sys.argv) != 2:
    raise SystemExit("Uso: python backend/train.py dataset/urls.csv (columnas url,label)")

def load_rows(path, encoding):
    rows = []
    seen = set()
    with open(path, newline="", encoding=encoding) as file:
        first_line = file.readline()
        file.seek(0)
        delimiter = ";" if first_line.count(";") > first_line.count(",") else ","
        reader = csv.DictReader(file, delimiter=delimiter)
        if reader.fieldnames is None:
            raise SystemExit("El CSV está vacío.")
        reader.fieldnames = [name.strip().lower() for name in reader.fieldnames]
        if not {"url", "label"} <= set(reader.fieldnames):
            raise SystemExit("El CSV debe tener columnas url,label. Comprueba también si está separado por comas o punto y coma.")
        for row in reader:
            raw = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip()
            if raw in seen or label not in {"0", "1"}: continue
            try:
                u = urlsplit(raw)
                if u.scheme not in {"http", "https"} or not u.hostname: continue
            except ValueError: continue
            seen.add(raw)
            rows.append((raw, int(label), u.hostname.lower()))
    return rows

for encoding in ("utf-8-sig", "cp1252", "latin-1"):
    try:
        rows = load_rows(sys.argv[1], encoding)
        print(f"CSV leído con codificación {encoding}: {len(rows)} URLs válidas.")
        break
    except UnicodeDecodeError:
        continue
if len(rows) < 40 or len({y for _, y, _ in rows}) < 2:
    raise SystemExit("Se necesitan al menos 40 URLs válidas y ambas clases.")

# Separamos por hostname para no evaluar el mismo dominio visto en entrenamiento.
groups = defaultdict(list)
for row in rows: groups[row[2]].append(row)
hosts = list(groups)
random.Random(42).shuffle(hosts)
test_hosts = set(hosts[:max(1, round(len(hosts) * .2))])
train = [r for r in rows if r[2] not in test_hosts]
test = [r for r in rows if r[2] in test_hosts]
if not test or {y for _, y, _ in train} != {0, 1} or {y for _, y, _ in test} != {0, 1}:
    raise SystemExit("El conjunto por dominio no contiene ambas clases en entrenamiento y prueba; agrega más dominios variados.")

xs = [features(url) for url, _, _ in train]
means = [sum(x[i] for x in xs) / len(xs) for i in range(len(FEATURES))]
stds = [max(.001, (sum((x[i] - means[i]) ** 2 for x in xs) / len(xs)) ** .5) for i in range(len(FEATURES))]
weights = [0.0] * len(FEATURES)
bias = 0.0
rng = random.Random(42)
for epoch in range(150):
    order = list(range(len(train)))
    rng.shuffle(order)
    rate = .04 / (1 + epoch / 80)
    for j in order:
        x = [(v - m) / s for v, m, s in zip(xs[j], means, stds)]
        y = train[j][1]
        z = max(-30, min(30, bias + sum(w * v for w, v in zip(weights, x))))
        error = (1 / (1 + math.exp(-z))) - y
        weights = [w - rate * (error * v + .001 * w) for w, v in zip(weights, x)]
        bias -= rate * error
model = {"features": FEATURES, "weights": weights, "bias": bias, "means": means, "stds": stds}
counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
for raw, label, _ in test:
    pred = int(probability(raw, model) >= .5)
    counts["tp" if pred and label else "fp" if pred else "fn" if label else "tn"] += 1
tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
precision = tp / (tp + fp) if tp + fp else 0
recall = tp / (tp + fn) if tp + fn else 0
report = {"train_count": len(train), "test_count": len(test), "test_domain_count": len(test_hosts),
          **counts, "precision": precision, "recall": recall,
          "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0}
(ROOT / "model.json").write_text(json.dumps(model, indent=2), encoding="utf-8")
(ROOT / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
