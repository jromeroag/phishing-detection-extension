"""Entrena un candidato sin sobrescribir model.json; exige scikit-learn y numpy.

python backend/train_v2.py dataset/urls.csv dataset/validacion_nueva.csv
La segunda base reserva por hostname un 20 % para prueba. Los hostnames que
aparecen en la primera base nunca forman parte de esa prueba.
"""
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

try:
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
except ImportError as exc:
    raise SystemExit("Instala dependencias para entrenar: python -m pip install numpy scikit-learn") from exc

from model import FEATURES, features

# La primera fuente tiene 0 páginas legítimas HTTP; usar "http" como rasgo
# aprende el origen de los datos y provoca alarmas en páginas institucionales.
MODEL_FEATURES = tuple(name for name in FEATURES if name != "http")
SELECTED = [FEATURES.index(name) for name in MODEL_FEATURES]


def url_features(raw):
    values = features(raw)
    return [values[index] for index in SELECTED]


def rows(path):
    for encoding in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            with path.open(encoding=encoding, newline="") as handle:
                sample = handle.read(8192)
                handle.seek(0)
                delimiter = ";" if sample.splitlines()[0].count(";") > sample.splitlines()[0].count(",") else ","
                reader = csv.DictReader(handle, delimiter=delimiter)
                reader.fieldnames = [field.strip().lower() for field in reader.fieldnames or ()]
                if not {"url", "label"} <= set(reader.fieldnames):
                    raise ValueError(f"{path}: faltan columnas url,label")
                result = []
                seen = set()
                for row in reader:
                    raw = (row.get("url") or "").strip()
                    label = (row.get("label") or "").strip()
                    if label not in ("0", "1") or not raw or raw in seen: continue
                    try:
                        parsed = urlsplit(raw)
                        if parsed.scheme not in ("http", "https") or not parsed.hostname: continue
                    except ValueError: continue
                    seen.add(raw)
                    result.append((raw, int(label), parsed.hostname.lower(), parsed.scheme))
                return result
        except UnicodeDecodeError:
            continue
    raise ValueError(f"{path}: codificación no reconocida")


def holdout(host):
    return int.from_bytes(hashlib.sha256(host.encode()).digest()[:4], "big") % 5 == 0


def scores(labels, predictions, threshold):
    tp = int(np.sum((predictions >= threshold) & (labels == 1)))
    fp = int(np.sum((predictions >= threshold) & (labels == 0)))
    tn = int(np.sum((predictions < threshold) & (labels == 0)))
    fn = int(np.sum((predictions < threshold) & (labels == 1)))
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "precision": tp / (tp + fp) if tp + fp else None}


def train(original_path, new_path):
    original = rows(original_path)
    source_hosts = {host for _, _, host, _ in original}
    extra = rows(new_path)
    new_train = [row for row in extra if row[2] in source_hosts or not holdout(row[2])]
    new_test = [row for row in extra if row[2] not in source_hosts and holdout(row[2])]
    if not new_test or {label for _, label, _, _ in new_test} != {0, 1}:
        raise ValueError("La muestra reservada debe contener ambas clases")
    # Evita contar una URL idéntica dos veces al combinar fuentes.
    prior_urls = {raw for raw, _, _, _ in original}
    new_train = [row for row in new_train if row[0] not in prior_urls]
    training = original + new_train
    if {label for _, label, _, _ in training} != {0, 1}:
        raise ValueError("El entrenamiento debe contener ambas clases")
    x_train = np.asarray([url_features(raw) for raw, _, _, _ in training], dtype=np.float64)
    y_train = np.asarray([label for _, label, _, _ in training], dtype=np.int8)
    scaler = StandardScaler().fit(x_train)
    classifier = LogisticRegression(C=0.1, class_weight="balanced", max_iter=300).fit(scaler.transform(x_train), y_train)
    x_test = np.asarray([url_features(raw) for raw, _, _, _ in new_test], dtype=np.float64)
    y_test = np.asarray([label for _, label, _, _ in new_test], dtype=np.int8)
    predicted = classifier.predict_proba(scaler.transform(x_test))[:, 1]
    report = {
        "source_original": str(original_path), "source_additional": str(new_path),
        "train_original_count": len(original), "train_additional_count": len(new_train),
        "test_additional_count": len(new_test),
        "train_classes": dict(Counter(str(y) for y in y_train)),
        "test_classes": dict(Counter(str(y) for y in y_test)),
        "test_hosts": len({host for _, _, host, _ in new_test}),
        "test_shared_hosts_with_training": len({host for _, _, host, _ in new_test} & {host for _, _, host, _ in training}),
        "thresholds": {str(t): scores(y_test, predicted, t) for t in (.4, .5, .8)},
        "by_scheme_at_0_5": {scheme: scores(y_test[[i for i, row in enumerate(new_test) if row[3] == scheme]],
                           predicted[[i for i, row in enumerate(new_test) if row[3] == scheme]], .5)
                           for scheme in ("http", "https")},
        "brier_score": float(np.mean((predicted - y_test) ** 2)),
        "note": "Esta prueba reservada proviene de la segunda fuente; la salida del modelo sigue sin calibrarse para afirmar probabilidades reales."
    }
    if report["test_shared_hosts_with_training"]: raise AssertionError("Fuga de dominios en prueba")
    model = {"features": MODEL_FEATURES, "weights": classifier.coef_[0].tolist(),
             "bias": float(classifier.intercept_[0]), "means": scaler.mean_.tolist(),
             "stds": scaler.scale_.tolist()}
    target = Path(__file__).resolve().parent
    (target / "model_v2.json").write_text(json.dumps(model, indent=2), encoding="utf-8")
    (target / "evaluation_v2.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


if __name__ == "__main__":
    if len(sys.argv) != 3: raise SystemExit("Uso: python backend/train_v2.py dataset/urls.csv dataset/validacion_nueva.csv")
    try: print(json.dumps(train(Path(sys.argv[1]), Path(sys.argv[2])), indent=2, ensure_ascii=False))
    except (OSError, ValueError) as exc: raise SystemExit("Error: " + str(exc)) from exc
