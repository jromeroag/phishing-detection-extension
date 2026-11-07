"""Valida los CSV indicados por la línea de comandos de las herramientas."""

import re
from pathlib import Path


DATASET_DIR = Path(__file__).resolve().parents[1] / "dataset"
DATASET_CSV = re.compile(r"dataset[/\\]([^/\\:\x00]+\.csv)")


def resolve_dataset_csv(raw_path):
    """Devuelve un CSV regular contenido en dataset, sin escapes por symlink."""
    if not isinstance(raw_path, str) or ".." in raw_path:
        raise ValueError("Se requiere una ruta dataset/nombre.csv")
    match = DATASET_CSV.fullmatch(raw_path)
    if match is None:
        raise ValueError("Se requiere una ruta dataset/nombre.csv")

    dataset_dir = DATASET_DIR.resolve(strict=True)
    candidate = (dataset_dir / match.group(1)).resolve(strict=True)
    if not candidate.is_relative_to(dataset_dir) or not candidate.is_file():
        raise ValueError("El CSV debe ser un archivo regular dentro de dataset")
    return candidate
