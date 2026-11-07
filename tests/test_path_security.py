"""Los CSV recibidos por CLI deben permanecer dentro de dataset."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
import path_security  # noqa: E402


class DatasetPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.dataset = self.root / "dataset"
        self.dataset.mkdir()
        self.csv = self.dataset / "nombre.csv"
        self.csv.write_text("url,label\n", encoding="utf-8")
        dataset_patch = patch.object(path_security, "DATASET_DIR", self.dataset)
        dataset_patch.start()
        self.addCleanup(dataset_patch.stop)

    def test_accepts_both_separators(self):
        self.assertEqual(path_security.resolve_dataset_csv("dataset/nombre.csv"), self.csv.resolve())
        self.assertEqual(path_security.resolve_dataset_csv(r"dataset\nombre.csv"), self.csv.resolve())

    def test_rejects_untrusted_paths(self):
        rejected = (
            "nombre.csv", "./dataset/nombre.csv", "/dataset/nombre.csv",
            r"C:\dataset\nombre.csv", r"\\server\share\dataset\nombre.csv",
            "dataset/../nombre.csv", r"dataset\..\nombre.csv",
            "dataset/sub/nombre.csv", r"dataset\sub\nombre.csv",
            "dataset//nombre.csv", "dataset/nombre.txt", "dataset/nombre.CSV",
            "dataset/..csv", "dataset/nombre.csv/", "dataset/nombre.csv:stream",
        )
        for raw in rejected:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                path_security.resolve_dataset_csv(raw)

    def test_rejects_missing_file_and_directory(self):
        with self.assertRaises(FileNotFoundError):
            path_security.resolve_dataset_csv("dataset/missing.csv")
        (self.dataset / "folder.csv").mkdir()
        with self.assertRaises(ValueError):
            path_security.resolve_dataset_csv("dataset/folder.csv")

    def test_rejects_symlink_outside_dataset(self):
        outside = self.root / "outside.csv"
        outside.write_text("url,label\n", encoding="utf-8")
        link = self.dataset / "link.csv"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"Enlaces simbólicos no disponibles: {exc}")
        with self.assertRaises(ValueError):
            path_security.resolve_dataset_csv("dataset/link.csv")

    def test_all_cli_entry_points_reject_traversal(self):
        commands = (
            ("evaluate_phishstorm.py", "dataset/../bad.csv"),
            ("train.py", "dataset/../bad.csv"),
            ("train_v2.py", "dataset/../bad.csv", "dataset/ejemplo_urls.csv"),
            ("validate_external.py", "dataset/../bad.csv"),
        )
        for script, *arguments in commands:
            with self.subTest(script=script):
                result = subprocess.run(
                    [sys.executable, str(ROOT / "backend" / script), *arguments],
                    cwd=ROOT, capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Se requiere una ruta dataset/nombre.csv", result.stderr)


if __name__ == "__main__":
    unittest.main()
