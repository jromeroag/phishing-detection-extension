"""Comprueba lectura externa sin dataset ni modelo privados."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from evaluate_phishstorm import evaluate  # noqa: E402
from validate_external import evaluate as validate_external  # noqa: E402
from model import LEGACY_FEATURES, FEATURES, probability  # noqa: E402


class EvaluationTest(unittest.TestCase):
    def test_old_model_and_decimal_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            model = folder / "model.json"
            model.write_text(json.dumps({
                "features": LEGACY_FEATURES, "bias": 0,
                "weights": [0] * 10, "means": [0] * 10, "stds": [1] * 10,
            }))
            csv = folder / "urlset.csv"
            csv.write_bytes("domain,label,ranking\nexample.com,0.0,1\n"
                            "https://test.example/,1.0,2\n".encode("cp1252"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                evaluate(csv, model)
            self.assertIn("Filas evaluadas: 2", output.getvalue())
            self.assertIn("falsos positivos 1/1", output.getvalue())
            self.assertIn("supuso HTTPS: 1", output.getvalue())
            self.assertEqual(probability("https://example.com/", json.loads(model.read_text())), .5)
            self.assertEqual(len(FEATURES), 15)

    def test_external_report_counts_and_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            model = folder / "model.json"
            model.write_text(json.dumps({"features": LEGACY_FEATURES, "bias": 0,
                "weights": [0] * 10, "means": [0] * 10, "stds": [1] * 10}))
            training = folder / "training.csv"
            training.write_text("url,label\nhttps://example.com/,0\n")
            validation = folder / "external.csv"
            validation.write_text("domain;label\nexample.com/test;0.0\nphishing.example.net;1.0\n")
            report = validate_external(validation, training, model)
            self.assertEqual(report["valid"], 2)
            self.assertEqual(report["training_domain_overlap"], 1)
            self.assertEqual(report["assumed_https"], 2)
            self.assertEqual(report["thresholds"]["0.5"]["tp"], 1)
            self.assertEqual(report["thresholds"]["0.5"]["fp"], 1)
            self.assertEqual(report["independent"]["valid"], 1)
            self.assertEqual(report["independent"]["thresholds"]["0.5"]["fp"], 0)


if __name__ == "__main__":
    unittest.main()
