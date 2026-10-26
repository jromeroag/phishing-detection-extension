import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.configure_extension import normalize_api_url  # noqa: E402


class CloudConfigurationTests(unittest.TestCase):
    def test_accepts_cloud_run_https_origin(self):
        self.assertEqual(
            normalize_api_url("https://escudo-api-abc.run.app/"),
            "https://escudo-api-abc.run.app",
        )

    def test_accepts_local_development_origin(self):
        self.assertEqual(
            normalize_api_url("http://127.0.0.1:8765"),
            "http://127.0.0.1:8765",
        )

    def test_rejects_remote_http_origin(self):
        with self.assertRaises(ValueError):
            normalize_api_url("http://escudo-api.example.com")

    def test_rejects_analyze_path(self):
        with self.assertRaises(ValueError):
            normalize_api_url("https://escudo-api-abc.run.app/analyze")


if __name__ == "__main__":
    unittest.main()
