import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from server import reputation  # noqa: E402


class ServerEvidenceTests(unittest.TestCase):
    def test_reputation_without_key_is_explicit_and_traceable(self):
        result = reputation("https://example.com/private?token=secret#section", None)
        self.assertEqual(result["status"], "not_configured")
        self.assertEqual(result["source"], "virustotal")
        self.assertEqual(result["scope"], "scheme_host_port_path")
        self.assertFalse(result["query_parameters_shared"])
        self.assertNotIn("token", str(result))


if __name__ == "__main__":
    unittest.main()
