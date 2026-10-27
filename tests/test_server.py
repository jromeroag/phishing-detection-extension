import sys
import unittest
from unittest.mock import patch
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from server import origin_allowed, reputation, runtime_address  # noqa: E402


class ServerEvidenceTests(unittest.TestCase):
    def test_reputation_without_key_is_explicit_and_traceable(self):
        result = reputation("https://example.com/private?token=secret#section", None)
        self.assertEqual(result["status"], "not_configured")
        self.assertEqual(result["source"], "virustotal")
        self.assertEqual(result["scope"], "scheme_host_port_path")
        self.assertFalse(result["query_parameters_shared"])
        self.assertNotIn("token", str(result))

    def test_all_source_configuration_flags_are_exposed_by_health_contract(self):
        expected = {
            "VT_API_KEY", "GOOGLE_SAFE_BROWSING_API_KEY",
            "PHISHTANK_API_KEY", "IPQS_API_KEY"
        }
        server_text = (BACKEND / "server.py").read_text(encoding="utf-8")
        self.assertTrue(all(name in server_text for name in expected))

    def test_cloud_run_uses_injected_host_and_port(self):
        with patch.dict("os.environ", {"K_SERVICE": "escudo", "PORT": "8080"}, clear=True):
            self.assertEqual(runtime_address(), ("0.0.0.0", 8080))

    def test_local_mode_keeps_original_address(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(runtime_address(), ("127.0.0.1", 8765))

    def test_exact_extension_origin_can_be_required(self):
        allowed = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
        with patch.dict("os.environ", {"ALLOWED_EXTENSION_ORIGINS": allowed}, clear=True):
            self.assertTrue(origin_allowed(allowed))
            self.assertFalse(origin_allowed("chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba"))


if __name__ == "__main__":
    unittest.main()
