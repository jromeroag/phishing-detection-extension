import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs


BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

import threat_sources  # noqa: E402


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def response(payload):
    return FakeResponse(json.dumps(payload).encode("utf-8"))


class ThreatSourceTests(unittest.TestCase):
    def setUp(self):
        threat_sources.reset_runtime_state()

    def test_missing_keys_are_explicit(self):
        results = threat_sources.lookup_all("https://example.com/path?token=secret#part", {})
        self.assertEqual(results["reputation"]["status"], "not_configured")
        self.assertEqual(results["google_safe_browsing"]["status"], "not_configured")
        self.assertEqual(results["phishtank"]["status"], "not_configured")
        self.assertEqual(results["ipqualityscore"]["status"], "not_configured")
        self.assertNotIn("token", str(results))

    def test_private_url_is_never_sent_to_providers(self):
        with patch.object(threat_sources, "urlopen") as mocked:
            result = threat_sources.lookup_google_safe_browsing(
                "http://127.0.0.1:8000/private?token=secret", "key"
            )
        self.assertEqual(result["status"], "not_applicable")
        mocked.assert_not_called()

    def test_google_safe_browsing_match_and_privacy(self):
        captured = {}

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            self.assertEqual(timeout, 4)
            return response({
                "threats": [{"url": "https://example.com/path", "threatTypes": ["SOCIAL_ENGINEERING"]}],
                "cacheDuration": "300s",
            })

        with patch.object(threat_sources, "urlopen", fake_open):
            result = threat_sources.lookup_google_safe_browsing(
                "https://user:pass@example.com/path?token=secret#part", "google-key"
            )
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["threat_types"], ["SOCIAL_ENGINEERING"])
        self.assertNotIn("token", captured["url"])
        self.assertNotIn("user", captured["url"])
        self.assertNotIn("google-key", str(result))

    def test_phishtank_verified_match(self):
        captured = {}

        def fake_open(request, timeout):
            captured["form"] = parse_qs(request.data.decode())
            captured["agent"] = request.get_header("User-agent")
            return response({"results": {
                "in_database": True, "verified": "y", "valid": "y", "phish_id": 42
            }})

        with patch.object(threat_sources, "urlopen", fake_open):
            result = threat_sources.lookup_phishtank(
                "https://example.com/login?session=secret", "pt-key"
            )
        self.assertEqual(result["status"], "found")
        self.assertTrue(result["verified"])
        self.assertTrue(result["valid"])
        self.assertEqual(captured["form"]["url"], ["https://example.com/login"])
        self.assertIn("EscudoTransparente", captured["agent"])

    def test_ipqualityscore_high_risk_response(self):
        captured = {}

        def fake_open(request, timeout):
            captured["form"] = parse_qs(request.data.decode())
            captured["key"] = request.get_header("Ipqs-key")
            return response({
                "success": True, "risk_score": 92, "unsafe": True,
                "suspicious": True, "phishing": True, "malware": False,
                "domain_trust": "malicious",
            })

        with patch.object(threat_sources, "urlopen", fake_open):
            result = threat_sources.lookup_ipqualityscore(
                "https://example.com/login?session=secret", "ipqs-key"
            )
        self.assertEqual(result["status"], "found")
        self.assertEqual(result["risk_score"], 92)
        self.assertTrue(result["phishing"])
        self.assertEqual(captured["key"], "ipqs-key")
        self.assertEqual(captured["form"]["url"], ["https://example.com/login"])
        self.assertNotIn("ipqs-key", str(result))


if __name__ == "__main__":
    unittest.main()
