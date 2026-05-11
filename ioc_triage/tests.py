from django.test import TestCase

from .services.triage import detect_hash_type, detect_ioc_type, score_confidence, triage_indicator


class TriageServiceTests(TestCase):
    def test_ip_detection_supports_ipv4_and_ipv6(self):
        self.assertEqual(detect_ioc_type("185.199.108.153"), "ip")
        self.assertEqual(detect_ioc_type("2001:db8::1"), "ip")

    def test_domain_detection_excludes_ips_and_urls(self):
        self.assertEqual(detect_ioc_type("secure-login-update-example.com"), "domain")
        self.assertNotEqual(detect_ioc_type("https://example.com/login"), "domain")

    def test_url_detection_requires_scheme_and_netloc(self):
        self.assertEqual(detect_ioc_type("http://45.77.12.10/login/update.exe"), "url")
        self.assertEqual(detect_ioc_type("example.com/path"), "unknown")

    def test_hash_detection_for_common_hash_lengths(self):
        self.assertEqual(detect_ioc_type("44d88612fea8a8f36de82e1278abb02f"), "hash")
        self.assertEqual(detect_hash_type("a" * 40), "SHA1")
        self.assertEqual(detect_hash_type("a" * 64), "SHA256")

    def test_invalid_ioc_handling(self):
        result = triage_indicator({"indicator": "not a valid ioc", "type": "domain", "source": "test", "date_found": "2026-05-01"})
        self.assertFalse(result.is_valid)
        self.assertEqual(result.detected_type, "unknown")
        self.assertEqual(result.confidence_level, "Low")

    def test_confidence_scoring(self):
        self.assertEqual(score_confidence(True, "Malicious", ["one", "two"])[0], "High")
        self.assertEqual(score_confidence(True, "Suspicious", ["one"])[0], "Medium")
        self.assertEqual(score_confidence(False, "Unknown", [])[0], "Low")

    def test_mitre_mapping_for_phishing_domain(self):
        result = triage_indicator({"indicator": "secure-login-update-example.com", "type": "domain", "source": "email", "date_found": "2026-05-01"})
        self.assertEqual(result.mitre_tactic, "Initial Access")
        self.assertIn("T1566.002", result.mitre_technique)
