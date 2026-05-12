from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from .models import IOCRecord
from .services.reporting import generate_pdf_report
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

    def test_ip_enrichment_uses_distinct_asn_and_country_labels(self):
        private_result = triage_indicator({
            "indicator": "10.42.14.64",
            "type": "ip",
            "source": "Network IDS",
            "date_found": "2026-05-03",
        })
        public_result = triage_indicator({
            "indicator": "8.8.8.8",
            "type": "ip",
            "source": "SIEM alert",
            "date_found": "2026-05-03",
        })

        self.assertEqual(private_result.asn, "Not applicable - private IP")
        self.assertEqual(private_result.country, "Private/internal network")
        self.assertNotEqual(private_result.asn, private_result.country)
        self.assertEqual(public_result.asn, "External ASN lookup not configured")
        self.assertEqual(public_result.country, "External GeoIP lookup not configured")
        self.assertNotEqual(public_result.asn, public_result.country)

class UploadWorkflowTests(TestCase):
    def test_multiple_csv_files_upload_in_one_batch(self):
        files = [
            SimpleUploadedFile(
                "one.csv",
                b"indicator,type,source,date_found\nsecure-login-update-example.com,domain,Email,2026-05-01\n",
                content_type="text/csv",
            ),
            SimpleUploadedFile(
                "two.csv",
                b"indicator,type,source,date_found\nhttp://198.51.100.10/login/update.exe,url,Proxy,2026-05-02\n",
                content_type="text/csv",
            ),
        ]

        response = self.client.post(reverse("home"), {"csv_files": files}, follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(IOCRecord.objects.count(), 2)
        self.assertContains(response, "Processed 2 IOC record(s) from 2 CSV file(s).")

    def test_invalid_csv_format_prompts_user_to_select_another_file(self):
        invalid_file = SimpleUploadedFile(
            "bad.csv",
            b"value,kind\nnot-good,unknown\n",
            content_type="text/csv",
        )

        response = self.client.post(reverse("home"), {"csv_files": [invalid_file]}, follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(IOCRecord.objects.count(), 0)
        self.assertContains(
            response,
            "Invalid CSV format. Required columns: indicator, type, source, date_found. Please select another file.",
        )

    def test_results_table_omits_country_column_for_low_confidence_ip_records(self):
        IOCRecord.objects.create(
            indicator="10.42.14.64",
            submitted_type="ip",
            detected_type="ip",
            source="Network IDS",
            date_found="2026-05-03",
            is_valid=True,
            validation_notes="Valid IOC detected.",
            reputation="Benign",
            reputation_notes="Private/internal IP address; treat as local context unless seen in suspicious logs.",
            asn="Internal/private address",
            country="Internal/private address",
            mitre_tactic="Unmapped",
            mitre_technique="Not enough evidence",
            confidence_level="Low",
            confidence_reason="Valid IOC, but reputation is unknown or evidence is limited.",
        )

        response = self.client.get(reverse("results") + "?detected_type=&confidence=Low")
        content = response.content.decode()

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Not applicable - private IP")
        self.assertNotContains(response, "<th>Country</th>", html=True)
        self.assertNotIn("Private/internal network", content)
        self.assertEqual(content.count("Internal/private address"), 0)

class ReportDownloadTests(TestCase):
    def test_pdf_report_download_returns_pdf_without_error_message(self):
        IOCRecord.objects.create(
            indicator="secure-login-update-example.com",
            submitted_type="domain",
            detected_type="domain",
            source="Email gateway",
            date_found="2026-05-01",
            is_valid=True,
            validation_notes="Valid IOC detected.",
            reputation="Suspicious",
            reputation_notes="Domain requires passive WHOIS/reputation verification.",
            mitre_tactic="Initial Access",
            mitre_technique="Phishing: Spearphishing Link / T1566.002",
            mitre_notes="Suspicious terms are consistent with a possible phishing lure.",
            confidence_level="High",
            confidence_reason="Valid IOC with multiple suspicious signals.",
        )

        response = self.client.get(reverse("report") + "?download=pdf")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF"))
        self.assertNotIn(b"PDF export requires ReportLab", response.content)

    def test_pdf_generation_has_builtin_fallback_when_reportlab_is_missing(self):
        records = IOCRecord.objects.none()

        with patch("ioc_triage.services.reporting.importlib.util.find_spec", return_value=None):
            pdf_bytes = generate_pdf_report(records)

        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertIn(b"%%EOF", pdf_bytes)
