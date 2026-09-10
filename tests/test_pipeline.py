import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.evidence_ledger import EvidenceLedger
from engine.geoip_resolver import GeoIPResolver
from engine.parser import EmailParser
from engine.pipeline import ForensicPipeline


ROOT = Path(__file__).resolve().parents[1]


class PipelineTests(unittest.TestCase):
    def sample(self, name):
        return (ROOT / "sample_emails" / name).read_bytes()

    def test_hash_uses_exact_submitted_bytes(self):
        raw = b"\nFrom: sender@example.com\r\nTo: user@example.com\r\n\r\nBody\r\n"
        result = EmailParser(raw).parse()
        self.assertEqual(result["forensic_hash"], hashlib.sha256(raw).hexdigest())

    def test_demo_scenarios_have_expected_risk_order(self):
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            ceo = ForensicPipeline.process_raw_email(self.sample("ceo_bec_fraud.eml"))
            forged = ForensicPipeline.process_raw_email(self.sample("forged_relay_attack.eml"))
            legitimate = ForensicPipeline.process_raw_email(self.sample("legitimate_delivery.eml"))

        self.assertGreaterEqual(ceo["threat_analysis"]["threat_score"], 70)
        self.assertTrue(forged["hops_analysis"]["has_timing_anomalies"])
        self.assertLess(legitimate["threat_analysis"]["threat_score"], 35)
        self.assertEqual(legitimate["authentication"]["overall_status"], "REPORTED_PASS")
        self.assertGreaterEqual(ceo["ml_analysis"]["phishing_probability"], 0.65)

    def test_geoip_failure_is_unavailable_not_simulated(self):
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            result = GeoIPResolver.resolve("8.8.4.4")
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertIsNone(result["latitude"])
        self.assertEqual(result["confidence"], "NONE")

    def test_ioc_graph_is_returned(self):
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            result = ForensicPipeline.process_raw_email(self.sample("ceo_bec_fraud.eml"))
        node_types = {node["type"] for node in result["ioc_graph"]["nodes"]}
        self.assertIn("EMAIL", node_types)
        self.assertIn("IP", node_types)
        self.assertIn("URL_DOMAIN", node_types)

    def test_ledger_records_form_a_hash_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = EvidenceLedger(str(Path(directory) / "ledger.jsonl"))
            first = ledger.append("ANL-ONE", "a" * 64)
            second = ledger.append("ANL-TWO", "b" * 64)
            self.assertEqual(first["previous_record_hash"], "GENESIS")
            self.assertEqual(second["previous_record_hash"], first["record_hash"])

    def test_zero_ssrf_static_url_scanner_flags_threats_without_requests(self):
        from engine.url_scanner import URLScanner
        with patch("requests.get") as mock_get, patch("requests.head") as mock_head:
            test_urls = [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:8080/admin",
                "https://xn--paypl-qqa.com/login",
                "https://legit-site.org/docs"
            ]
            scanned = URLScanner.scan_all(test_urls)
            # Verify NO outbound network requests were made (SSRF immunity)
            mock_get.assert_not_called()
            mock_head.assert_not_called()

            self.assertTrue(scanned[0]["is_internal_or_ssrf"])
            self.assertTrue(scanned[1]["is_internal_or_ssrf"])
            self.assertTrue(scanned[2]["punycode"])
            self.assertFalse(scanned[3]["suspicious"])

    def test_evidence_precedence_suppresses_urgency_false_positives(self):
        raw_email = (
            b"From: \"GitHub Security\" <support@github.com>\r\n"
            b"To: engineer@company.com\r\n"
            b"Subject: Action Required: Personal Access Token Expiring Immediately\r\n"
            b"Date: Thu, 10 Sep 2026 12:00:00 +0000\r\n"
            b"Authentication-Results: mx.company.com;\r\n"
            b" dkim=pass header.i=@github.com header.s=s1;\r\n"
            b" spf=pass smtp.mailfrom=bounces.github.com;\r\n"
            b" dmarc=pass header.from=github.com\r\n"
            b"\r\n"
            b"Urgent action required. Your invoice attached and account verification required immediately.\r\n"
        )
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            report = ForensicPipeline.process_raw_email(raw_email)

        # Authenticated email with urgency words should NOT trigger high risk
        self.assertLess(report["threat_analysis"]["threat_score"], 25)
        self.assertEqual(report["threat_analysis"]["risk_category"], "LOW_OBSERVED_RISK")
        self.assertEqual(report["threat_analysis"]["enforcement_action"], "ALLOW")

    def test_esp_relay_alignment_passes(self):
        raw_email = (
            b"From: \"Stripe Billing\" <invoices@stripe.com>\r\n"
            b"To: finance@startup.io\r\n"
            b"Subject: Monthly Cloud Invoice Paid\r\n"
            b"Return-Path: <bounces@sendgrid.net>\r\n"
            b"Authentication-Results: mx.startup.io;\r\n"
            b" dkim=pass header.i=@stripe.com header.s=st1;\r\n"
            b" spf=pass smtp.mailfrom=bounces@sendgrid.net\r\n"
            b"\r\n"
            b"Here is your monthly invoice receipt for cloud compute services.\r\n"
        )
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            report = ForensicPipeline.process_raw_email(raw_email)

        # ESP relay with SendGrid Return-Path and valid Stripe DKIM alignment must pass DMARC
        self.assertTrue(report["authentication"]["composite_pass"])
        self.assertLess(report["threat_analysis"]["threat_score"], 25)

    def test_unverified_headers_lowers_confidence_not_threat(self):
        raw_email = (
            b"From: colleague@internal.net\r\n"
            b"To: rk@internal.net\r\n"
            b"Subject: Team Lunch Tomorrow\r\n"
            b"\r\n"
            b"Hey RK, let us meet for lunch tomorrow at 12:30.\r\n"
        )
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            report = ForensicPipeline.process_raw_email(raw_email)

        self.assertTrue(report["authentication"]["is_unverified"])
        self.assertLess(report["threat_analysis"]["threat_score"], 35)
        self.assertEqual(report["threat_analysis"]["enforcement_action"], "MONITOR")
        self.assertLessEqual(report["threat_analysis"]["confidence_score"], 65)

    def test_vendor_bank_change_bec_detected(self):
        with open("sample_emails/vendor_bank_change_bec.eml", "rb") as f:
            raw_email = f.read()
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            report = ForensicPipeline.process_raw_email(raw_email)

        # Authenticated vendor with mismatched Reply-To requesting bank change must be flagged
        threat = report["threat_analysis"]
        self.assertGreaterEqual(threat["threat_score"], 60.0)
        self.assertIn("BEC_VENDOR_FINANCIAL_DIVERSION", threat["detections"])
        self.assertIn("REPLY_TO_ORG_MISMATCH", threat["detections"])
        factors = " ".join(f["detail"] for f in threat["explainability_factors"])
        self.assertIn("Out-of-band verification required", factors)

    def test_ui_backend_mappings(self):
        from app import build_ui_compatible_payload
        with open("sample_emails/vendor_bank_change_bec.eml", "rb") as f:
            raw_email = f.read()
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            report = ForensicPipeline.process_raw_email(raw_email)
            ui_payload = build_ui_compatible_payload(report)

        # 1. headers.hops must be integer (not an object/list)
        self.assertIsInstance(ui_payload["headers"]["hops"], int)
        # 2. trace.mx must be a list (never raw string) so .map() succeeds
        self.assertIsInstance(ui_payload["trace"]["mx"], list)
        # 3. trace.geo must contain lat, lon, loc, and org
        geo = ui_payload["trace"]["geo"]
        self.assertIn("lat", geo)
        self.assertIn("lon", geo)
        self.assertIn("loc", geo)
        self.assertIn("org", geo)

    def test_copilot_engine_reasoning(self):
        from engine.copilot_engine import ForensicCopilot
        # 1. Standby mode and greeting
        empty_res = ForensicCopilot.query("")
        self.assertEqual(empty_res["category"], "GREETING")
        standby_res = ForensicCopilot.query("Hello")
        self.assertEqual(standby_res["category"], "STANDBY")

        # 2. Domain & Reply-to reasoning
        sample_report = {
            "fraud_score": 85,
            "risk_level": "CRITICAL",
            "label": "fraud",
            "confidence": 90,
            "headers": {
                "from": "billing@vendor.com",
                "reply_to": "attacker@evil.xyz",
                "origin_ip": "198.98.56.12",
                "spf": True,
                "dkim": True,
                "dmarc": False,
                "reasons": ["REPLY_TO_DOMAIN_MISMATCH"]
            },
            "ai": {"bec_type": "wire fraud", "reasons": ["REPLY_TO_DOMAIN_MISMATCH"]},
            "trace": {"geo": {"ip": "198.98.56.12", "city": "Dallas", "country": "US"}}
        }
        domain_res = ForensicCopilot.query("Explain the domain and reply to target", sample_report)
        self.assertEqual(domain_res["category"], "DOMAIN_ANALYSIS")
        self.assertIn("attacker@evil.xyz", domain_res["reply"])

        # 3. Header reasoning
        header_res = ForensicCopilot.query("Explain headers and SPF", sample_report)
        self.assertEqual(header_res["category"], "HEADER_ANALYSIS")
        self.assertIn("SPF", header_res["reply"])

        # 4. Out-of-band remediation
        oob_res = ForensicCopilot.query("What out of band steps should I take?", sample_report)
        self.assertEqual(oob_res["category"], "REMEDIATION")
        self.assertIn("Out-of-Band", oob_res["reply"])


if __name__ == "__main__":
    unittest.main()

