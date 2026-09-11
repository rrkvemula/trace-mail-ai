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
        # 1. Greeting mode
        empty_res = ForensicCopilot.query("")
        self.assertEqual(empty_res["category"], "GREETING")

        # 2. Test deterministic reasoning engine fallback under unit isolation
        with patch.object(ForensicCopilot, "_try_ollama", return_value=None), \
             patch("argus_x.analyst.ArgusAnalyst.query", side_effect=Exception("offline")):
            standby_res = ForensicCopilot.query("Hello")
            self.assertEqual(standby_res["category"], "STANDBY")

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

    def test_argus_x_native_analyst_integration(self):
        from engine.copilot_engine import ForensicCopilot
        # Verify ARGUS-X air-gapped forensic engine delivers triage when available
        res = ForensicCopilot.query("Hello")
        self.assertIn(res["engine"], ["argus_x_native", "deterministic", "trace_mail_neural_rules"])
        self.assertIn("reply", res)


    def test_evidence_generator_handles_special_xml_characters(self):
        from engine.evidence_generator import EvidenceGenerator
        bad_data = {
            "analysis_id": "TEST<SPECIAL>&ID",
            "forensic_hash": "a" * 64,
            "threat_analysis": {"verdict": "MALICIOUS <SCRIPT> & ATTACK", "threat_score": 88.0},
            "ml_analysis": {"phishing_probability": 0.95, "label": "PHISHING <ALERT>"},
            "headers": {"from": "attacker<script>@evil.com", "to": "victim@co.org"},
            "authentication": {},
            "hops_analysis": {},
            "ledger_receipt": {"record_hash": "RECORD<HASH>&01"}
        }
        with tempfile.NamedTemporaryFile(suffix=".pdf") as f:
            pdf_path = EvidenceGenerator.generate_pdf(bad_data, f.name)
            self.assertTrue(Path(pdf_path).exists())
            self.assertGreater(Path(pdf_path).stat().st_size, 1000)

    def test_auth_validator_dns_caching(self):
        from engine.auth_validator import AuthValidator
        AuthValidator._DNS_CACHE.clear()
        v1 = AuthValidator({"from": "user@google.com"})
        r1 = v1._query_dns_records("google.com")
        self.assertIn("google.com", AuthValidator._DNS_CACHE)

        # Second call must hit cache immediately
        with patch("dns.resolver.Resolver") as mock_resolver:
            r2 = v1._query_dns_records("google.com")
            mock_resolver.assert_not_called()
            self.assertEqual(r1, r2)

    def test_geoip_cache_bounding(self):
        from engine.geoip_resolver import GeoIPResolver
        GeoIPResolver.CACHE.clear()
        original_max = GeoIPResolver.MAX_CACHE_SIZE
        try:
            GeoIPResolver.MAX_CACHE_SIZE = 5
            for i in range(10):
                GeoIPResolver._store_cache(f"key-{i}", {"data": i})
            self.assertLessEqual(len(GeoIPResolver.CACHE), 5)
            self.assertIn("key-9", GeoIPResolver.CACHE)
            self.assertNotIn("key-0", GeoIPResolver.CACHE)
        finally:
            GeoIPResolver.MAX_CACHE_SIZE = original_max

    def test_trained_ml_classifier_multi_class(self):
        from engine.ml_classifier import CLASSIFIER

        # 1. Test BEC prediction
        bec_text = "Urgent: Please expedite confidential wire transfer of $50,000 to our new vendor bank account."
        bec_res = CLASSIFIER.predict(bec_text)
        self.assertGreater(bec_res["phishing_probability"], 0.75)
        if "class_probabilities" in bec_res:
            self.assertGreater(bec_res["class_probabilities"]["bec_fraud"], 0.60)

        # 2. Test Phishing prediction
        phish_text = "Security Alert: Microsoft 365 password expired. Verify your corporate credentials at http://portal.com"
        phish_res = CLASSIFIER.predict(phish_text)
        self.assertGreater(phish_res["phishing_probability"], 0.75)
        if "class_probabilities" in phish_res:
            self.assertGreater(phish_res["class_probabilities"]["phishing"], 0.60)

        # 3. Test Legitimate prediction
        legit_text = "Smart India Hackathon campus orientation schedule has been updated. Please review the attached agenda."
        legit_res = CLASSIFIER.predict(legit_text)
        self.assertLess(legit_res["phishing_probability"], 0.35)

    def test_onnx_transformer_active_inference(self):
        from engine.ml_classifier import CLASSIFIER
        res = CLASSIFIER.predict("Urgent: wire transfer of $10,000 required immediately.")
        self.assertIn("ONNX", res.get("algorithm", ""))
        self.assertEqual(res.get("validation_status"), "TRAINED_PRODUCTION_DEEP_LEARNING")
        self.assertIn("bec_fraud", res.get("class_probabilities", {}))
        self.assertGreater(res["class_probabilities"]["bec_fraud"], 0.70)

    def test_html_only_body_fallback(self):
        html_email = (
            b"From: billing@vendor.com\r\n"
            b"To: victim@corp.com\r\n"
            b"Subject: Invoice Due\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body><style>p {color:red;}</style><p>Please wire $45,000 to our new bank account urgently.</p></body></html>"
        )
        parsed = EmailParser(html_email).parse()
        self.assertTrue(parsed["body"]["has_html"])
        self.assertIn("Please wire $45,000 to our new bank account urgently.", parsed["body"]["plain_text"])
        self.assertNotIn("<style>", parsed["body"]["plain_text"])
        self.assertNotIn("<p>", parsed["body"]["plain_text"])

    def test_ipv6_hop_and_origin_extraction(self):
        ipv6_email = (
            b"From: test@ipv6.com\r\n"
            b"To: victim@corp.com\r\n"
            b"Subject: IPv6 Test\r\n"
            b"X-Originating-IP: [2001:4860:4860::8888]\r\n"
            b"Received: from mail.example.com (mail.example.com [IPv6:2607:f8b0:4005:805::200e])\r\n"
            b" by mx.google.com with ESMTPS id 123;\r\n"
            b" Fri, 11 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Testing IPv6 extraction."
        )
        parsed = EmailParser(ipv6_email).parse()
        self.assertEqual(len(parsed["hops"]), 1)
        self.assertEqual(parsed["hops"][0]["ip"], "2607:f8b0:4005:805::200e")
        self.assertTrue(parsed["hops"][0]["is_public_ip"])
        self.assertEqual(parsed["origin_ip"], "2001:4860:4860::8888")


if __name__ == "__main__":
    unittest.main()

