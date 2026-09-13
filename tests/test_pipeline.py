import hashlib
import os
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
        with patch.object(ForensicCopilot, "_try_tokenrouter_glm", return_value=None), \
             patch.object(ForensicCopilot, "_try_ollama", return_value=None), \
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
        with patch.object(ForensicCopilot, "_try_tokenrouter_glm", return_value=None):
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
        self.assertEqual(res.get("validation_status"), "SYNTHETIC_TEMPLATE_BASELINE")
        self.assertIn("model_card", res)
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

    def test_rag_engine_retrieval(self):
        from engine.rag_engine import ForensicRAG
        # 1. MITRE ATT&CK retrieval
        phish_docs = ForensicRAG.retrieve("Spearphishing links and punycode domain harvesting", top_k=2)
        self.assertGreaterEqual(len(phish_docs), 1)
        self.assertIn("MITRE-T1566", phish_docs[0]["id"])

        # 2. CISA & FBI Wire Fraud Playbook retrieval
        bec_docs = ForensicRAG.retrieve("Vendor bank account change and wire transfer diversion", top_k=2)
        self.assertGreaterEqual(len(bec_docs), 1)
        bec_ids = [d["id"] for d in bec_docs]
        self.assertIn("PLAYBOOK-BEC-01", bec_ids)
        playbook = next(d for d in bec_docs if d["id"] == "PLAYBOOK-BEC-01")
        self.assertIn("SWIFT", " ".join(playbook["raw"]["immediate_actions"]))

        # 3. RFC Standards retrieval
        rfc_docs = ForensicRAG.retrieve("DMARC alignment strict vs relaxed mode", top_k=2)
        self.assertGreaterEqual(len(rfc_docs), 1)
        self.assertEqual(rfc_docs[0]["id"], "RFC-7489")

    def test_copilot_rag_augmented_reply(self):
        from engine.copilot_engine import ForensicCopilot
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
        with patch.object(ForensicCopilot, "_try_tokenrouter_glm", return_value=None):
            res = ForensicCopilot.query("What does CISA playbook say about wire fraud?", sample_report)
            self.assertTrue(res.get("rag_augmented"))
            self.assertGreaterEqual(len(res.get("citations", [])), 1)
            self.assertIn("SWIFT", res["reply"])

    def test_mobile_pdf_email_extraction_and_domain_geolocation(self):
        from reportlab.pdfgen import canvas
        import io
        buf = io.BytesIO()
        c = canvas.Canvas(buf)
        c.drawString(100, 750, "From: support@chatgpt.openai.com")
        c.drawString(100, 730, "To: rk@example.com")
        c.drawString(100, 710, "Subject: OpenAI ChatGPT Team Invitation")
        c.drawString(100, 690, "Welcome to the team workspace.")
        c.save()
        pdf_bytes = buf.getvalue()

        report = ForensicPipeline.process_raw_email(pdf_bytes)
        self.assertTrue(report.get("origin_location"))
        self.assertIn("San Francisco", report.get("origin_location", ""))
        self.assertEqual(report.get("origin_geo", {}).get("country"), "United States")
        self.assertIsNotNone(report.get("origin_geo", {}).get("latitude"))

    def test_mobile_pdf_email_with_in_text_origin_ip(self):
        from reportlab.pdfgen import canvas
        import io
        buf = io.BytesIO()
        c = canvas.Canvas(buf)
        c.drawString(100, 750, "From: notifications@openai.com")
        c.drawString(100, 730, "To: rk@example.com")
        c.drawString(100, 710, "Subject: Security Alert")
        c.drawString(100, 690, "Security cluster outbound relay observed: 167.89.61.27")
        c.save()
        pdf_bytes = buf.getvalue()

        report = ForensicPipeline.process_raw_email(pdf_bytes)
        self.assertEqual(report.get("origin_ip"), "167.89.61.27")
        self.assertIn("Denver", report.get("origin_location", ""))
        self.assertEqual(report.get("origin_geo", {}).get("country"), "United States")

    def test_folded_dkim_headers_with_from_clause(self):
        """Ensures that RFC 5322 folded continuation lines containing 'from:' do not corrupt the From: header."""
        eml_text = (
            "Received: from mta.example.com ([193.35.16.214]) by mx.google.com;\n"
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\n"
            "\td=unstop.news; s=nc2048;\n"
            "\th=message-id:reply-to:to:\n"
            "\t from:subject:mime-version:content-type;\n"
            "\tbh=abc123==;\n"
            "From: Ananya Bhatt <noreply@unstop.news>\n"
            "To: recipient@example.com\n"
            "Subject: Test Folded DKIM\n"
            "\n"
            "Hello world"
        )
        report = ForensicPipeline.process_raw_email(eml_text)
        self.assertEqual(report["headers"].get("from"), "Ananya Bhatt <noreply@unstop.news>")
        self.assertEqual(report["headers"].get("subject"), "Test Folded DKIM")
        self.assertEqual(report.get("origin_ip"), "193.35.16.214")

    def test_two_class_evidence_precedence_policy(self):
        """Ensures that isolated single heuristics cannot trigger high-risk categorization without >=2 independent evidence classes."""
        from engine.threat_scorer import ThreatScorer
        # Simulate an email with only linguistic urgency keywords and high ML probability, but NO crypto failure, NO link threat, NO BEC wire diversion
        parsed = {
            "headers": {"from": "partner@legit-partner.com", "to": "user@corp.com", "subject": "Urgent Action Required"},
            "body": {"plain_text": "Please verify your account and complete action immediately. Urgent invoice attached."},
            "attachments": []
        }
        auth = {"composite_pass": False, "is_unverified": True, "spf": {"status": "NONE"}, "dkim": {"status": "NONE"}, "dmarc": {"status": "NONE"}}
        hop = {"has_timing_anomalies": False, "analyzed_hops": []}
        ml = {"phishing_probability": 0.95, "matched_indicators": ["urgent", "verify"]}

        scorer = ThreatScorer(parsed, auth, hop, ml)
        res = scorer.calculate()
        # Single evidence class (or zero hard classes) must not be allowed to trigger HIGH_RISK or QUARANTINE_RECOMMENDED
        self.assertNotEqual(res.get("risk_category"), "HIGH_RISK")
        self.assertEqual(res.get("enforcement_action"), "WARN_REVIEW")
        self.assertLessEqual(res.get("threat_score"), 65.0)
        self.assertEqual(res.get("evidence_strength"), "LOW")
        self.assertIn("limitations", res)

    def test_untrusted_authserv_detection(self):
        """Ensures that fake or untrusted authserv-id in Authentication-Results is flagged."""
        from engine.auth_validator import AuthValidator
        headers = {
            "from": "sales@attacker.com",
            "to": "victim@mycorp.com",
            "authentication_results": ["attacker.com; spf=pass; dkim=pass; dmarc=pass"]
        }
        hops = [{"by_mta": "mx.mycorp.com", "from_mta": "mail.attacker.com"}]
        validator = AuthValidator(headers, hops)
        audit = validator.audit()
        self.assertFalse(audit.get("is_trusted_authserv"))
        self.assertEqual(audit.get("evidence_status"), "FORGED_OR_UNTRUSTED_AUTHSERV")
        self.assertIn("limitations", audit)

    def test_model_card_and_experimental_signal(self):
        """Verifies that the ML classifier provides an honest SYNTHETIC_TEMPLATE_BASELINE and comprehensive model card."""
        from engine.ml_classifier import CLASSIFIER
        pred = CLASSIFIER.predict("Hello, checking in on the project deliverables.")
        self.assertEqual(pred.get("validation_status"), "SYNTHETIC_TEMPLATE_BASELINE")
        self.assertIn("model_card", pred)
        card = pred["model_card"]
        self.assertEqual(card.get("status"), "SYNTHETIC_TEMPLATE_BASELINE")
        self.assertIn("limitations", card)

    def test_internal_same_domain_authserv_is_trusted(self):
        """Ensures that internal same-domain mail with matching authserv-id is trusted when corroborated by observed receiving MTA."""
        from engine.auth_validator import AuthValidator
        headers = {
            "from": "hr@mycorp.com",
            "to": "employee@mycorp.com",
            "authentication_results": ["mycorp.com; spf=pass; dkim=pass; dmarc=pass"]
        }
        hops = [{"by_mta": "mail.mycorp.com (Postfix)"}]
        validator = AuthValidator(headers, hops=hops)
        audit = validator.audit()
        self.assertTrue(audit.get("is_trusted_authserv"))
        self.assertIn("Internal domain authority", audit["authserv_evaluation"].get("reason", ""))

    def test_authserv_attacker_to_header_spoof_rejected(self):
        """Ensures that an external attacker cannot bypass authserv trust by setting To: header to match their domain (P0-3 Fix)."""
        from engine.auth_validator import AuthValidator
        headers = {
            "from": "ceo@attacker.com",
            "to": "victim@attacker.com",
            "authentication_results": ["attacker.com; spf=pass; dkim=pass; dmarc=pass"]
        }
        # Observed hop is Google or external provider, NOT attacker.com
        hops = [{"by_mta": "mx.google.com"}]
        validator = AuthValidator(headers, hops=hops)
        audit = validator.audit()
        self.assertFalse(audit.get("is_trusted_authserv"))
        self.assertEqual(audit.get("evidence_status"), "FORGED_OR_UNTRUSTED_AUTHSERV")

    def test_authserv_attacker_no_hops_to_header_spoof_rejected(self):
        """Ensures that an attacker cannot bypass authserv trust in an email without hops by setting To: domain to match From: (P0-3 Fix)."""
        from engine.auth_validator import AuthValidator
        headers = {
            "from": "ceo@attacker.com",
            "to": "victim@attacker.com",
            "authentication_results": ["attacker.com; spf=pass; dkim=pass; dmarc=pass"]
        }
        # No hops provided at all
        validator = AuthValidator(headers, hops=[])
        audit = validator.audit()
        self.assertFalse(audit.get("is_trusted_authserv"))
        self.assertEqual(audit.get("evidence_status"), "FORGED_OR_UNTRUSTED_AUTHSERV")

    def test_double_extension_attachment_detection(self):
        """Ensures that dangerous double extensions (e.g. invoice.pdf.exe) trigger high-severity alert."""
        from engine.threat_scorer import ThreatScorer
        parsed = {
            "headers": {"from": "vendor@supplies.com", "to": "user@corp.com", "subject": "Invoice"},
            "body": {"plain_text": "Please see attached invoice."},
            "attachments": [{"filename": "invoice_march.pdf.exe", "content_type": "application/x-msdownload"}]
        }
        auth = {"composite_pass": False, "is_unverified": True, "spf": {"status": "NONE"}, "dkim": {"status": "NONE"}, "dmarc": {"status": "NONE"}}
        hop = {"has_timing_anomalies": False, "analyzed_hops": []}
        scorer = ThreatScorer(parsed, auth, hop)
        res = scorer.calculate()
        self.assertIn("DOUBLE_EXTENSION_DECEPTION", res.get("detections", []))
        self.assertIn("WEAPONIZED_ATTACHMENT", res.get("detections", []))
        self.assertGreaterEqual(res.get("threat_score"), 45.0)

    def test_mime_extension_mismatch_detection(self):
        """Ensures that declared MIME type mismatch with executable payload is flagged."""
        from engine.threat_scorer import ThreatScorer
        parsed = {
            "headers": {"from": "admin@service.com", "to": "user@corp.com", "subject": "Document"},
            "body": {"plain_text": "Attached form"},
            "attachments": [{"filename": "form.scr", "content_type": "application/pdf"}]
        }
        auth = {"composite_pass": False, "is_unverified": True, "spf": {"status": "NONE"}, "dkim": {"status": "NONE"}, "dmarc": {"status": "NONE"}}
        hop = {"has_timing_anomalies": False, "analyzed_hops": []}
        scorer = ThreatScorer(parsed, auth, hop)
        res = scorer.calculate()
        self.assertIn("MIME_EXTENSION_MISMATCH", res.get("detections", []))

    def test_deterministic_dkim_verification_and_conflict_states(self):
        """Deterministic CI-portable test for independent DKIM passes, crypto-fail conflicts, and DNS outages (P0-1 & P0-2 Fix)."""
        from unittest.mock import patch
        from engine.auth_validator import AuthValidator

        headers = {
            "from": "notifications@verified.org",
            "to": "user@example.com",
            "authentication_results": ["mx.google.com; dkim=pass header.i=@verified.org header.s=s1; spf=pass; dmarc=pass"],
            "dkim_signature": ["v=1; a=rsa-sha256; d=verified.org; s=s1; b=fake..."]
        }
        hops = [{"by_mta": "mx.google.com"}]
        raw_eml = b"From: notifications@verified.org\r\nTo: user@example.com\r\nDKIM-Signature: v=1; d=verified.org; s=s1; b=fake\r\n\r\nHello"

        # 1. Successful independent cryptographic validation
        with patch("dkim.load_pk_from_dns", return_value=(b"fake_pk", 2048, "rsa", None)), \
             patch("dkim.verify", return_value=True):
            validator = AuthValidator(headers, hops=hops, raw_content=raw_eml)
            audit = validator.audit()
            self.assertEqual(audit.get("evidence_status"), "INDEPENDENTLY_VERIFIED_PASS")
            self.assertTrue(audit.get("dkim", {}).get("independently_verified"))

        # 2. Critical Crypto Mismatch: Receiver said pass, but independent crypto fails (tampering/forgery)
        with patch("dkim.load_pk_from_dns", return_value=(b"fake_pk", 2048, "rsa", None)), \
             patch("dkim.verify", return_value=False):
            validator = AuthValidator(headers, hops=hops, raw_content=raw_eml)
            audit = validator.audit()
            self.assertEqual(audit.get("evidence_status"), "RECEIVER_PASS_CRYPTO_MISMATCH")
            self.assertEqual(audit.get("overall_status"), "CRYPTO_MISMATCH_OR_TAMPERED")
            self.assertFalse(audit.get("composite_pass"))

        # 3. DNS/Key Unavailable: Key missing from DNS
        import dkim
        with patch("dkim.load_pk_from_dns", side_effect=dkim.KeyFormatError("missing public key")):
            validator = AuthValidator(headers, hops=hops, raw_content=raw_eml)
            audit = validator.audit()
            self.assertEqual(audit.get("evidence_status"), "RECEIVER_REPORTED_PASS_KEY_UNAVAILABLE")
            self.assertEqual(audit.get("dkim", {}).get("independent_status"), "DKIM_KEY_MISSING")

    def test_scoped_allowlist_suppresses_noise_but_not_weaponized_payload(self):
        """Verifies that scoped allowlist suppresses noise for trusted senders, but NEVER suppresses weaponized payloads (P1 Fix)."""
        from engine.threat_scorer import ThreatScorer

        # Scenario A: Benign mail from allowlisted exact sender
        parsed_benign = {
            "headers": {"from": "billing@trusted-vendor.com", "to": "finance@corp.com", "subject": "Urgent wire payment update"},
            "body": {"plain_text": "Please process payment urgently."},
            "attachments": []
        }
        auth_pass = {"composite_pass": True, "sender_domain": "trusted-vendor.com", "evidence_status": "RECEIVER_REPORTED_PASS"}
        hop_clean = {"has_timing_anomalies": False, "analyzed_hops": []}
        allowlist = {"billing@trusted-vendor.com"}

        scorer = ThreatScorer(parsed_benign, auth_pass, hop_clean, allowlist=allowlist)
        res = scorer.calculate()
        self.assertEqual(res.get("threat_score"), 0.0)
        self.assertEqual(res.get("enforcement_action"), "ALLOW")

        # Scenario B: Mail from allowlisted sender carrying weaponized attachment (.pdf.exe)
        parsed_malicious = {
            "headers": {"from": "billing@trusted-vendor.com", "to": "finance@corp.com", "subject": "Invoice"},
            "body": {"plain_text": "Attached is your invoice."},
            "attachments": [{"filename": "invoice.pdf.exe", "content_type": "application/x-msdownload"}]
        }
        scorer_mal = ThreatScorer(parsed_malicious, auth_pass, hop_clean, allowlist=allowlist)
        res_mal = scorer_mal.calculate()
        # Safety Invariant: Allowlist must be bypassed!
        self.assertGreaterEqual(res_mal.get("threat_score"), 45.0)
        self.assertIn("WEAPONIZED_ATTACHMENT", res_mal.get("detections", []))
        self.assertTrue(any("Allowlist bypassed" in f.get("detail", "") for f in res_mal.get("explainability_factors", [])))

    def test_homoglyph_brand_impersonation_detection(self):
        """Verifies that visual homoglyphs imitating protected brands (e.g. Cyrillic 'a' in pаypal) are caught with UTS-39."""
        from engine.url_scanner import URLScanner
        # Cyrillic 'а' (U+0430) inside paypal
        spoofed_url = "https://p\u0430ypal.com/signin"
        res = URLScanner.scan_single(spoofed_url)
        self.assertTrue(res.get("is_homoglyph_brand"))
        self.assertEqual(res.get("impersonated_brand"), "paypal.com")
        self.assertTrue(res.get("suspicious"))

    def test_whole_script_legitimate_idn_not_penalized(self):
        """Ensures authentic international domains (e.g. münchen.de) do not trigger false positive homoglyph alerts."""
        from engine.url_scanner import URLScanner
        # Authentic German IDN
        legit_url = "https://xn--mnchen-3ya.de/service"
        res = URLScanner.scan_single(legit_url)
        self.assertFalse(res.get("is_homoglyph_brand"))
        self.assertFalse(res.get("is_mixed_script"))
        self.assertFalse(res.get("suspicious"))

    def test_html_anchor_href_mismatch_detected(self):
        """Ensures that HTML anchor text displaying a trusted domain while linking to an attacker domain is flagged."""
        from engine.parser import EmailParser
        from engine.threat_scorer import ThreatScorer

        html_body = '<a href="https://evil-harvest-phish.ru/login">https://chase.com/login</a>'
        raw_eml = f"From: alert@service.com\r\nTo: victim@example.com\r\nContent-Type: text/html\r\n\r\n{html_body}"
        parser = EmailParser(raw_eml)
        parsed = parser.parse()

        self.assertGreater(len(parsed.get("body", {}).get("link_spoofs", [])), 0)
        spoof = parsed["body"]["link_spoofs"][0]
        self.assertEqual(spoof.get("displayed_domain"), "chase.com")
        self.assertEqual(spoof.get("destination_domain"), "evil-harvest-phish.ru")

        # ThreatScorer calculation
        auth = {"composite_pass": False, "is_unverified": True, "spf": {"status": "NONE"}, "dkim": {"status": "NONE"}, "dmarc": {"status": "NONE"}}
        hop = {"has_timing_anomalies": False, "analyzed_hops": []}
        scorer = ThreatScorer(parsed, auth, hop)
        res = scorer.calculate()
        self.assertIn("LINK_TARGET_MISMATCH", res.get("detections", []))
        self.assertGreaterEqual(res.get("threat_score"), 45.0)


    def test_extortion_and_blackmail_threat_detection(self):
        """Tests that extortion, sextortion, and ransomware threats with crypto payment demands are detected and escalated."""
        from engine.threat_scorer import ThreatScorer

        # Scenario 1: Sextortion with Bitcoin payment demand
        email_data = {
            "headers": {"subject": "I have your private videos and recorded your webcam"},
            "body": {
                "plain_text": (
                    "I have your private videos and photos. I recorded you through your webcam. "
                    "Send 0.5 Bitcoin to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq within 48 hours "
                    "or I will leak this to all your contacts and your life will be ruined."
                )
            },
            "attachments": []
        }
        auth_pass = {"composite_pass": True, "spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
        hop_clean = {"has_timing_anomalies": False, "analyzed_hops": []}

        scorer = ThreatScorer(email_data, auth_pass, hop_clean)
        res = scorer.calculate()

        self.assertIn("SEXTORTION", res.get("detections", []))
        self.assertEqual(res.get("risk_category"), "HIGH_RISK")
        self.assertEqual(res.get("enforcement_action"), "QUARANTINE_RECOMMENDED")
        self.assertIn("CRITICAL EXTORTION", res.get("verdict", ""))
        self.assertTrue(any(f.get("category") == "VICTIM_GUIDANCE" for f in res.get("explainability_factors", [])))

        # Scenario 2: Ransomware file encryption threat
        ransom_data = {
            "headers": {"subject": "All your corporate files have been encrypted"},
            "body": {
                "plain_text": (
                    "Your files have been encrypted with military-grade algorithms. "
                    "To obtain the decryption key, pay the ransom in Monero to 48cedpbtb1wD5zPz1P5P9z "
                    "otherwise all sensitive information about you will be exposed."
                )
            },
            "attachments": []
        }
        scorer_ransom = ThreatScorer(ransom_data, auth_pass, hop_clean)
        res_ransom = scorer_ransom.calculate()

        self.assertIn("RANSOMWARE_THREAT", res_ransom.get("detections", []))
        self.assertEqual(res_ransom.get("risk_category"), "HIGH_RISK")


if __name__ == "__main__":
    unittest.main()


