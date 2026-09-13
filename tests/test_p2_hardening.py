"""
Tests for P2 Operational Hardening & Copilot Capability:
1. CSP Header Hardening in app.py
2. Bounded Rate Limiter with TTL Pruning in app.py
3. GLM-5.3 Forensic AI Analyst integration in engine/glm_analyst.py & app.py
"""

import time
import json
import asyncio
import threading
import unittest
from unittest.mock import patch, MagicMock
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from fastapi import HTTPException

from app import (
    app as fastapi_app,
    BoundedRateLimiter,
    check_client_rate_limit,
    RATE_LIMITER,
    add_security_headers,
    forensic_ai_analyst,
    AIAnalystRequest,
    ANALYSIS_CACHE,
    get_client_ip,
    build_ui_compatible_payload,
    analyze_email,
)
from engine.glm_analyst import GLMForensicAnalyst


def run_async(coro):
    if asyncio.iscoroutine(coro):
        return asyncio.run(coro)
    return coro


class CSPHardeningTests(unittest.TestCase):
    """Test suite for Content Security Policy audit and hardening."""

    def _get_csp_header(self, path="/health"):
        # Invoke add_security_headers middleware directly
        scope = {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
        req = Request(scope)

        async def dummy_next(r):
            return PlainTextResponse("OK")

        resp = run_async(add_security_headers(req, dummy_next))
        return resp.headers.get("Content-Security-Policy", "")

    def test_csp_header_present(self):
        csp = self._get_csp_header()
        self.assertTrue(len(csp) > 0, "Content-Security-Policy header must be present.")

    def test_csp_removes_unsafe_eval(self):
        csp = self._get_csp_header()
        self.assertNotIn(
            "'unsafe-eval'",
            csp,
            "CSP must not contain 'unsafe-eval' in any directive."
        )

    def test_csp_default_src_is_strictly_self(self):
        csp = self._get_csp_header()
        self.assertIn("default-src 'self'", csp)
        # Ensure default-src does not leak wildcards
        for part in csp.split(";"):
            part = part.strip()
            if part.startswith("default-src"):
                self.assertNotIn("https:", part)
                self.assertNotIn("'unsafe-inline'", part)
                self.assertNotIn("'unsafe-eval'", part)
                self.assertNotIn("data:", part)
                self.assertNotIn("blob:", part)

    def test_csp_includes_object_src_none_and_base_uri_self(self):
        csp = self._get_csp_header()
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'self'", csp)

    def test_csp_script_src_allows_ui_cdns_without_excessive_wildcards(self):
        csp = self._get_csp_header()
        # Required CDNs for dashboard Tailwind, Three.js, Lenis, and Firebase
        self.assertIn("https://cdn.tailwindcss.com", csp)
        self.assertIn("https://unpkg.com", csp)
        self.assertIn("https://cdnjs.cloudflare.com", csp)
        self.assertIn("https://www.gstatic.com", csp)
        self.assertIn("https://apis.google.com", csp)
        # Wildcard *.google.com should not be in script-src
        for part in csp.split(";"):
            part = part.strip()
            if part.startswith("script-src"):
                self.assertNotIn("https://*.google.com", part)

    def test_csp_has_explicit_style_font_and_img_directives(self):
        csp = self._get_csp_header()
        self.assertIn("style-src", csp)
        self.assertIn("font-src", csp)
        self.assertIn("img-src", csp)
        self.assertIn("connect-src", csp)
        self.assertIn("frame-src", csp)

    def test_csp_style_and_img_sources_support_leaflet_and_map_tiles(self):
        csp = self._get_csp_header()
        self.assertIn("https://unpkg.com", csp)
        self.assertIn("https://*.basemaps.cartocdn.com", csp)
        self.assertIn("https://*.tile.openstreetmap.org", csp)


class BoundedRateLimiterTests(unittest.TestCase):
    """Test suite for sliding-window rate limiter bounding and TTL cleanup."""

    def test_under_limit_passes(self):
        limiter = BoundedRateLimiter(window_seconds=10, max_requests=5, max_tracked_ips=100)
        for _ in range(5):
            self.assertTrue(limiter.check("192.168.1.100"))

    def test_over_limit_blocked(self):
        limiter = BoundedRateLimiter(window_seconds=10, max_requests=3, max_tracked_ips=100)
        self.assertTrue(limiter.check("10.0.0.1"))
        self.assertTrue(limiter.check("10.0.0.1"))
        self.assertTrue(limiter.check("10.0.0.1"))
        # 4th request exceeds limit
        self.assertFalse(limiter.check("10.0.0.1"))

    def test_capacity_bounding_lru_eviction(self):
        max_ips = 5
        limiter = BoundedRateLimiter(window_seconds=60, max_requests=10, max_tracked_ips=max_ips)
        for i in range(20):
            limiter.check(f"172.16.0.{i}")

        # Tracked count must be bounded and never exceed max_tracked_ips
        self.assertLessEqual(limiter.tracked_count(), max_ips)

    def test_stale_ip_ttl_pruning(self):
        limiter = BoundedRateLimiter(window_seconds=1, max_requests=5, max_tracked_ips=100, cleanup_interval=1)
        limiter.check("1.1.1.1")
        limiter.check("2.2.2.2")
        self.assertEqual(limiter.tracked_count(), 2)

        # Fast forward time beyond window
        with patch("time.time", return_value=time.time() + 2.0):
            # Accessing check on another IP triggers prune
            limiter.check("3.3.3.3")
            # 1.1.1.1 and 2.2.2.2 are older than 1s window and should be pruned
            self.assertEqual(limiter.tracked_count(), 1)

    def test_concurrent_rate_limiter_thread_safety(self):
        limiter = BoundedRateLimiter(window_seconds=60, max_requests=100, max_tracked_ips=50)
        errors = []

        def worker(worker_id):
            try:
                for _ in range(20):
                    limiter.check(f"192.168.0.{worker_id % 10}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
        self.assertLessEqual(limiter.tracked_count(), 50)

    def test_client_ip_extraction_from_forwarded_headers(self):
        # Cloudflare header
        scope_cf = {"type": "http", "method": "GET", "path": "/", "headers": [(b"cf-connecting-ip", b"203.0.113.195")], "client": ("10.0.0.1", 12345)}
        self.assertEqual(get_client_ip(Request(scope_cf)), "203.0.113.195")

        # X-Real-IP header
        scope_real = {"type": "http", "method": "GET", "path": "/", "headers": [(b"x-real-ip", b"198.51.100.22")], "client": ("10.0.0.1", 12345)}
        self.assertEqual(get_client_ip(Request(scope_real)), "198.51.100.22")

        # X-Forwarded-For header with multiple hops
        scope_xff = {"type": "http", "method": "GET", "path": "/", "headers": [(b"x-forwarded-for", b"192.0.2.1, 10.0.0.2")], "client": ("10.0.0.1", 12345)}
        self.assertEqual(get_client_ip(Request(scope_xff)), "192.0.2.1")

        # Peer fallback
        scope_peer = {"type": "http", "method": "GET", "path": "/", "headers": [], "client": ("172.16.1.5", 12345)}
        self.assertEqual(get_client_ip(Request(scope_peer)), "172.16.1.5")

    def test_zero_limit_lru_bounding(self):
        limiter = BoundedRateLimiter(window_seconds=60, max_requests=0, max_tracked_ips=3)
        for i in range(10):
            res = limiter.check(f"192.168.1.{i}")
            self.assertFalse(res)
        self.assertLessEqual(limiter.tracked_count(), 3)


class GLMForensicAnalystTests(unittest.TestCase):
    """Test suite for GLM-5.3 Forensic AI Analyst integration & fallback."""

    def setUp(self):
        self.benign_report = {
            "analysis_id": "ANL-BENIGN-001",
            "forensic_hash": "a1b2c3d4" * 8,
            "threat_analysis": {
                "threat_score": 5.0,
                "risk_category": "LOW_OBSERVED_RISK",
                "detections": [],
                "explainability_factors": [{"detail": "All cryptographic signatures valid"}]
            },
            "authentication": {
                "spf": {"status": "PASS", "domain": "example.com"},
                "dkim": {"status": "PASS", "domain": "example.com"},
                "dmarc": {"status": "PASS"},
                "composite_pass": True,
            },
            "headers": {
                "from": "alice@example.com",
                "return_path": "alice@example.com",
                "subject": "Weekly Team Meeting",
                "to": "bob@example.com",
            },
            "origin_geo": {"ip": "93.184.216.34", "country": "United States", "asn": "AS15133"},
            "origin_ip": "93.184.216.34",
            "body_summary": {"scanned_links": [], "attachments": []},
            "ledger_receipt": {"record_hash": "1111222233334444"},
        }

        self.malicious_report = {
            "analysis_id": "ANL-THREAT-002",
            "forensic_hash": "e5f6e7f8" * 8,
            "threat_analysis": {
                "threat_score": 88.0,
                "risk_category": "CRITICAL_THREAT",
                "detections": ["BEC_VENDOR_FINANCIAL_DIVERSION", "DISPLAY_NAME_SPOOFING", "PUNYCODE_LOOKALIKE"],
                "explainability_factors": [
                    {"detail": "Critical BEC keyword combinations for wire diversion"},
                    {"detail": "Punycode deceptive link target"}
                ]
            },
            "authentication": {
                "spf": {"status": "FAIL", "domain": "spoofer.net"},
                "dkim": {"status": "NONE", "domain": ""},
                "dmarc": {"status": "FAIL"},
                "composite_pass": False,
            },
            "headers": {
                "from": "\"CEO John\" <ceo@spoofer.net>",
                "return_path": "bounce@spoofer.net",
                "subject": "URGENT: Immediate Vendor Payment Wire Routing Update",
                "to": "cfo@targetcorp.com",
            },
            "origin_geo": {"ip": "185.220.101.5", "country": "Germany", "asn": "AS208323", "is_tor": True},
            "origin_ip": "185.220.101.5",
            "body_summary": {
                "scanned_links": [{"original": "https://xn--paypl-qqa.com", "punycode": True, "suspicious": True}],
                "attachments": [{"filename": "invoice_update.pdf.exe", "is_weaponized": True, "double_extension": True}],
            },
            "ledger_receipt": {"record_hash": "5555666677778888"},
        }

    def test_deterministic_fallback_on_benign_report(self):
        result = GLMForensicAnalyst.synthesize_triage(self.benign_report, force_deterministic=True)
        self.assertEqual(result["status"], "FALLBACK_DETERMINISTIC")
        self.assertEqual(result["analysis_id"], "ANL-BENIGN-001")
        self.assertEqual(result["risk_category"], "LOW_OBSERVED_RISK")
        self.assertTrue(result["ledger_verified"])
        self.assertIn("Executive Incident Narrative", result["narrative"])
        self.assertGreaterEqual(len(result["triage_advice"]), 1)

    def test_deterministic_fallback_on_malicious_report(self):
        result = GLMForensicAnalyst.synthesize_triage(self.malicious_report, force_deterministic=True)
        self.assertEqual(result["status"], "FALLBACK_DETERMINISTIC")
        self.assertEqual(result["analysis_id"], "ANL-THREAT-002")
        self.assertEqual(result["risk_category"], "CRITICAL_THREAT")
        self.assertGreaterEqual(result["threat_score"], 70.0)

        # Check triage advice contains containment actions
        advice_text = " ".join(result["triage_advice"]).upper()
        self.assertIn("QUARANTINE", advice_text)
        self.assertIn("FINANCIAL VERIFICATION", advice_text)

        # Check MITRE ATT&CK mapping
        tech_ids = {m["technique_id"] for m in result["mitre_mappings"]}
        self.assertTrue(any(t in tech_ids for t in ("T1566.002", "T1586.002", "T1656")))

    def test_http_429_graceful_fallback(self):
        import urllib.error
        error_429 = urllib.error.HTTPError(
            url="https://api.tokenrouter.com/v1/chat/completions",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=None
        )
        with patch("urllib.request.urlopen", side_effect=error_429):
            with patch.dict("os.environ", {"TOKENROUTER_API_KEY": "test_token"}):
                result = GLMForensicAnalyst.synthesize_triage(self.malicious_report)
                self.assertEqual(result["status"], "FALLBACK_DETERMINISTIC")
                self.assertIn("429", result.get("fallback_reason", ""))
                self.assertIn("QUARANTINE", " ".join(result["triage_advice"]))

    def test_tokenrouter_successful_response_parsing(self):
        ai_response_payload = {
            "choices": [
                {
                    "message": {
                        "content": (
                            "### Executive Threat Narrative\n"
                            "This is a high-confidence Business Email Compromise attack.\n\n"
                            "### Immediate Actions\n"
                            "- [ ] QUARANTINE message from all mailboxes\n"
                            "- [ ] BLOCK origin IP on border firewall\n"
                            "- [ ] VERIFY bank details out of band with vendor\n\n"
                            "### MITRE Matrix\n"
                            "- T1566.002 Spearphishing Link\n"
                            "- T1586.002 Compromised Email Account"
                        )
                    }
                }
            ]
        }
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(ai_response_payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with patch.dict("os.environ", {"TOKENROUTER_API_KEY": "valid_token"}):
                result = GLMForensicAnalyst.synthesize_triage(self.malicious_report)
                self.assertEqual(result["status"], "SUCCESS")
                self.assertEqual(result["engine"], "z-ai/glm-5.3-free")
                self.assertIn("Business Email Compromise", result["narrative"])
                self.assertGreaterEqual(len(result["triage_advice"]), 2)

    def test_endpoint_forensic_ai_analyst_direct(self):
        req = AIAnalystRequest(report=self.malicious_report, force_deterministic=True)
        res = forensic_ai_analyst(req)
        self.assertEqual(res["analysis_id"], "ANL-THREAT-002")
        self.assertIn("triage_advice", res)
        self.assertIn("narrative", res)

    def test_endpoint_cached_analysis_retrieval(self):
        ANALYSIS_CACHE["ANL-BENIGN-001"] = self.benign_report
        req = AIAnalystRequest(analysis_id="ANL-BENIGN-001", force_deterministic=True)
        res = forensic_ai_analyst(req)
        self.assertEqual(res["analysis_id"], "ANL-BENIGN-001")
        self.assertEqual(res["risk_category"], "LOW_OBSERVED_RISK")

    def test_endpoint_unknown_analysis_id_returns_404(self):
        ANALYSIS_CACHE.clear()
        ANALYSIS_CACHE["ANL-BENIGN-001"] = self.benign_report
        req = AIAnalystRequest(analysis_id="ANL-NONEXISTENT", force_deterministic=True)
        with self.assertRaises(HTTPException) as ctx:
            forensic_ai_analyst(req)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_build_ui_compatible_payload_preserves_analysis_id_and_hash(self):
        raw_report = dict(self.benign_report)
        raw_report["analysis_id"] = "ANL-TEST-999"
        raw_report["forensic_hash"] = "fedcba9876543210"
        ui_payload = build_ui_compatible_payload(raw_report)
        self.assertEqual(ui_payload.get("analysis_id"), "ANL-TEST-999")
        self.assertEqual(ui_payload.get("forensic_hash"), "fedcba9876543210")

    def test_glm_analyst_supports_ui_payload_format(self):
        raw_report = dict(self.malicious_report)
        raw_report["analysis_id"] = "ANL-UI-001"
        raw_report["forensic_hash"] = "abcdef1234567890"
        ui_payload = build_ui_compatible_payload(raw_report)
        result = GLMForensicAnalyst.synthesize_triage(ui_payload, force_deterministic=True)
        self.assertEqual(result["status"], "FALLBACK_DETERMINISTIC")
        self.assertEqual(result["analysis_id"], "ANL-UI-001")
        self.assertGreaterEqual(result["threat_score"], 70.0)

    def test_analyze_email_endpoint_signature_has_request(self):
        import inspect
        sig = inspect.signature(analyze_email)
        self.assertIn("request", sig.parameters)


if __name__ == "__main__":
    unittest.main()
