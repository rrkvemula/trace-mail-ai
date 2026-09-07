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


if __name__ == "__main__":
    unittest.main()
