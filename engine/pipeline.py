"""
Consolidated Forensic Pipeline Orchestrator
Coordinates ingestion, hop unrolling, cryptographic auth,
GeoIP enrichment, latency delta heuristics, and threat scoring.
"""

from typing import Dict, Any, Union
from .parser import EmailParser
from .hop_analyzer import HopAnalyzer
from .auth_validator import AuthValidator
from .geoip_resolver import GeoIPResolver
from .threat_scorer import ThreatScorer
from .ml_classifier import CLASSIFIER
from .ioc_graph import IOCGraphBuilder

class ForensicPipeline:
    """Orchestrates the entire TRACE-MAIL AI forensic workflow."""

    @classmethod
    def process_raw_email(cls, raw_email_content: Union[str, bytes]) -> Dict[str, Any]:
        # 1. Parse Envelope & MIME Structure
        parser = EmailParser(raw_email_content)
        parsed_data = parser.parse()

        # 2. Enrich Hops with Geolocation Telemetry
        enriched_hops = []
        for h in parsed_data.get("hops", []):
            hop_copy = dict(h)
            ip_to_resolve = hop_copy.get("ip")
            hop_copy["geo"] = GeoIPResolver.resolve(ip_to_resolve)
            enriched_hops.append(hop_copy)

        # 3. Analyze Hop Latency & Anti-Forged Relay Heuristics (ΔT)
        hop_analyzer = HopAnalyzer(enriched_hops)
        hop_results = hop_analyzer.analyze()

        # 4. Cryptographic Authentication & DMARC Alignment
        auth_validator = AuthValidator(parsed_data.get("headers", {}))
        auth_results = auth_validator.audit()

        # 5. Train-at-start prototype ML baseline plus explainable rule scoring
        ml_text = " ".join([
            parsed_data.get("headers", {}).get("subject", ""),
            parsed_data.get("body", {}).get("plain_text", ""),
        ])
        ml_results = CLASSIFIER.predict(ml_text)
        threat_scorer = ThreatScorer(parsed_data, auth_results, hop_results, ml_results)
        threat_results = threat_scorer.calculate()
        ioc_graph = IOCGraphBuilder.build(parsed_data, hop_results.get("analyzed_hops", []))

        # 6. Resolve Origin IP Geolocation
        origin_ip = parsed_data.get("origin_ip")
        origin_geo = GeoIPResolver.resolve(origin_ip)

        # Build Consolidated Forensic Payload
        return {
            "forensic_hash": parsed_data.get("forensic_hash"),
            "parsed_at_utc": parsed_data.get("parsed_at_utc"),
            "headers": parsed_data.get("headers"),
            "origin_ip": origin_ip,
            "origin_evidence": parsed_data.get("origin_evidence"),
            "origin_geo": origin_geo,
            "hops_analysis": hop_results,
            "authentication": auth_results,
            "threat_analysis": threat_results,
            "ml_analysis": ml_results,
            "ioc_graph": ioc_graph,
            "body_summary": {
                "plain_text_snippet": parsed_data.get("body", {}).get("plain_text", "")[:350],
                "links": parsed_data.get("body", {}).get("links", []),
                "total_links": parsed_data.get("body", {}).get("total_links", 0),
                "attachments": parsed_data.get("attachments", [])
            }
        }
