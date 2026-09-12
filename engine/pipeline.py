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

        # 2. Enrich Hops with Geolocation Telemetry (Bounded to max 5 hops to prevent DoS)
        enriched_hops = []
        raw_hops = parsed_data.get("hops", [])
        MAX_HOPS_TO_ENRICH = 5
        for i, h in enumerate(raw_hops):
            hop_copy = dict(h)
            ip_to_resolve = hop_copy.get("ip")
            if i < MAX_HOPS_TO_ENRICH:
                hop_copy["geo"] = GeoIPResolver.resolve(ip_to_resolve)
            else:
                hop_copy["geo"] = GeoIPResolver._empty_geo("Hop depth exceeded safe enrichment limit", is_private=False)
            enriched_hops.append(hop_copy)

        # 3. Analyze Hop Latency & Anti-Forged Relay Heuristics (ΔT)
        hop_analyzer = HopAnalyzer(enriched_hops)
        hop_results = hop_analyzer.analyze()

        # 4. Cryptographic Authentication & DMARC Alignment
        auth_validator = AuthValidator(parsed_data.get("headers", {}), hop_results.get("analyzed_hops", []), raw_email_content)
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

        # 6. Resolve Origin IP Geolocation & Physical Infrastructure
        origin_ip = parsed_data.get("origin_ip")
        origin_geo = GeoIPResolver.resolve(origin_ip)

        # Fallback 1: Check intermediate hops if origin IP was unlocated
        if not origin_ip or origin_geo.get("latitude") is None:
            for h in hop_results.get("analyzed_hops", []):
                h_ip = h.get("ip")
                if h_ip:
                    h_geo = GeoIPResolver.resolve(h_ip)
                    if h_geo.get("latitude") is not None:
                        origin_ip = h_ip
                        origin_geo = h_geo
                        break

        # Fallback 2: Resolve sender domain authority (vital for mobile PDF exports and visual snapshots)
        if not origin_ip or origin_geo.get("latitude") is None:
            import re
            from_hdr = str(parsed_data.get("headers", {}).get("from", ""))
            sender_domain = None
            m = re.search(r"@([a-zA-Z0-9.\-]+)", from_hdr)
            if m:
                sender_domain = m.group(1).rstrip(">., \t")
            if not sender_domain:
                m2 = re.search(r"@([a-zA-Z0-9.\-]+)", str(parsed_data.get("headers", {}).get("return_path", "")))
                if m2:
                    sender_domain = m2.group(1).rstrip(">., \t")

            if sender_domain:
                d_geo = GeoIPResolver.resolve_domain(sender_domain)
                if d_geo.get("latitude") is not None:
                    origin_ip = d_geo.get("ip")
                    origin_geo = d_geo
                    parsed_data["origin_evidence"] = {
                        "ip": origin_ip,
                        "domain": sender_domain,
                        "source": f"Sender Domain Authority ({sender_domain})",
                        "confidence": "APPROXIMATE",
                        "note": d_geo.get("note", f"Geolocated from registered domain infrastructure: {sender_domain}")
                    }

        city_str = origin_geo.get("city") or ""
        country_str = origin_geo.get("country") or ""
        if city_str and country_str and city_str != "Unavailable" and country_str != "Unavailable":
            origin_loc = f"{city_str}, {country_str}"
        elif city_str and city_str != "Unavailable":
            origin_loc = city_str
        elif country_str and country_str != "Unavailable":
            origin_loc = country_str
        elif origin_geo.get("is_private") or origin_geo.get("status") == "INTERNAL_ENCLAVE":
            origin_loc = "Internal Enterprise Enclave"
        else:
            origin_loc = origin_geo.get("note") or "Unknown Location"

        if "headers" in parsed_data and isinstance(parsed_data["headers"], dict):
            parsed_data["headers"]["origin_ip"] = origin_ip
            parsed_data["headers"]["origin_location"] = origin_loc
            parsed_data["headers"]["origin_geo"] = origin_geo

        # 7. Safe Static Link Analysis (Zero SSRF)
        from .url_scanner import URLScanner
        scanned_links = URLScanner.scan_all(parsed_data.get("body", {}).get("links", []))

        # Build Consolidated Forensic Payload
        return {
            "forensic_hash": parsed_data.get("forensic_hash"),
            "parsed_at_utc": parsed_data.get("parsed_at_utc"),
            "is_pdf_export": parsed_data.get("is_pdf_export", False),
            "headers": parsed_data.get("headers"),
            "origin_ip": origin_ip,
            "origin_location": origin_loc,
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
                "scanned_links": scanned_links,
                "total_links": parsed_data.get("body", {}).get("total_links", 0),
                "attachments": parsed_data.get("attachments", [])
            }
        }
