"""
Authentication evidence interpreter.
Reads receiver-reported SPF/DKIM/DMARC results and labels their provenance.
"""

import re
from typing import Dict, Any, List, Optional
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

class AuthValidator:
    """Evaluates cryptographic email authentication and domain alignment."""

    def __init__(self, headers: Dict[str, Any]):
        self.headers = headers
        self.from_header = headers.get("from", "")
        self.from_domain = self._extract_domain(self.from_header)

    def audit(self) -> Dict[str, Any]:
        """Runs complete authentication audit."""
        spf_info = self._audit_spf()
        dkim_info = self._audit_dkim()
        dmarc_info = self._audit_dmarc(spf_info, dkim_info)
        dns_policies = self._query_dns_records(self.from_domain)

        # Determine composite authentication status
        passed = (
            (spf_info.get("status") == "PASS" and dmarc_info.get("spf_aligned")) or
            (dkim_info.get("status") == "PASS" and dmarc_info.get("dkim_aligned"))
        )

        overall_verdict = "REPORTED_PASS" if passed else "REPORTED_FAIL"
        if spf_info.get("status") == "NONE" and dkim_info.get("status") == "NONE":
            overall_verdict = "UNVERIFIED"

        return {
            "overall_status": overall_verdict,
            "sender_domain": self.from_domain,
            "spf": spf_info,
            "dkim": dkim_info,
            "dmarc": dmarc_info,
            "dns_published_policies": dns_policies
            ,"trust_notice": (
                "Statuses are parsed from Authentication-Results/Received-SPF headers. "
                "This prototype does not independently replay SPF or verify the DKIM signature."
            )
        }

    def _extract_domain(self, email_str: str) -> str:
        """Extracts the domain portion from an email address or header."""
        match = re.search(r'@([a-zA-Z0-9.\-_]+)', email_str)
        if match:
            return match.group(1).lower().strip('>')
        return ""

    def _audit_spf(self) -> Dict[str, Any]:
        """Extracts SPF authentication status and domain."""
        auth_results = " ".join(self.headers.get("authentication_results", []))
        rec_spf = " ".join(self.headers.get("received_spf", []))
        combined = (auth_results + " " + rec_spf).lower()

        status = "NONE"
        details = "No SPF verification header present."
        spf_domain = ""

        match = re.search(r'\bspf=([a-z]+)', combined)
        if match:
            status = match.group(1).upper()
            details = f"Authentication-Results header reports SPF={status}."
        elif "pass" in rec_spf.lower():
            status = "PASS"
            details = "Received-SPF header reports PASS."
        elif "fail" in rec_spf.lower():
            status = "FAIL"
            details = "Received-SPF header reports FAIL."

        # Extract domain/sender evaluated in SPF
        dom_match = re.search(r'smtp\.mailfrom=([^\s;]+)', combined) or re.search(r'envelope-from=([^\s;]+)', combined)
        if dom_match:
            spf_domain = self._extract_domain(dom_match.group(1)) or dom_match.group(1).lower()

        return {
            "status": status,
            "evaluated_domain": spf_domain,
            "details": details,
            "evidence_source": "Message authentication headers",
            "independently_verified": False
        }

    def _audit_dkim(self) -> Dict[str, Any]:
        """Extracts DKIM signature verification status, selector, and domain."""
        auth_results = " ".join(self.headers.get("authentication_results", []))
        dkim_sigs = self.headers.get("dkim_signatures", [])
        combined = auth_results.lower()

        status = "NONE"
        details = "No DKIM verification record found."
        dkim_domain = ""
        selector = ""

        match = re.search(r'\bdkim=([a-z]+)', combined)
        if match:
            status = match.group(1).upper()
            details = f"Authentication-Results header reports DKIM={status}."

        # Parse DKIM-Signature header if available
        if dkim_sigs:
            first_sig = dkim_sigs[0]
            d_match = re.search(r'\bd=([^\s;]+)', first_sig)
            s_match = re.search(r'\bs=([^\s;]+)', first_sig)
            if d_match:
                dkim_domain = d_match.group(1).lower()
            if s_match:
                selector = s_match.group(1).lower()
            if status == "NONE":
                status = "PRESENT"
                details = f"DKIM signature present (d={dkim_domain}, s={selector})."

        return {
            "status": status,
            "signature_domain": dkim_domain,
            "selector": selector,
            "details": details,
            "evidence_source": "Message authentication headers",
            "independently_verified": False
        }

    def _audit_dmarc(self, spf_info: Dict[str, Any], dkim_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validates DMARC alignment between From: domain and SPF/DKIM domains."""
        auth_results = " ".join(self.headers.get("authentication_results", [])).lower()

        dmarc_status = "NONE"
        match = re.search(r'\bdmarc=([a-z]+)', auth_results)
        if match:
            dmarc_status = match.group(1).upper()

        # Check Alignment
        from_dom = self.from_domain
        spf_dom = spf_info.get("evaluated_domain", "")
        dkim_dom = dkim_info.get("signature_domain", "")

        spf_aligned = bool(from_dom and spf_dom and (from_dom == spf_dom or from_dom.endswith("." + spf_dom) or spf_dom.endswith("." + from_dom)))
        dkim_aligned = bool(from_dom and dkim_dom and (from_dom == dkim_dom or from_dom.endswith("." + dkim_dom) or dkim_dom.endswith("." + from_dom)))

        return {
            "status": dmarc_status,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "aligned_from_domain": from_dom,
            "details": f"Header-reported DMARC: {dmarc_status} (SPF aligned: {spf_aligned}, DKIM aligned: {dkim_aligned})",
            "evidence_source": "Authentication-Results header",
            "independently_verified": False
        }

    def _query_dns_records(self, domain: str) -> Dict[str, Any]:
        """Queries public DNS for SPF and DMARC TXT records."""
        if not DNS_AVAILABLE or not domain:
            return {"spf_record": None, "dmarc_record": None, "dns_query_status": "DNS_NOT_AVAILABLE"}

        spf_rec = None
        dmarc_rec = None
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 1.5

        try:
            answers = resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_str = rdata.to_text().strip('"')
                if "v=spf1" in txt_str:
                    spf_rec = txt_str
                    break
        except Exception:
            spf_rec = None

        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in dmarc_answers:
                txt_str = rdata.to_text().strip('"')
                if "v=DMARC1" in txt_str:
                    dmarc_rec = txt_str
                    break
        except Exception:
            dmarc_rec = None

        return {
            "spf_record": spf_rec,
            "dmarc_record": dmarc_rec,
            "dns_query_status": "OK" if (spf_rec or dmarc_rec) else "NO_RECORDS"
        }
