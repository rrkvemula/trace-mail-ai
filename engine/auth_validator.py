"""
Authentication evidence interpreter.
Evaluates receiver-reported SPF, DKIM, DMARC results and RFC 7489 alignment.
Distinguishes between PASS, explicit FAIL, and neutral/UNVERIFIED states.
Supports ESP bounce-relay awareness (SendGrid, Mailchimp, Amazon SES, Google Workspace).
"""

import re
from typing import Dict, Any, List, Optional

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class AuthValidator:
    """Evaluates cryptographic email authentication and domain alignment under RFC 7489."""

    # Recognized ESP bounce domains where Return-Path differs from From: but DKIM aligns
    KNOWN_ESP_DOMAINS = {
        "sendgrid.net", "sendgrid.info", "mailgun.org", "mailgun.net",
        "amazonses.com", "mcsv.net", "mcdlv.net", "mailchimpapp.net",
        "google.com", "googlemail.com", "outlook.com", "protection.outlook.com",
        "hubspot.com", "postmarkapp.com", "sparkpostmail.com", "mandrillapp.com"
    }

    def __init__(self, headers: Dict[str, Any]):
        self.headers = headers
        self.from_header = headers.get("from", "")
        self.return_path_header = headers.get("return_path", "")
        self.from_domain = self._extract_domain(self.from_header)
        self.return_path_domain = self._extract_domain(self.return_path_header)

    @staticmethod
    def _extract_domain(email_str: str) -> str:
        """Extracts the domain portion from an email address or header."""
        match = re.search(r'@([a-zA-Z0-9.\-_]+)', email_str or "")
        if match:
            return match.group(1).lower().strip('> \t\r\n')
        return ""

    @classmethod
    def get_organizational_domain(cls, domain: str) -> str:
        """
        Extracts the base organizational domain (e.g. bounce.email.github.com -> github.com).
        Handles common two-part public suffixes such as .co.uk, .gov.in, .edu.in.
        """
        if not domain:
            return ""
        parts = domain.lower().strip('.').split('.')
        if len(parts) <= 2:
            return ".".join(parts)

        two_part_suffixes = {
            "co.uk", "gov.in", "edu.in", "org.in", "ac.in", "nic.in",
            "res.in", "com.au", "co.jp", "com.br", "co.za"
        }
        if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_suffixes:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    def audit(self) -> Dict[str, Any]:
        """Runs complete authentication audit adhering to RFC 7489."""
        spf_info = self._audit_spf()
        dkim_info = self._audit_dkim()
        dmarc_info = self._audit_dmarc(spf_info, dkim_info)
        dns_policies = self._query_dns_records(self.from_domain)

        # RFC 7489 Section 4.2: DMARC passes if EITHER SPF aligns & passes OR DKIM aligns & passes
        spf_passed_and_aligned = (spf_info.get("status") == "PASS" and dmarc_info.get("spf_aligned", False))
        dkim_passed_and_aligned = (dkim_info.get("status") == "PASS" and dmarc_info.get("dkim_aligned", False))
        composite_pass = (
            dmarc_info.get("status") == "PASS" or
            spf_passed_and_aligned or
            dkim_passed_and_aligned
        )

        # Explicit failure vs unverified
        if composite_pass:
            overall_verdict = "REPORTED_PASS"
        elif dmarc_info.get("status") == "FAIL" or (spf_info.get("status") == "FAIL" and dkim_info.get("status") == "FAIL"):
            overall_verdict = "REPORTED_FAIL"
        elif spf_info.get("status") == "NONE" and dkim_info.get("status") == "NONE":
            overall_verdict = "UNVERIFIED"
        else:
            overall_verdict = "PARTIAL_OR_UNVERIFIED"

        return {
            "overall_status": overall_verdict,
            "sender_domain": self.from_domain,
            "from_organizational_domain": self.get_organizational_domain(self.from_domain),
            "spf": spf_info,
            "dkim": dkim_info,
            "dmarc": dmarc_info,
            "composite_pass": composite_pass,
            "is_unverified": overall_verdict == "UNVERIFIED",
            "dns_published_policies": dns_policies,
            "trust_notice": (
                "Statuses are parsed from Authentication-Results and Received-SPF headers under RFC 7489. "
                "Neutral or missing headers indicate unverified telemetry, not confirmed malice."
            )
        }

    def _audit_spf(self) -> Dict[str, Any]:
        """Extracts SPF authentication status and evaluated domain."""
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
        elif "softfail" in rec_spf.lower():
            status = "SOFTFAIL"
            details = "Received-SPF header reports SOFTFAIL."

        # Extract domain/sender evaluated in SPF
        dom_match = (
            re.search(r'smtp\.mailfrom=([^\s;]+)', combined) or
            re.search(r'envelope-from=([^\s;]+)', combined) or
            re.search(r'domain of ([^\s;]+)', combined)
        )
        if dom_match:
            raw_dom = dom_match.group(1).strip()
            spf_domain = self._extract_domain(raw_dom) or raw_dom.lower().strip('> ')
        elif self.return_path_domain:
            spf_domain = self.return_path_domain

        return {
            "status": status,
            "evaluated_domain": spf_domain,
            "details": details,
            "evidence_source": "Message authentication headers",
            "independently_verified": False
        }

    def _audit_dkim(self) -> Dict[str, Any]:
        """Extracts DKIM signature verification status, selector, and signing domain."""
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
            first_sig = str(dkim_sigs[0])
            d_match = re.search(r'\bd=([^\s;]+)', first_sig)
            s_match = re.search(r'\bs=([^\s;]+)', first_sig)
            if d_match:
                dkim_domain = d_match.group(1).lower().strip('"')
            if s_match:
                selector = s_match.group(1).lower().strip('"')
        # Also extract signing domain from Authentication-Results (header.d= or header.i=)
        if not dkim_domain:
            header_d = re.search(r'header\.d=([^\s;]+)', combined)
            if header_d:
                dkim_domain = header_d.group(1).lower().strip('"')
        if not dkim_domain:
            header_i = re.search(r'header\.i=@?([^\s;]+)', combined)
            if header_i:
                raw_i = header_i.group(1).lower().strip('"')
                dkim_domain = self._extract_domain(raw_i) or raw_i
        if not selector:
            header_s = re.search(r'header\.s=([^\s;]+)', combined)
            if header_s:
                selector = header_s.group(1).lower().strip('"')

        return {
            "status": status,
            "signature_domain": dkim_domain,
            "selector": selector,
            "details": details,
            "evidence_source": "Message authentication headers",
            "independently_verified": False
        }

    def _audit_dmarc(self, spf_info: Dict[str, Any], dkim_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validates DMARC alignment between From: domain and SPF/DKIM domains (RFC 7489)."""
        auth_results = " ".join(self.headers.get("authentication_results", [])).lower()

        dmarc_status = "NONE"
        match = re.search(r'\bdmarc=([a-z]+)', auth_results)
        if match:
            dmarc_status = match.group(1).upper()

        from_dom = self.from_domain
        from_org = self.get_organizational_domain(from_dom)

        spf_dom = spf_info.get("evaluated_domain", "")
        spf_org = self.get_organizational_domain(spf_dom)

        dkim_dom = dkim_info.get("signature_domain", "")
        dkim_org = self.get_organizational_domain(dkim_dom)

        # Relaxed alignment: Organizational domains match
        spf_aligned = bool(from_org and spf_org and from_org == spf_org)
        dkim_aligned = bool(from_org and dkim_org and from_org == dkim_org)

        # Strict alignment: Exact FQDN match
        spf_strict_aligned = bool(from_dom and spf_dom and from_dom == spf_dom)
        dkim_strict_aligned = bool(from_dom and dkim_dom and from_dom == dkim_dom)

        # Check for legitimate ESP relay pattern (e.g. From: co.com, Return-Path: bounces.sendgrid.net, DKIM: co.com)
        is_esp_relay = bool(
            spf_dom and any(esp in spf_dom for esp in self.KNOWN_ESP_DOMAINS) and
            dkim_aligned and dkim_info.get("status") == "PASS"
        )

        return {
            "status": dmarc_status,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "spf_strict_aligned": spf_strict_aligned,
            "dkim_strict_aligned": dkim_strict_aligned,
            "is_esp_relay": is_esp_relay,
            "aligned_from_domain": from_dom,
            "details": (
                f"Header DMARC: {dmarc_status} "
                f"(SPF aligned: {spf_aligned}, DKIM aligned: {dkim_aligned}, ESP relay: {is_esp_relay})"
            ),
            "evidence_source": "Authentication-Results header & RFC 7489 calculation",
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
