"""
Safe Static URL Security Scanner.
Inspects email URLs statically for phishing, punycode homographs, IP-literals,
embedded credentials, suspicious TLDs, and internal SSRF probes.
NEVER triggers outbound network connections to attacker-supplied URLs.
"""

import ipaddress
import re
from urllib.parse import urlparse
from typing import Dict, Any, List

class URLScanner:
    """Safe, zero-request static URL analysis engine."""

    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".buzz", ".work", ".cam", ".click", ".link", ".rest",
        ".country", ".quest", ".monster", ".sbs", ".icu"
    }

    KNOWN_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly",
        "ow.ly", "rb.gy", "cutt.ly", "rebrand.ly", "v.gd", "clck.ru"
    }

    DANGEROUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".hta", ".vbs", ".iso", ".img",
        ".dll", ".cmd", ".ps1", ".jar", ".docm", ".xlsm"
    }

    # Cloud metadata and internal probe targets
    CLOUD_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}

    @classmethod
    def scan_all(cls, urls: List[str]) -> List[Dict[str, Any]]:
        """Scans a list of URLs safely with static inspection."""
        results = []
        for u in urls[:30]:  # Bound processing
            results.append(cls.scan_single(u))
        return results

    @classmethod
    def scan_single(cls, url_str: str) -> Dict[str, Any]:
        """Statically inspects a single URL without outgoing HTTP requests."""
        # 1. De-obfuscate common defanging notation
        clean = (
            url_str.replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace("[@]", "@")
            .replace("[at]", "@")
            .strip()
        )

        if not clean.startswith(("http://", "https://")):
            clean = "http://" + clean

        parsed = urlparse(clean)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        port = parsed.port

        risk_reasons = []
        is_suspicious = False
        is_ip_literal = False
        is_internal_or_ssrf = False
        is_punycode = False
        is_shortener = False

        # 2. Check for embedded credentials in authority (e.g. http://google.com@phishingsite.com)
        if "@" in parsed.netloc:
            is_suspicious = True
            risk_reasons.append("Credential / authority spoofing using '@' separator in URL")

        # 3. Check IP literals and SSRF indicators
        if hostname:
            try:
                ip_obj = ipaddress.ip_address(hostname)
                is_ip_literal = True
                if hostname in cls.CLOUD_METADATA_IPS:
                    is_suspicious = True
                    is_internal_or_ssrf = True
                    risk_reasons.append("CRITICAL: Cloud metadata IP probe (SSRF target)")
                elif ip_obj.is_loopback:
                    is_suspicious = True
                    is_internal_or_ssrf = True
                    risk_reasons.append("Loopback IP target (127.0.0.1 / localhost SSRF)")
                elif ip_obj.is_private:
                    is_suspicious = True
                    is_internal_or_ssrf = True
                    risk_reasons.append(f"Private RFC 1918 internal IP address target ({hostname})")
                elif ip_obj.is_reserved or ip_obj.is_multicast:
                    is_suspicious = True
                    risk_reasons.append("Reserved / multicast IP target")
                else:
                    is_suspicious = True
                    risk_reasons.append("Raw IP address used instead of valid hostname")
            except ValueError:
                is_ip_literal = False

        # 4. Check Punycode / IDN Homograph attacks
        if "xn--" in hostname:
            is_punycode = True
            is_suspicious = True
            risk_reasons.append(f"Internationalized Punycode homograph domain detected ({hostname})")

        # 5. Check URL shorteners
        if hostname in cls.KNOWN_SHORTENERS:
            is_shortener = True
            is_suspicious = True
            risk_reasons.append(f"URL shortener hides ultimate destination ({hostname})")

        # 6. Check Suspicious TLDs
        for tld in cls.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                is_suspicious = True
                risk_reasons.append(f"High-abuse top-level domain ({tld})")
                break

        # 7. Check for direct payload download extensions
        lower_path = path.lower()
        for ext in cls.DANGEROUS_EXTENSIONS:
            if lower_path.endswith(ext):
                is_suspicious = True
                risk_reasons.append(f"Direct link to executable / weaponized payload ({ext})")
                break

        # 8. Obfuscated length heuristics
        if len(clean) > 250:
            risk_reasons.append("Unusually long URL (>250 chars), possible token smuggling or tracking payload")

        return {
            "original": url_str,
            "normalized": clean,
            "hostname": hostname,
            "scheme": parsed.scheme,
            "port": port,
            "is_ip_literal": is_ip_literal,
            "is_internal_or_ssrf": is_internal_or_ssrf,
            "punycode": is_punycode,
            "is_shortener": is_shortener,
            "suspicious": is_suspicious,
            "risk_reasons": risk_reasons,
            "redirects": 0,  # Zero active redirects followed (safe static analysis)
            "inspection_method": "STATIC_SAFE_INSPECTION_NO_SSRF"
        }
