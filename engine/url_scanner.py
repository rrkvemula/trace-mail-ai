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

    # Zero-width / invisible characters used to break tokenization and regex matching
    ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad', '\u200e', '\u200f'}

    # UTS-39 prototype homoglyphs mapping to canonical Latin ASCII
    CONFUSABLE_MAP = {
        # Cyrillic homoglyphs
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's',
        'А': 'a', 'В': 'b', 'С': 'c', 'Е': 'e', 'Н': 'h', 'І': 'i', 'Ј': 'j', 'К': 'k', 'М': 'm', 'О': 'o',
        'Р': 'p', 'Ѕ': 's', 'Т': 't', 'Х': 'x', 'Ү': 'y', 'ԛ': 'q', 'ԝ': 'w',
        # Greek homoglyphs
        'α': 'a', 'β': 'b', 'γ': 'g', 'ε': 'e', 'η': 'h', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p',
        'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'Ο': 'o', 'Ρ': 'p', 'Τ': 't',
        # Fullwidth ASCII (FF01-FF5E)
        'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i',
        'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r',
        'ｓ': 's', 'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z'
    }

    PROTECTED_BRAND_DOMAINS = {
        "google.com", "microsoft.com", "apple.com", "paypal.com", "amazon.com",
        "netflix.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
        "citibank.com", "unstop.com", "tata.com", "github.com", "linkedin.com",
        "facebook.com", "instagram.com", "whatsapp.com", "dropbox.com", "docusign.com"
    }

    @classmethod
    def _is_mixed_script(cls, label: str) -> bool:
        """RFC 5890: Checks if a single domain label mixes Latin characters with non-Latin scripts (e.g. Cyrillic or Greek)."""
        import unicodedata
        scripts = set()
        for ch in label.lower():
            if ch.isalnum():
                o = ord(ch)
                if o <= 0x024F:  # ASCII, Latin-1 Supplement, Latin Extended-A & B
                    scripts.add("LATIN")
                else:
                    name = unicodedata.name(ch, "")
                    if "CYRILLIC" in name:
                        scripts.add("CYRILLIC")
                    elif "GREEK" in name:
                        scripts.add("GREEK")
                    elif "ARABIC" in name:
                        scripts.add("ARABIC")
                    elif "HEBREW" in name:
                        scripts.add("HEBREW")
        return "LATIN" in scripts and any(s in scripts for s in ["CYRILLIC", "GREEK", "ARABIC", "HEBREW"])

    @classmethod
    def _get_skeleton(cls, text: str) -> str:
        """Converts Unicode text to Latin confusable skeleton (UTS-39)."""
        return "".join(cls.CONFUSABLE_MAP.get(ch, ch) for ch in text.lower())

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
        # 1. Detect zero-width characters and de-obfuscate common defanging notation
        has_invisible_chars = any(c in url_str for c in cls.ZERO_WIDTH_CHARS)
        clean = "".join(c for c in url_str if c not in cls.ZERO_WIDTH_CHARS)
        clean = (
            clean.replace("hxxps://", "https://")
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
        is_homoglyph_brand = False
        is_mixed_script = False
        impersonated_brand = None
        decoded_host = hostname
        skeleton_host = hostname

        if has_invisible_chars:
            is_suspicious = True
            risk_reasons.append("Zero-width or invisible Unicode characters detected in URL (obfuscation evasion)")

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

        # 4. Check Punycode / IDN Homograph & UTS-39 Confusable attacks
        if hostname:
            if "xn--" in hostname:
                is_punycode = True
                try:
                    import idna
                    decoded_host = idna.decode(hostname)
                except Exception:
                    decoded_host = hostname
            else:
                decoded_host = hostname

            skeleton_host = cls._get_skeleton(decoded_host)

            # Check UTS-39 Confusable Skeleton against Protected Brands
            for brand in cls.PROTECTED_BRAND_DOMAINS:
                if skeleton_host == brand or skeleton_host.endswith("." + brand):
                    if decoded_host != brand and not decoded_host.endswith("." + brand):
                        is_homoglyph_brand = True
                        impersonated_brand = brand
                        break

            # Check Mixed-Script Labels (RFC 5890 Violation)
            for label in decoded_host.split("."):
                if cls._is_mixed_script(label):
                    is_mixed_script = True
                    break

            if is_homoglyph_brand:
                is_suspicious = True
                risk_reasons.append(f"CRITICAL: Visual homoglyph impersonation of protected brand '{impersonated_brand}' (Skeleton: '{skeleton_host}', Encoded: '{hostname}')")
            elif is_mixed_script:
                is_suspicious = True
                risk_reasons.append(f"Mixed-script domain label detected ({decoded_host}); mixes Latin and non-Latin scripts (RFC 5890 violation)")
            elif is_punycode:
                # Legitimate whole-script IDN (e.g. münchen.de or authentic non-Latin domain)
                # Informational note without inflating risk score
                risk_reasons.append(f"Internationalized Domain Name (IDN: '{decoded_host}')")

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
            "is_homoglyph_brand": is_homoglyph_brand,
            "impersonated_brand": impersonated_brand,
            "is_mixed_script": is_mixed_script,
            "has_invisible_chars": has_invisible_chars,
            "decoded_hostname": decoded_host,
            "skeleton_hostname": skeleton_host,
            "is_shortener": is_shortener,
            "suspicious": is_suspicious,
            "risk_reasons": risk_reasons,
            "redirects": 0,  # Zero active redirects followed (safe static analysis)
            "inspection_method": "STATIC_SAFE_INSPECTION_NO_SSRF"
        }
