"""
GeoIP & infrastructure enrichment engine.
All returned locations are network-level estimates and never person-level attribution.
"""

import ipaddress
import urllib.request
import json
from typing import Dict, Any, Optional

class GeoIPResolver:
    """Enriches IP addresses with geographic and network telemetry."""

    # In-memory cache to prevent redundant lookups
    CACHE: Dict[str, Dict[str, Any]] = {}

    # Known Tor exit nodes / Bulletproof host prefixes (sample list for offline detection)
    KNOWN_TOR_IPS = {"185.220.101.5", "185.220.101.6", "185.220.101.7", "198.98.56.12", "199.249.230.88"}
    KNOWN_HOSTING_ASNS = {"AS14061": "DigitalOcean", "AS16509": "Amazon AWS", "AS24940": "Hetzner", "AS16276": "OVH", "AS63949": "Linode"}

    @classmethod
    def resolve(cls, ip: Optional[str]) -> Dict[str, Any]:
        """Resolves an IP to full geographic and ASN telemetry."""
        if not ip:
            return cls._empty_geo("No IP provided")

        if ip in cls.CACHE:
            return cls.CACHE[ip]

        # Check private / bogon
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                res = cls._empty_geo("Private / Internal Network IP (RFC 1918)", is_private=True)
                cls.CACHE[ip] = res
                return res
        except ValueError:
            return cls._empty_geo(f"Invalid IP format: {ip}")

        # Attempt resolution through an HTTPS endpoint.
        geo_data = cls._query_ip_api(ip)
        if not geo_data:
            geo_data = cls._unavailable_geo(ip, "Live GeoIP lookup was unavailable")

        # Anonymity & Infrastructure Checks
        is_tor = ip in cls.KNOWN_TOR_IPS
        asn_str = geo_data.get("asn", "")
        is_cloud = any(asn_id in asn_str for asn_id in cls.KNOWN_HOSTING_ASNS)

        geo_data["is_tor"] = is_tor
        geo_data["is_cloud_hosting"] = is_cloud
        geo_data["is_suspicious_infra"] = bool(is_tor or ("vpn" in geo_data.get("isp", "").lower()))

        cls.CACHE[ip] = geo_data
        return geo_data

    @classmethod
    def _query_ip_api(cls, ip: str) -> Optional[Dict[str, Any]]:
        """Queries public geolocation endpoint."""
        url = f"https://ipwho.is/{ip}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TRACE-MAIL-AI/1.0"})
            with urllib.request.urlopen(req, timeout=1.8) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get("success") is True:
                    connection = data.get("connection") or {}
                    lat = data.get("latitude")
                    lon = data.get("longitude")
                    loc = f"{lat},{lon}" if lat is not None and lon is not None else None
                    org = connection.get("org", "Unknown Org")
                    return {
                        "ip": ip,
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("country_code", "XX"),
                        "region": data.get("region", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "latitude": lat,
                        "longitude": lon,
                        "lat": lat,
                        "lon": lon,
                        "loc": loc,
                        "org": org,
                        "isp": connection.get("isp", "Unknown ISP"),
                        "organization": org,
                        "asn": f"AS{connection.get('asn')}" if connection.get("asn") else "Unknown ASN",
                        "is_private": False,
                        "status": "RESOLVED",
                        "source": "ipwho.is",
                        "confidence": "APPROXIMATE",
                        "note": "GeoIP describes registered network infrastructure and may be inaccurate or affected by proxies/VPNs."
                    }
        except Exception:
            pass
        return None

    @classmethod
    def _unavailable_geo(cls, ip: str, note: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "country": "Unavailable",
            "country_code": "--",
            "region": "Unavailable",
            "city": "Unavailable",
            "latitude": None,
            "longitude": None,
            "lat": None,
            "lon": None,
            "loc": None,
            "org": "Unavailable",
            "isp": "Unavailable",
            "organization": "Unavailable",
            "asn": "Unavailable",
            "is_private": False,
            "is_tor": ip in cls.KNOWN_TOR_IPS,
            "is_cloud_hosting": False,
            "is_suspicious_infra": ip in cls.KNOWN_TOR_IPS,
            "status": "UNAVAILABLE",
            "source": "No live source",
            "confidence": "NONE",
            "note": note
        }

    @classmethod
    def _empty_geo(cls, note: str, is_private: bool = False) -> Dict[str, Any]:
        return {
            "ip": None,
            "country": "Internal / Unknown",
            "country_code": "--",
            "region": "Internal",
            "city": note,
            "latitude": None,
            "longitude": None,
            "lat": None,
            "lon": None,
            "loc": None,
            "org": "Internal Network",
            "isp": "Local Relay",
            "organization": "Internal Network",
            "asn": "Private",
            "is_private": is_private,
            "is_tor": False,
            "is_cloud_hosting": False,
            "is_suspicious_infra": False,
            "status": "INTERNAL",
            "source": "Local address classification",
            "confidence": "NOT_APPLICABLE",
            "note": note
        }
