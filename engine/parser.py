"""
RFC 5322 / MIME Email Parser & Hop Unroller
Extracts envelope metadata, authentication headers, chronological relay hops,
embedded URLs, attachments, and computes SHA-256 forensic fingerprints.
Preserves the exact submitted bytes for evidence hashing.
"""

import email
import email.policy
from email.utils import parsedate_to_datetime
import hashlib
import re
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union

class EmailParser:
    """Parses raw email data (.eml or string) into a structured forensic object."""

    IPV4_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    IPV6_PATTERN = re.compile(r'\[(?:IPv6:)?([0-9a-fA-F:]+)\]|\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\b')
    URL_PATTERN = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')

    @classmethod
    def _extract_ip_candidates(cls, text: str) -> List[str]:
        """Extracts valid IPv4 and IPv6 addresses from text in order of appearance."""
        if not text:
            return []
        found_ips: List[str] = []
        for m in cls.IPV4_PATTERN.findall(text):
            try:
                ip = ipaddress.ip_address(m)
                found_ips.append(str(ip))
            except ValueError:
                pass
        for m in cls.IPV6_PATTERN.finditer(text):
            cand = m.group(1) or m.group(2)
            if cand and ':' in cand:
                try:
                    ip = ipaddress.ip_address(cand)
                    if isinstance(ip, ipaddress.IPv6Address):
                        found_ips.append(str(ip))
                except ValueError:
                    pass
        return found_ips

    def __init__(self, raw_content: Union[str, bytes]):
        self.raw_bytes = raw_content if isinstance(raw_content, bytes) else raw_content.encode('utf-8')
        self.sha256_hash = hashlib.sha256(self.raw_bytes).hexdigest()
        self.is_pdf_export = False

        if self.raw_bytes.startswith(b"%PDF"):
            self.is_pdf_export = True
            extracted_text = self._extract_text_from_pdf(self.raw_bytes)
            self.raw_content = extracted_text
        else:
            self.raw_content = self.raw_bytes.decode('utf-8', errors='replace')

        sanitized = self._sanitize_raw_text(self.raw_content)
        self.msg = email.message_from_string(sanitized, policy=email.policy.default)

    @classmethod
    def _extract_text_from_pdf(cls, pdf_bytes: bytes) -> str:
        """Extracts text and structures email headers from mobile PDF email printouts/exports."""
        try:
            import pypdf
            import io
            reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
            pages_text = []
            for p in reader.pages:
                t = p.extract_text()
                if t:
                    pages_text.append(t)
            full_text = "\n".join(pages_text).strip()

            lines = full_text.splitlines()
            reconstructed_headers = []
            body_lines = []
            in_header_block = True
            found_any_header = False

            common_headers = {
                "from", "to", "subject", "date", "reply-to", "cc", "bcc", "sent",
                "received", "x-originating-ip", "authentication-results", "dkim-signature",
                "return-path", "received-spf", "arc-authentication-results", "message-id",
                "x-mailer", "mime-version", "content-type"
            }
            for line in lines:
                line_stripped = line.strip()
                if in_header_block:
                    m = re.match(r"^([A-Za-z\-]+):\s*(.*)$", line_stripped)
                    if m and m.group(1).lower() in common_headers:
                        hdr_name = m.group(1)
                        if hdr_name.lower() == "sent":
                            hdr_name = "Date"
                        reconstructed_headers.append(f"{hdr_name}: {m.group(2)}")
                        found_any_header = True
                    elif found_any_header and not line_stripped:
                        in_header_block = False
                    elif found_any_header and not m:
                        in_header_block = False
                        body_lines.append(line)
                    else:
                        body_lines.append(line)
                else:
                    body_lines.append(line)

            if found_any_header:
                return "\n".join(reconstructed_headers) + "\n\n" + "\n".join(body_lines)

            # If no labeled headers, look for sender email in first few lines
            for i in range(min(12, len(lines))):
                email_match = re.search(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", lines[i])
                if email_match:
                    sender_email = email_match.group(1)
                    return f"From: {sender_email}\nSubject: Mobile PDF Email Export\n\n" + full_text

            return full_text
        except Exception:
            return ""

    @staticmethod
    def _sanitize_raw_text(text: str) -> str:
        """
        Sanitizes raw email text to fix copy-paste anomalies:
        - Strips markdown code fences (```email, ```text, ```)
        - Strips leading blank lines before the headers
        - Un-indents indented headers (e.g. '    To:', '    Subject:') so RFC 5322 does not fold them
        """
        lines = text.splitlines()
        
        # 1. Drop leading markdown code blocks or blank lines
        while lines and (lines[0].strip().startswith("```") or not lines[0].strip()):
            lines.pop(0)
            
        # 2. Drop trailing markdown fences or whitespace
        while lines and (lines[-1].strip().startswith("```") or not lines[-1].strip()):
            lines.pop(-1)

        # 3. Un-indent headers in the header section
        processed = []
        in_headers = True
        header_start_pattern = re.compile(r"^\s*([A-Za-z][A-Za-z0-9\-]*):(\s*.*)$")

        for line in lines:
            if in_headers:
                if not line.strip():
                    in_headers = False
                    processed.append("")
                    continue
                m = header_start_pattern.match(line)
                if m:
                    processed.append(f"{m.group(1)}:{m.group(2)}")
                else:
                    processed.append(line)
            else:
                processed.append(line)

        return "\n".join(processed)

    def parse(self) -> Dict[str, Any]:
        headers = self._extract_headers()
        hops = self._extract_hops()
        body_data = self._extract_body_and_links()
        attachments = self._extract_attachments()

        origin_evidence = self._determine_origin_candidate(hops)

        return {
            "forensic_hash": self.sha256_hash,
            "parsed_at_utc": datetime.now(timezone.utc).isoformat(),
            "is_pdf_export": getattr(self, "is_pdf_export", False),
            "headers": headers,
            "origin_ip": origin_evidence.get("ip"),
            "origin_evidence": origin_evidence,
            "hops": hops,
            "total_hops": len(hops),
            "body": body_data,
            "attachments": attachments
        }

    def _extract_headers(self) -> Dict[str, Any]:
        """Extracts standard and authentication headers."""
        return {
            "from": str(self.msg.get("From", "")),
            "to": str(self.msg.get("To", "")),
            "subject": str(self.msg.get("Subject", "(No Subject)")),
            "date": str(self.msg.get("Date", "")),
            "message_id": str(self.msg.get("Message-ID", "")),
            "reply_to": str(self.msg.get("Reply-To", "")),
            "return_path": str(self.msg.get("Return-Path", "")),
            "authentication_results": self.msg.get_all("Authentication-Results", []),
            "received_spf": self.msg.get_all("Received-SPF", []),
            "dkim_signatures": self.msg.get_all("DKIM-Signature", []),
            "x_originating_ip": str(self.msg.get("X-Originating-IP", "")),
            "x_mailer": str(self.msg.get("X-Mailer", ""))
        }

    def _extract_hops(self) -> List[Dict[str, Any]]:
        """
        Extracts all Received: headers and unrolls them into chronological order.
        Note: The top-most Received header is the last hop; the bottom-most is Hop #1 (origin).
        """
        raw_received = self.msg.get_all("Received", [])
        if not raw_received:
            return []

        # Reverse to get chronological sequence (Hop 1 = Origin, Hop N = Destination Gateway)
        chronological_received = list(reversed(raw_received))
        hops = []

        for idx, rec in enumerate(chronological_received, start=1):
            hop_info = self._parse_single_received_header(str(rec), idx)
            hops.append(hop_info)

        return hops

    def _parse_single_received_header(self, header_str: str, hop_index: int) -> Dict[str, Any]:
        """Parses a single Received header line into IP, MTA domains, protocol, and timestamp."""
        clean_text = " ".join(header_str.split())

        # Specific source IP extraction: prefer the IP inside the 'from ... [IP]' clause
        from_clause_match = re.search(r'\bfrom\b(.*?)(?:\bby\b|;|$)', clean_text, re.IGNORECASE)
        source_clause_text = from_clause_match.group(1) if from_clause_match else clean_text
        source_ips = self._extract_ip_candidates(source_clause_text)

        source_candidate_ip = None
        for ip in source_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local):
                    source_candidate_ip = ip
                    break
            except ValueError:
                continue

        if source_candidate_ip:
            candidate_ip = source_candidate_ip
            hop_confidence = "HIGH"
        else:
            found_ips = self._extract_ip_candidates(clean_text)
            candidate_ip = None
            for ip in found_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local):
                        candidate_ip = ip
                        break
                except ValueError:
                    continue
            if candidate_ip:
                hop_confidence = "MEDIUM"
            elif found_ips:
                candidate_ip = found_ips[0]
                hop_confidence = "LOW"
            else:
                candidate_ip = None
                hop_confidence = "UNVERIFIED"

        # Extract From and By MTAs
        from_mta = "Unknown"
        by_mta = "Unknown"
        
        from_match = re.search(r'\bfrom\s+([^\s;()]+)', clean_text, re.IGNORECASE)
        if from_match:
            from_mta = from_match.group(1).strip()

        by_match = re.search(r'\bby\s+([^\s;()]+)', clean_text, re.IGNORECASE)
        if by_match:
            by_mta = by_match.group(1).strip()

        # Extract Protocol (e.g. ESMTP, SMTP, ESMTPS)
        proto_match = re.search(r'\bwith\s+([^\s;()]+)', clean_text, re.IGNORECASE)
        protocol = proto_match.group(1).upper() if proto_match else "SMTP"

        # Extract Timestamp (usually after the last semicolon)
        timestamp_str = None
        parsed_dt = None
        iso_timestamp = None

        if ';' in clean_text:
            raw_ts = clean_text.split(';')[-1].strip()
            raw_ts = re.sub(r'\(.*?\)', '', raw_ts).strip()
            try:
                parsed_dt = parsedate_to_datetime(raw_ts)
                if parsed_dt:
                    iso_timestamp = parsed_dt.astimezone(timezone.utc).isoformat()
                    timestamp_str = raw_ts
            except Exception:
                timestamp_str = raw_ts

        is_pub = False
        if candidate_ip:
            try:
                ip_obj = ipaddress.ip_address(candidate_ip)
                is_pub = not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
            except ValueError:
                is_pub = False

        return {
            "hop_number": hop_index,
            "ip": candidate_ip,
            "confidence": hop_confidence,
            "from_mta": from_mta,
            "by_mta": by_mta,
            "protocol": protocol,
            "raw_timestamp": timestamp_str,
            "timestamp_iso": iso_timestamp,
            "is_public_ip": is_pub,
            "raw_header": header_str[:500] + ("..." if len(header_str) > 500 else "")
        }

    def _determine_origin_candidate(self, hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Returns a candidate source IP with an explicit evidence limitation."""
        x_orig = str(self.msg.get("X-Originating-IP", ""))
        ips = self._extract_ip_candidates(x_orig)
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local):
                    return {
                        "ip": ip,
                        "source": "X-Originating-IP header",
                        "confidence": "LOW",
                        "note": "This header can be absent or sender-controlled and requires independent corroboration."
                    }
            except ValueError:
                pass

        for hop in hops:
            if hop.get("ip") and hop.get("is_public_ip"):
                return {
                    "ip": hop["ip"],
                    "source": f"Earliest public IP observed in Received header #{hop['hop_number']}",
                    "confidence": hop.get("confidence", "MEDIUM"),
                    "note": "This identifies mail transfer infrastructure (MTA relay), not a personal handheld device."
                }

        if hops and hops[0].get("ip"):
            return {
                "ip": hops[0]["ip"],
                "source": "Earliest Received header",
                "confidence": "LOW",
                "note": "Only a private or internal gateway relay address was recorded."
            }

        # If no hop IP, inspect message content/telemetry for public candidate IPs
        content_ips = self._extract_ip_candidates(self.raw_content)
        for c_ip in content_ips:
            try:
                ip_obj = ipaddress.ip_address(c_ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local):
                    return {
                        "ip": c_ip,
                        "source": "Message Telemetry / In-Text IP Indicator",
                        "confidence": "CORROBORATED",
                        "note": f"Public IP {c_ip} identified from message telemetry/content."
                    }
            except ValueError:
                pass

        if getattr(self, "is_pdf_export", False) and not hops:
            return {
                "ip": None,
                "source": "Mobile PDF Visual Printout",
                "confidence": "VISUAL_SNAPSHOT",
                "note": "Sender transit hops unavailable: this visual PDF printout does not contain original RFC 5322 Received routing headers. Physical origin geolocated from registered sender domain authority."
            }

        return {
            "ip": None,
            "source": "No candidate available",
            "confidence": "NONE",
            "note": "No public source infrastructure could be extracted from the submitted headers."
        }

    def _extract_body_and_links(self) -> Dict[str, Any]:
        """Extracts text content and all HTTP/HTTPS links."""
        plain_text = ""
        html_text = ""

        if self.msg.is_multipart():
            for part in self.msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition', ''))
                if 'attachment' not in cdispo:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            decoded = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                            if ctype == 'text/plain':
                                plain_text += decoded + "\n"
                            elif ctype == 'text/html':
                                html_text += decoded + "\n"
                    except Exception:
                        pass
        else:
            payload = self.msg.get_payload(decode=True)
            if payload:
                decoded = payload.decode(self.msg.get_content_charset() or 'utf-8', errors='replace')
                if self.msg.get_content_type() == 'text/html':
                    html_text = decoded
                else:
                    plain_text = decoded

        combined_text = plain_text + " " + html_text
        found_links = list(set(self.URL_PATTERN.findall(combined_text)))

        extracted_plain = plain_text.strip()
        # Fall back to stripped HTML if no text/plain body was provided (critical for HTML-only phishing & ML inference)
        if not extracted_plain and html_text.strip():
            clean_html = re.sub(r'<style[^>]*>.*?</style>', ' ', html_text, flags=re.DOTALL | re.IGNORECASE)
            clean_html = re.sub(r'<script[^>]*>.*?</script>', ' ', clean_html, flags=re.DOTALL | re.IGNORECASE)
            clean_html = re.sub(r'<[^>]+>', ' ', clean_html)
            clean_html = " ".join(clean_html.split())
            extracted_plain = clean_html

        return {
            "plain_text": extracted_plain,
            "has_html": bool(html_text),
            "links": found_links,
            "total_links": len(found_links)
        }

    def _extract_attachments(self) -> List[Dict[str, Any]]:
        """Extracts metadata of attached files."""
        attachments = []
        if self.msg.is_multipart():
            for part in self.msg.walk():
                cdispo = str(part.get('Content-Disposition', ''))
                if 'attachment' in cdispo or part.get_filename():
                    fname = part.get_filename() or "unnamed_attachment"
                    payload = part.get_payload(decode=True) or b""
                    attachments.append({
                        "filename": fname,
                        "content_type": part.get_content_type(),
                        "size_bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest() if payload else None
                    })
        return attachments
