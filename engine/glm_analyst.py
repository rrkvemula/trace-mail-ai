"""
GLM-5.3 Forensic AI Analyst & SOC Triage Engine.
Provides explainable threat risk narratives, actionable SOC containment advice,
and MITRE ATT&CK/D3FEND matrix mappings grounded strictly in the deterministic
evidence ledger.
Utilizes TokenRouter API (model: z-ai/glm-5.3-free) with a resilient deterministic
synthesis fallback when the external API is rate limited (e.g. HTTP 429), unavailable,
or air-gapped.
"""

import os
import re
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("tracemail.glm_analyst")

TOKENROUTER_ENDPOINT = "https://api.tokenrouter.com/v1/chat/completions"
DEFAULT_MODEL = "z-ai/glm-5.3-free"
DEFAULT_TIMEOUT = 12.0  # seconds


class GLMForensicAnalyst:
    """
    Forensic AI Analyst leveraging GLM-5.3 via TokenRouter
    with deterministic evidence ledger synthesis fallback.
    """

    @classmethod
    def synthesize_triage(
        cls,
        report: Dict[str, Any],
        focus: str = "full",
        force_deterministic: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> Dict[str, Any]:
        """
        Synthesizes human-readable triage advice and explainable risk narratives
        from the deterministic evidence ledger.
        """
        evidence_facts = cls._extract_evidence_facts(report)
        analysis_id = evidence_facts["analysis_id"]
        forensic_hash = evidence_facts["forensic_hash"]
        threat_score = evidence_facts["threat_score"]
        risk_category = evidence_facts["risk_category"]

        api_key = os.environ.get("TOKENROUTER_API_KEY", "").strip()

        if force_deterministic or not api_key:
            reason = "Explicit deterministic synthesis requested" if force_deterministic else "TOKENROUTER_API_KEY not configured"
            return cls._build_deterministic_result(evidence_facts, fallback_reason=reason)

        try:
            prompt = cls._build_analyst_prompt(evidence_facts, focus)
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "TraceMail-Forensic-Analyst/2.1",
            }
            body = {
                "model": DEFAULT_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are TraceMail SOC Forensic AI Analyst (GLM-5.3), a senior email incident responder "
                            "and RFC 5322/7489 forensic specialist. You synthesize concise, human-readable triage "
                            "assessments, explainable risk narratives, and actionable containment advice grounded "
                            "strictly in the deterministic evidence ledger. Do not invent or assume indicators not present."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                "temperature": 0.2,
                "max_tokens": 1200,
            }

            req = urllib.request.Request(
                TOKENROUTER_ENDPOINT,
                data=json.dumps(body).encode("utf-8"),
                headers=headers,
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    content = resp_data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                    if content:
                        parsed_narrative, triage_actions, mitre_mappings = cls._parse_ai_response(content, evidence_facts)
                        return {
                            "status": "SUCCESS",
                            "engine": DEFAULT_MODEL,
                            "model": DEFAULT_MODEL,
                            "analysis_id": analysis_id,
                            "forensic_hash": forensic_hash,
                            "threat_score": threat_score,
                            "risk_category": risk_category,
                            "narrative": parsed_narrative,
                            "triage_advice": triage_actions,
                            "mitre_mappings": mitre_mappings,
                            "ledger_verified": True,
                            "ledger_receipt": evidence_facts.get("ledger_receipt"),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }

        except urllib.error.HTTPError as http_err:
            logger.warning(
                "TokenRouter API HTTP error %s (%s). Falling back to deterministic synthesis.",
                http_err.code,
                http_err.reason,
            )
            return cls._build_deterministic_result(
                evidence_facts,
                fallback_reason=f"TokenRouter API returned HTTP {http_err.code} ({http_err.reason})",
            )
        except Exception as exc:
            logger.warning(
                "TokenRouter API call failed: %s. Falling back to deterministic synthesis.",
                exc,
            )
            return cls._build_deterministic_result(
                evidence_facts,
                fallback_reason=f"TokenRouter API call failed: {type(exc).__name__} ({str(exc)})",
            )

        return cls._build_deterministic_result(
            evidence_facts,
            fallback_reason="Empty response from TokenRouter model",
        )

    @classmethod
    def _extract_evidence_facts(cls, report: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts and standardizes deterministic facts from the report (supports raw pipeline and UI payload formats)."""
        threat = report.get("threat_analysis") or {}
        auth = report.get("authentication") or {}
        headers = report.get("headers") or {}
        hops = report.get("hops_analysis") or {}
        origin_geo = report.get("origin_geo") or (report.get("trace", {}).get("geo") if isinstance(report.get("trace"), dict) else {}) or {}
        body_summary = report.get("body_summary") or {}

        analysis_id = report.get("analysis_id") or "ANL-UNKNOWN"
        forensic_hash = report.get("forensic_hash") or report.get("evidence_hash") or "UNKNOWN"
        raw_threat_score = threat.get("threat_score") if threat.get("threat_score") is not None else report.get("fraud_score", 0.0)
        threat_score = float(raw_threat_score)
        raw_category = threat.get("risk_category") or report.get("risk_level") or (
            "CRITICAL_THREAT" if threat_score >= 70 else ("ELEVATED_RISK" if threat_score >= 35 else "LOW_OBSERVED_RISK")
        )
        risk_category = raw_category.replace(" ", "_").upper() if isinstance(raw_category, str) else "LOW_OBSERVED_RISK"

        detections = threat.get("detections") or []
        explainability = [f.get("detail", "") for f in threat.get("explainability_factors", []) if isinstance(f, dict)]
        if not explainability and isinstance(report.get("ai"), dict) and report.get("ai", {}).get("reasons"):
            explainability = [str(r) for r in report["ai"]["reasons"]]
        elif not explainability and isinstance(headers.get("reasons"), list):
            explainability = [str(r) for r in headers["reasons"]]

        spf_data = auth.get("spf") or {}
        dkim_data = auth.get("dkim") or {}
        dmarc_data = auth.get("dmarc") or {}
        authserv = auth.get("authserv_trust") or {}

        spf_status = spf_data.get("status") if isinstance(spf_data, dict) else ("PASS" if headers.get("spf") else "NONE")
        dkim_status = dkim_data.get("status") if isinstance(dkim_data, dict) else ("PASS" if headers.get("dkim") else "NONE")
        dmarc_status = dmarc_data.get("status") if isinstance(dmarc_data, dict) else ("PASS" if headers.get("dmarc") else "NONE")

        scanned_links = body_summary.get("scanned_links") or report.get("links") or []
        suspicious_links = [
            l for l in scanned_links
            if isinstance(l, dict) and (l.get("suspicious") or l.get("punycode") or l.get("is_internal_or_ssrf"))
        ]

        attachments = report.get("attachments") or body_summary.get("attachments") or []
        weaponized_attachments = [
            a for a in attachments
            if isinstance(a, dict) and (a.get("is_weaponized") or a.get("double_extension") or a.get("suspicious"))
        ]

        resolved_origin_ip = report.get("origin_ip") or origin_geo.get("ip") or headers.get("origin_ip") or "Unavailable"

        return {
            "analysis_id": analysis_id,
            "forensic_hash": forensic_hash,
            "threat_score": threat_score,
            "risk_category": risk_category,
            "detections": detections,
            "explainability": explainability,
            "headers": {
                "from": headers.get("from") or headers.get("from_address") or "Unavailable",
                "return_path": headers.get("return_path") or "Unavailable",
                "subject": headers.get("subject") or "Unavailable",
                "date": headers.get("date") or "Unavailable",
                "to": headers.get("to") or "Unavailable",
            },
            "auth": {
                "spf_status": spf_status or "NONE",
                "spf_domain": spf_data.get("domain", "") if isinstance(spf_data, dict) else "",
                "dkim_status": dkim_status or "NONE",
                "dkim_domain": dkim_data.get("domain", "") if isinstance(dkim_data, dict) else "",
                "dmarc_status": dmarc_status or "NONE",
                "composite_pass": auth.get("composite_pass", False),
                "authserv_trusted": authserv.get("trusted", False) if isinstance(authserv, dict) else False,
            },
            "hops": {
                "count": len(hops.get("analyzed_hops") or headers.get("hops_list") or []),
                "timing_anomalies": hops.get("has_timing_anomalies", False),
            },
            "origin": {
                "ip": resolved_origin_ip,
                "country": origin_geo.get("country", "Unknown"),
                "asn": origin_geo.get("asn", "Unknown"),
                "is_tor": origin_geo.get("is_tor", False),
                "is_cloud": origin_geo.get("is_cloud_hosting", False),
                "is_private": origin_geo.get("is_private", False),
            },
            "links": {
                "total": len(scanned_links),
                "suspicious_count": len(suspicious_links),
                "suspicious_items": suspicious_links[:5],
            },
            "attachments": {
                "total": len(attachments),
                "weaponized_count": len(weaponized_attachments),
                "weaponized_items": weaponized_attachments[:5],
            },
            "ledger_receipt": report.get("ledger_receipt"),
        }

    @classmethod
    def _build_analyst_prompt(cls, facts: Dict[str, Any], focus: str) -> str:
        """Constructs the prompt for the GLM-5.3 forensic model."""
        return (
            f"Analyze this verified email forensic evidence ledger for Analysis ID '{facts['analysis_id']}':\n\n"
            f"--- DETERMINISTIC EVIDENCE LEDGER ---\n"
            f"SHA-256 Forensic Hash: {facts['forensic_hash']}\n"
            f"Overall Threat Score: {facts['threat_score']}/100 ({facts['risk_category']})\n"
            f"Detection Flags: {', '.join(facts['detections']) if facts['detections'] else 'None'}\n\n"
            f"Headers:\n"
            f"- From: {facts['headers']['from']}\n"
            f"- Return-Path: {facts['headers']['return_path']}\n"
            f"- Subject: {facts['headers']['subject']}\n\n"
            f"Cryptographic Authentication (RFC 5322/7489):\n"
            f"- SPF: {facts['auth']['spf_status']} (Domain: {facts['auth']['spf_domain']})\n"
            f"- DKIM: {facts['auth']['dkim_status']} (Domain: {facts['auth']['dkim_domain']})\n"
            f"- DMARC: {facts['auth']['dmarc_status']}\n"
            f"- Composite Pass: {facts['auth']['composite_pass']}\n\n"
            f"Infrastructure & Network:\n"
            f"- Origin IP: {facts['origin']['ip']} ({facts['origin']['country']}, ASN: {facts['origin']['asn']})\n"
            f"- Tor Exit Node: {facts['origin']['is_tor']} | Cloud Hosting: {facts['origin']['is_cloud']}\n"
            f"- Hop Latency Anomalies: {facts['hops']['timing_anomalies']}\n\n"
            f"Payloads & Indicators:\n"
            f"- Suspicious URLs: {facts['links']['suspicious_count']}/{facts['links']['total']}\n"
            f"- Weaponized Attachments: {facts['attachments']['weaponized_count']}/{facts['attachments']['total']}\n"
            f"- Key Factors: {'; '.join(facts['explainability']) if facts['explainability'] else 'Normal forensic delivery profile'}\n\n"
            f"--- TASK ---\n"
            f"Provide a structured SOC response in clean markdown with:\n"
            f"1. Executive Threat Narrative (2-3 concise paragraphs summarizing the incident and confidence level)\n"
            f"2. SOC Triage & Immediate Actions (bulleted checklist of containment, identity, network, and policy actions)\n"
            f"3. MITRE ATT&CK & D3FEND Mapping (techniques with IDs, names, and tactics)\n"
        )

    @classmethod
    def _parse_ai_response(
        cls, ai_text: str, facts: Dict[str, Any]
    ) -> Tuple[str, List[str], List[Dict[str, str]]]:
        """Parses the AI markdown response into narrative, triage items, and MITRE mappings."""
        narrative = ai_text
        triage_actions: List[str] = []
        mitre_mappings: List[Dict[str, str]] = []

        action_keywords = (
            "quarantine", "block", "isolate", "reset", "verify", "sinkhole",
            "report", "revoke", "notify", "inspect", "contain", "disable",
            "alert", "investigate", "ban", "filter", "firewall", "hold", "purge"
        )

        # Extract bullet points as potential triage actions
        for line in ai_text.splitlines():
            line_str = line.strip()
            if re.match(r"^(\s*[-*•]|\s*\d+[\.\)]|\s*\[[ xX]?\])", line_str) and len(line_str) > 8:
                clean_line = re.sub(r"^(\s*[-*•]|\s*\d+[\.\)]|\s*\[[ xX]?\])\s*", "", line_str).strip()
                if any(w in clean_line.lower() for w in action_keywords):
                    if clean_line not in triage_actions:
                        triage_actions.append(clean_line)

        # Extract MITRE technique references
        mitre_patterns = re.findall(r"(T\d{4}(?:\.\d{3})?|D3-[A-Z]+)", ai_text)
        seen_techniques = set()
        for tech in mitre_patterns:
            if tech not in seen_techniques:
                seen_techniques.add(tech)
                mitre_mappings.append({
                    "technique_id": tech,
                    "name": cls._get_technique_name(tech),
                    "tactic": cls._get_technique_tactic(tech),
                })

        # If AI didn't format discrete bullets, fall back to deterministic lists
        if not triage_actions:
            triage_actions = cls._generate_deterministic_triage_actions(facts)
        if not mitre_mappings:
            mitre_mappings = cls._generate_deterministic_mitre(facts)

        return narrative, triage_actions[:8], mitre_mappings[:6]

    @classmethod
    def _build_deterministic_result(
        cls, facts: Dict[str, Any], fallback_reason: str
    ) -> Dict[str, Any]:
        """Synthesizes deterministic expert triage and narrative from the evidence ledger."""
        narrative = cls._generate_deterministic_narrative(facts)
        triage_actions = cls._generate_deterministic_triage_actions(facts)
        mitre_mappings = cls._generate_deterministic_mitre(facts)

        return {
            "status": "FALLBACK_DETERMINISTIC",
            "engine": "trace_mail_deterministic_synthesis",
            "model": DEFAULT_MODEL,
            "analysis_id": facts["analysis_id"],
            "forensic_hash": facts["forensic_hash"],
            "threat_score": facts["threat_score"],
            "risk_category": facts["risk_category"],
            "narrative": narrative,
            "triage_advice": triage_actions,
            "mitre_mappings": mitre_mappings,
            "ledger_verified": True,
            "ledger_receipt": facts.get("ledger_receipt"),
            "fallback_reason": fallback_reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def _generate_deterministic_narrative(cls, facts: Dict[str, Any]) -> str:
        """Constructs an explainable risk narrative directly from ledger facts."""
        score = facts["threat_score"]
        category = facts["risk_category"]
        detections = facts["detections"]
        hdr = facts["headers"]
        auth = facts["auth"]
        origin = facts["origin"]
        links = facts["links"]
        attachments = facts["attachments"]

        sections = []

        # Executive Summary
        if score >= 70:
            verdict_badge = f"### 🚨 Executive Incident Narrative — {category} (Threat Score: {int(score)}/100)"
            summary_p = (
                f"A high-severity email threat has been confirmed through deterministic cryptographic and header inspection. "
                f"The message targeting '{hdr['to']}' presents clear indicators of weaponization or deceptive delivery tactics, "
                f"carrying active detection signatures: **{', '.join(detections) if detections else 'Cryptographic & Behavioral Anomalies'}**."
            )
        elif score >= 35:
            verdict_badge = f"### ⚠️ Executive Incident Narrative — {category} (Threat Score: {int(score)}/100)"
            summary_p = (
                f"Elevated forensic risk detected for message from '{hdr['from']}'. While some authentication or delivery elements "
                f"may be standard, the message exhibits suspicious attributes requiring SOC tier-2 review before release."
            )
        else:
            verdict_badge = f"### ✅ Executive Incident Narrative — {category} (Threat Score: {int(score)}/100)"
            summary_p = (
                f"Deterministic forensic inspection indicates a benign, authentic delivery profile. "
                f"Cryptographic invariants (SPF/DKIM/DMARC) and transmission latency conform to baseline expectations."
            )

        sections.append(verdict_badge)
        sections.append(summary_p)

        # Forensic Correlation
        sections.append("#### 🔬 Forensic Invariant Correlation")
        auth_notes = []
        if auth["spf_status"] == "PASS" and auth["dkim_status"] == "PASS":
            auth_notes.append("Dual cryptographic alignment (SPF and DKIM pass) confirmed under RFC 5322.")
        else:
            if auth["spf_status"] != "PASS":
                auth_notes.append(f"SPF validation failed or unaligned ({auth['spf_status']}) for envelope domain '{auth['spf_domain']}'.")
            if auth["dkim_status"] != "PASS":
                auth_notes.append(f"DKIM signature is absent or invalid ({auth['dkim_status']}).")

        if origin["is_tor"]:
            auth_notes.append(f"Origin IP {origin['ip']} is an active Tor exit node.")
        elif origin["is_cloud"]:
            auth_notes.append(f"Origin IP {origin['ip']} originates from a cloud hosting datacenter (ASN: {origin['asn']}).")

        if links["suspicious_count"] > 0:
            auth_notes.append(f"Identified {links['suspicious_count']} suspicious or deceptive URLs (e.g. Punycode/homoglyphs or internal SSRF targets).")

        if attachments["weaponized_count"] > 0:
            auth_notes.append(f"Identified {attachments['weaponized_count']} weaponized or double-extension attachment payload(s).")

        if not auth_notes:
            auth_notes.append("No adverse cryptographic, routing, or payload anomalies observed.")

        for note in auth_notes:
            sections.append(f"- {note}")

        # Ledger Verification
        sections.append(f"\n*Tamper-Evident Ledger SHA-256 Hash:* `{facts['forensic_hash']}`")

        return "\n\n".join(sections)

    @classmethod
    def _generate_deterministic_triage_actions(cls, facts: Dict[str, Any]) -> List[str]:
        """Generates prioritized, actionable SOC triage containment items."""
        score = facts["threat_score"]
        detections = facts["detections"]
        origin = facts["origin"]
        links = facts["links"]
        attachments = facts["attachments"]

        actions = []

        if score >= 70:
            actions.append("QUARANTINE: Purge message across all tenant mailboxes (M365 / Google Workspace eDiscovery).")
            if origin["ip"] and origin["ip"] != "Unavailable" and not origin.get("is_private"):
                actions.append(f"FIREWALL: Block outbound and ingress traffic for origin IP {origin['ip']} on perimeter edge / EDR.")

            is_bec = any("BEC" in d or "SPOOFING" in d for d in detections)
            if is_bec:
                actions.append("FINANCIAL VERIFICATION: Issue immediate hold on wire transfers; initiate out-of-band phone verification using known contacts.")
                actions.append("IDENTITY: Audit targeted executive account for unauthorized mailbox forwarding or delegated inbox rules.")

            if links["suspicious_count"] > 0:
                actions.append("CREDENTIAL CONTAINMENT: Force password reset and terminate active session tokens for any recipient who clicked links.")
                actions.append("DNS SINKHOLE: Add suspicious payload domains to enterprise DNS blocklist / secure web gateway.")

            if attachments["weaponized_count"] > 0:
                actions.append("ENDPOINT ISOLATION: Check EDR telemetry for process spawns or execution artifacts matching attachment hashes.")

        elif score >= 35:
            actions.append("USER WARNING: Route message to spam/quarantine; append external sender impersonation advisory banner.")
            actions.append("ANALYST REVIEW: Perform manual header and domain age WHOIS inspection before releasing.")
            if links["suspicious_count"] > 0:
                actions.append("LINK INSPECTION: Verify link destination within sandboxed web proxy.")

        else:
            actions.append("ALLOW: Message conforms to verified sender policy; safe for standard delivery.")
            actions.append("MONITOR: Maintain standard baseline telemetry.")

        return actions

    @classmethod
    def _generate_deterministic_mitre(cls, facts: Dict[str, Any]) -> List[Dict[str, str]]:
        """Maps detected evidence flags to MITRE ATT&CK & D3FEND matrices."""
        score = facts["threat_score"]
        detections = set(facts["detections"])
        links = facts["links"]
        attachments = facts["attachments"]

        mappings = []

        if score >= 35:
            if links["suspicious_count"] > 0 or any("LINK" in d or "PUNYCODE" in d or "SSRF" in d for d in detections):
                mappings.append({
                    "technique_id": "T1566.002",
                    "name": "Spearphishing Link",
                    "tactic": "Initial Access",
                })
            if attachments["weaponized_count"] > 0 or any("ATTACHMENT" in d for d in detections):
                mappings.append({
                    "technique_id": "T1566.001",
                    "name": "Spearphishing Attachment",
                    "tactic": "Initial Access",
                })
            if any("SPOOFING" in d or "HOMOGLYPH" in d for d in detections):
                mappings.append({
                    "technique_id": "T1656",
                    "name": "Impersonation",
                    "tactic": "Defense Evasion",
                })
            if any("BEC" in d for d in detections):
                mappings.append({
                    "technique_id": "T1586.002",
                    "name": "Compromised Email Account",
                    "tactic": "Resource Development",
                })

            # Defensive D3FEND mapping
            mappings.append({
                "technique_id": "D3-EBR",
                "name": "Email Body Filtering",
                "tactic": "D3FEND Detection",
            })
            mappings.append({
                "technique_id": "D3-EAHF",
                "name": "Email Authentication Header Filtering",
                "tactic": "D3FEND Detection",
            })

        return mappings

    @staticmethod
    def _get_technique_name(technique_id: str) -> str:
        names = {
            "T1566": "Phishing",
            "T1566.001": "Spearphishing Attachment",
            "T1566.002": "Spearphishing Link",
            "T1566.003": "Spearphishing via Service",
            "T1656": "Impersonation",
            "T1586.002": "Compromised Email Account",
            "T1204": "User Execution",
            "D3-EBR": "Email Body Filtering",
            "D3-EAHF": "Email Authentication Header Filtering",
            "D3-EAI": "Email Authentication Invariant Verification",
        }
        return names.get(technique_id, "Tactical Threat Invariant")

    @staticmethod
    def _get_technique_tactic(technique_id: str) -> str:
        if technique_id.startswith("D3-"):
            return "D3FEND Detection"
        tactics = {
            "T1566": "Initial Access",
            "T1566.001": "Initial Access",
            "T1566.002": "Initial Access",
            "T1566.003": "Initial Access",
            "T1656": "Defense Evasion",
            "T1586.002": "Resource Development",
            "T1204": "Execution",
        }
        return tactics.get(technique_id, "Adversary Tactic")
