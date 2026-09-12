"""
Threat Scorer & Explainable Risk Engine.
Evaluates linguistic urgency, BEC indicators (wire transfer, gift cards),
domain typosquatting, safe static link inspection, and generates an explainability matrix.

Adheres to Master Rule:
A single weak heuristic (e.g. keywords) must NOT overpower strong authenticating evidence
(SPF PASS + DKIM PASS + DMARC PASS / Aligned).
Separates Detection, Risk, Confidence, and Enforcement actions.
"""

import re
from typing import Dict, Any, List
from .url_scanner import URLScanner
from .auth_validator import AuthValidator

class ThreatScorer:
    """Calculates composite threat score (0-100), calibrated confidence, and enforcement actions."""

    # High-risk financial & coercion triggers (BEC)
    URGENCY_KEYWORDS = [
        "urgent", "immediately", "overdue", "account suspended", "verify your account",
        "action required", "wire transfer", "bank transfer", "invoice attached",
        "gift card", "direct deposit", "payroll", "swift", "confidential request",
        "fund transfer", "payment diversion", "credentials expired", "password reset"
    ]

    FREE_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "protonmail.com"}

    def __init__(
        self,
        parsed_email: Dict[str, Any],
        auth_results: Dict[str, Any],
        hop_results: Dict[str, Any],
        ml_result: Dict[str, Any] = None
    ):
        self.parsed = parsed_email
        self.auth = auth_results
        self.hop = hop_results
        self.ml_result = ml_result or {}
        self.score = 0.0
        self.confidence = 85.0
        self.factors: List[Dict[str, Any]] = []
        self.detections: List[str] = []

    def calculate(self) -> Dict[str, Any]:
        """Calculates total score, calibrated confidence, and builds explainability breakdown."""
        # 1. Determine baseline authentication trust
        composite_pass = self.auth.get("composite_pass", False)
        is_unverified = self.auth.get("is_unverified", False)

        # 2. Run modular scorers
        self._score_authentication()
        self._score_hops_and_latency()
        self._score_display_spoofing()
        self._score_reply_to_and_bec()
        self._score_links_and_attachments()

        # Invariant Protection: If the message exhibits severe BEC financial diversion,
        # impersonation, or dangerous links, do NOT allow reported auth passes to suppress risk.
        # This protects against Account Takeover (ATO) and forged Authentication-Results.
        auth_discount_eligible = composite_pass and not any(d in self.detections for d in [
            "BEC_VENDOR_FINANCIAL_DIVERSION",
            "REPLY_TO_ORG_MISMATCH",
            "DISPLAY_NAME_SPOOFING",
            "SSRF_INTERNAL_TARGET",
            "PUNYCODE_LOOKALIKE",
            "WEAPONIZED_ATTACHMENT"
        ])

        self._score_linguistic_urgency(crypto_authenticated=auth_discount_eligible)
        self._score_ml_baseline(crypto_authenticated=auth_discount_eligible)

        # 3. Adjust Confidence Calibration
        if is_unverified:
            self.confidence = min(self.confidence, 60.0)
            self.factors.append({
                "category": "CONFIDENCE_CALIBRATION",
                "impact": "Confidence -25%",
                "severity": "INFO",
                "detail": "Email lacks receiver-reported authentication headers; telemetry is unverified."
            })
        elif composite_pass:
            self.confidence = min(98.0, self.confidence + 10.0)

        # 4. Clamp score between 0 and 100
        final_score = max(0.0, min(100.0, round(self.score, 1)))
        final_conf = max(10.0, min(99.0, round(self.confidence, 0)))

        # 5. Determine Risk Category and Enforcement Policy
        is_bec_diversion = "BEC_VENDOR_FINANCIAL_DIVERSION" in self.detections
        if final_score >= 70.0:
            category = "HIGH_RISK"
            color = "#F87171"  # Red
            if is_bec_diversion:
                verdict = "CRITICAL BEC DIVERSION — OUT-OF-BAND VERIFICATION REQUIRED"
            else:
                verdict = "HIGH RISK — ANALYST REVIEW REQUIRED"
            enforcement = "QUARANTINE_RECOMMENDED" if final_conf >= 70 else "WARN_REVIEW"
        elif final_score >= 35.0 or is_bec_diversion:
            category = "SUSPICIOUS" if final_score < 70.0 else "HIGH_RISK"
            color = "#FFD166" if final_score < 70.0 else "#F87171"
            if is_bec_diversion:
                verdict = "ELEVATED BEC RISK — OUT-OF-BAND VERIFICATION REQUIRED"
            else:
                verdict = "ELEVATED RISK — REVIEW RECOMMENDED"
            enforcement = "WARN_REVIEW"
        else:
            category = "LOW_OBSERVED_RISK"
            color = "#4ADE80"  # Green
            verdict = "LOW OBSERVED RISK — NOT A SAFETY GUARANTEE"
            enforcement = "MONITOR" if is_unverified else "ALLOW"

        return {
            "threat_score": final_score,
            "confidence_score": final_conf,
            "risk_category": category,
            "badge_color": color,
            "verdict": verdict,
            "enforcement_action": enforcement,
            "detections": self.detections,
            "explainability_factors": self.factors,
            "analysis_method": "EVIDENCE_PRECEDENCE_HYBRID_SCORING",
            "model_status": "Explainable rules + Naive Bayes baseline with RFC 7489 alignment"
        }

    def _score_authentication(self):
        """Scores cryptographic SPF, DKIM, and DMARC alignment."""
        spf_status = self.auth.get("spf", {}).get("status", "NONE")
        dkim_status = self.auth.get("dkim", {}).get("status", "NONE")
        dmarc_status = self.auth.get("dmarc", {}).get("status", "NONE")
        dmarc_aligned = self.auth.get("dmarc", {}).get("dkim_aligned", False) or self.auth.get("dmarc", {}).get("spf_aligned", False)

        if dmarc_status == "FAIL":
            self.score += 35.0
            self.detections.append("DMARC_FAIL")
            self.factors.append({
                "category": "AUTHENTICATION",
                "impact": "+35 pts",
                "severity": "HIGH",
                "detail": "Receiver-reported DMARC validation failed (domain alignment breached)."
            })
        elif spf_status == "FAIL" and not dmarc_aligned:
            self.score += 20.0
            self.detections.append("SPF_FAIL")
            self.factors.append({
                "category": "AUTHENTICATION",
                "impact": "+20 pts",
                "severity": "MEDIUM",
                "detail": "SPF check failed without compensating DKIM domain alignment."
            })
        elif self.auth.get("composite_pass"):
            # Strong authenticating evidence reduces baseline noise
            self.detections.append("CRYPTOGRAPHIC_PASS")
            self.factors.append({
                "category": "AUTHENTICATION",
                "impact": "Verified Pass",
                "severity": "BENIGN",
                "detail": "Cryptographic authentication passed (SPF/DKIM/DMARC alignment verified)."
            })
        elif dmarc_status == "NONE" and spf_status == "NONE":
            # Missing header: Do NOT add threat points! Lower confidence instead.
            self.detections.append("AUTH_UNVERIFIED")
            self.factors.append({
                "category": "AUTHENTICATION",
                "impact": "0 pts",
                "severity": "NEUTRAL",
                "detail": "No cryptographic authentication headers reported in submitted email."
            })

    def _score_hops_and_latency(self):
        """Penalizes forged relay headers and negative latency."""
        if self.hop.get("has_timing_anomalies"):
            self.score += 40.0
            self.detections.append("REVERSED_TIMING_ANOMALY")
            self.factors.append({
                "category": "RELAY_INTEGRITY",
                "impact": "+40 pts",
                "severity": "HIGH",
                "detail": "Reversed relay timestamps detected. Possible causes include clock skew, malformed data, or header manipulation."
            })

    def _score_display_spoofing(self):
        """Detects display name spoofing (e.g. 'CEO Name' <random_gmail@gmail.com>)."""
        from_hdr = self.parsed.get("headers", {}).get("from", "")
        if "<" in from_hdr and ">" in from_hdr:
            display_name = from_hdr.split("<")[0].strip().strip('"').lower()
            addr = from_hdr.split("<")[1].split(">")[0].strip().lower()
            addr_domain = addr.split("@")[-1] if "@" in addr else ""

            if any(title in display_name for title in ["ceo", "director", "principal", "hr", "payroll", "admin", "executive", "president"]):
                if addr_domain in self.FREE_PROVIDERS:
                    self.score += 30.0
                    self.detections.append("DISPLAY_NAME_SPOOFING")
                    self.factors.append({
                        "category": "IMPERSONATION",
                        "impact": "+30 pts",
                        "severity": "CRITICAL",
                        "detail": f"Executive persona '{display_name}' sent from personal consumer address '{addr}'."
                    })

    def _score_reply_to_and_bec(self):
        """
        Detects Reply-To organizational domain mismatches combined with financial,
        banking, or wire transfer modifications (Vendor Email Compromise / BEC).
        A compromised or rogue vendor mailbox that passes SPF/DKIM can still request
        fraudulent bank account modifications while routing victim replies to an attacker domain.
        This rule applies high-weight non-discountable risk points and requires out-of-band verification.
        """
        headers = self.parsed.get("headers", {})
        from_hdr = headers.get("from", "")
        reply_to_hdr = headers.get("reply_to", "")

        if not reply_to_hdr or not from_hdr:
            return

        from_domain = AuthValidator._extract_domain(from_hdr)
        reply_to_domain = AuthValidator._extract_domain(reply_to_hdr)

        if not from_domain or not reply_to_domain:
            return

        from_org = AuthValidator.get_organizational_domain(from_domain)
        reply_to_org = AuthValidator.get_organizational_domain(reply_to_domain)

        # Check if organizational domains differ
        if from_org and reply_to_org and from_org != reply_to_org:
            subject = headers.get("subject", "").lower()
            body = self.parsed.get("body", {}).get("plain_text", "").lower()
            combined_text = subject + " " + body

            financial_terms = [
                "bank", "banking", "banking details", "bank account", "wire transfer",
                "remittance", "invoice payment", "routing number", "iban", "swift",
                "update vendor", "update the vendor record", "new account details",
                "change of bank", "payment details", "transfer funds", "remittance details"
            ]

            evasion_terms = [
                "do not call", "confidential", "treat this as confidential",
                "in an audit", "keep this confidential", "don't call", "audit"
            ]

            matched_financial = [term for term in financial_terms if term in combined_text]
            matched_evasion = [term for term in evasion_terms if term in combined_text]

            if matched_financial:
                # High-weight BEC signal: Never discounted by sender authentication!
                weight = 55.0
                if matched_evasion:
                    weight += 15.0
                    self.detections.append("BEC_VERIFICATION_EVASION")

                self.score += weight
                self.detections.append("BEC_VENDOR_FINANCIAL_DIVERSION")
                self.detections.append("REPLY_TO_ORG_MISMATCH")

                detail = (
                    f"Reply-To organizational domain '{reply_to_org}' does not match From domain '{from_org}' "
                    f"in an email requesting bank/remittance modifications ({', '.join(matched_financial[:3])}). "
                    f"Out-of-band verification required: Contact the vendor via verified telephone before updating banking records."
                )
                if matched_evasion:
                    detail += f" Evasion tactic detected: '{matched_evasion[0]}' suppresses independent verification."

                self.factors.append({
                    "category": "BEC_DETECTION",
                    "impact": f"+{weight:.0f} pts (Critical Vendor BEC)",
                    "severity": "CRITICAL",
                    "detail": detail
                })
            else:
                weight = 20.0
                self.score += weight
                self.detections.append("REPLY_TO_ORG_MISMATCH")
                self.factors.append({
                    "category": "HEADER_INTEGRITY",
                    "impact": f"+{weight:.0f} pts",
                    "severity": "MEDIUM",
                    "detail": f"Reply-To organizational domain '{reply_to_org}' does not match From domain '{from_org}'."
                })

    def _score_links_and_attachments(self):
        """Inspects embedded links and attachments safely with static analysis (NO SSRF)."""
        links = self.parsed.get("body", {}).get("links", [])
        scanned_links = URLScanner.scan_all(links)

        for l in scanned_links:
            if l.get("is_internal_or_ssrf"):
                self.score += 45.0
                self.detections.append("SSRF_INTERNAL_TARGET")
                self.factors.append({
                    "category": "URL_REPUTATION",
                    "impact": "+45 pts",
                    "severity": "CRITICAL",
                    "detail": f"Link targets cloud metadata or internal network address: {l.get('hostname')}"
                })
                break
            elif l.get("punycode"):
                self.score += 25.0
                self.detections.append("PUNYCODE_LOOKALIKE")
                self.factors.append({
                    "category": "URL_REPUTATION",
                    "impact": "+25 pts",
                    "severity": "HIGH",
                    "detail": f"Internationalized Punycode homograph domain detected: {l.get('hostname')}"
                })
                break
            elif l.get("is_ip_literal"):
                self.score += 20.0
                self.detections.append("IP_LITERAL_URL")
                self.factors.append({
                    "category": "URL_REPUTATION",
                    "impact": "+20 pts",
                    "severity": "MEDIUM",
                    "detail": f"Raw IP address link instead of hostname: {l.get('hostname')}"
                })
                break
            elif l.get("suspicious"):
                self.score += 15.0
                self.detections.append("SUSPICIOUS_URL")
                self.factors.append({
                    "category": "URL_REPUTATION",
                    "impact": "+15 pts",
                    "severity": "MEDIUM",
                    "detail": f"Suspicious URL characteristics: {', '.join(l.get('risk_reasons', []))[:80]}"
                })
                break

        # Attachments inspection (e.g. .exe, .scr, .iso, .vbs)
        dangerous_exts = [".exe", ".scr", ".iso", ".vbs", ".bat", ".hta", ".docm", ".cmd", ".ps1"]
        for att in self.parsed.get("attachments", []):
            fname = att.get("filename", "").lower()
            if any(fname.endswith(ext) for ext in dangerous_exts):
                self.score += 35.0
                self.detections.append("WEAPONIZED_ATTACHMENT")
                self.factors.append({
                    "category": "ATTACHMENT_SECURITY",
                    "impact": "+35 pts",
                    "severity": "CRITICAL",
                    "detail": f"Potentially executable or weaponized attachment detected: {fname}"
                })
                break

    def _score_linguistic_urgency(self, crypto_authenticated: bool = False):
        """
        Scans subject and body for urgency and financial fraud keywords.
        CRITICAL RULE: If email is cryptographically authenticated (SPF/DKIM/DMARC PASS),
        weak generic keywords (urgent, invoice, verify) are discounted by 85% to prevent false positives.
        """
        subject = self.parsed.get("headers", {}).get("subject", "").lower()
        body = self.parsed.get("body", {}).get("plain_text", "").lower()
        combined = subject + " " + body

        matched_keywords = []
        for kw in self.URGENCY_KEYWORDS:
            if re.search(r'\b' + re.escape(kw) + r'\b', combined):
                matched_keywords.append(kw)

        if matched_keywords:
            raw_weight = min(30.0, len(matched_keywords) * 6.0)
            if crypto_authenticated:
                # Suppress weak heuristic on authentic messages
                discounted_weight = round(raw_weight * 0.15, 1)
                self.score += discounted_weight
                self.factors.append({
                    "category": "CONTENT_ANALYSIS",
                    "impact": f"+{discounted_weight} pts (Suppressed by Auth Pass)",
                    "severity": "LOW",
                    "detail": f"Generic business keywords detected ({', '.join(matched_keywords[:3])}), but discounted due to verified sender authentication."
                })
            else:
                self.score += raw_weight
                self.detections.append("LINGUISTIC_URGENCY")
                self.factors.append({
                    "category": "CONTENT_ANALYSIS",
                    "impact": f"+{raw_weight:.0f} pts",
                    "severity": "MEDIUM",
                    "detail": f"Social engineering / BEC urgency indicators detected: {', '.join(matched_keywords[:4])}"
                })

    def _score_ml_baseline(self, crypto_authenticated: bool = False):
        """Adds a calibrated contribution from the text classifier."""
        probability = float(self.ml_result.get("phishing_probability", 0.5))
        if probability < 0.65:
            return

        weight = 18.0 if probability >= 0.85 else 12.0
        if crypto_authenticated:
            weight = round(weight * 0.2, 1)

        indicators = self.ml_result.get("matched_indicators", [])
        detail = f"Naive Bayes baseline estimated {probability * 100:.1f}% phishing probability"
        if indicators:
            detail += f" (terms: {', '.join(indicators[:4])})"
        if crypto_authenticated:
            detail += "; risk reduced due to cryptographic authentication pass"

        self.score += weight
        self.factors.append({
            "category": "ML_BASELINE",
            "impact": f"+{weight:.0f} pts",
            "severity": "LOW" if crypto_authenticated else "MEDIUM",
            "detail": detail
        })
