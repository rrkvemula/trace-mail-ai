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
from typing import Dict, Any, List, Optional, Set
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

    # Extortion, sextortion, and blackmail threat indicators
    EXTORTION_THREAT_PHRASES = [
        "i have your private", "i hacked your", "i recorded you",
        "i have access to your", "i installed a trojan", "i placed a malware",
        "i know your password", "i have compromising", "your dirty secret",
        "i captured you", "webcam footage", "intimate video", "intimate moment",
        "embarrassing video", "embarrassing material", "shameful activity",
        "expose you", "expose your", "leak your", "leak this to",
        "share with your contacts", "send to your contacts", "send to all your",
        "share this with everyone", "all your friends will see",
        "your reputation will be destroyed", "your life will be ruined",
        "sensitive information about you", "sensitive data about you",
        "i have evidence against you", "i have proof of your",
        "data breach.*your account", "your data has been compromised",
        "we have encrypted your files", "your files have been encrypted",
        "pay the ransom", "decryption key", "decrypt your files",
    ]

    EXTORTION_DEMAND_KEYWORDS = [
        # Cryptocurrencies
        "bitcoin", "btc", "cryptocurrency", "crypto wallet", "monero", "xmr",
        "ethereum", "eth", "usdt", "tether", "litecoin",
        "wallet address", "send.*to this address", "transfer.*within",
        # Gift Cards & Prepaid Vouchers
        "gift card", "apple gift card", "itunes card", "amazon gift card",
        "google play card", "steam card", "steam gift card", "razer gold",
        "moneypak", "greendot", "paysafecard", "voucher code", "card code",
        # P2P Payment & Wire Transfer Channels
        "cash app", "cashtag", "venmo", "zelle", "paypal", "western union",
        "moneygram", "wire transfer", "bank transfer", "upi id", "paytm",
        # Coercion, Deadlines & Timers
        "you have.*hours", "you have.*days", "deadline",
        "countdown", "timer", "clock is ticking", "time is running out",
        "or else", "otherwise i will", "if you don't pay", "if you refuse",
        "consequences will be", "no negotiation",
        # Two-Stage Extortion Bait (Evading Keyword Filters)
        "reply to this email", "contact me on telegram", "reach me on telegram",
        "telegram @", "session id", "wickr", "signal", "settle this quietly",
        "to prevent the leak", "to stop the release", "instructions to pay"
    ]

    FREE_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "protonmail.com"}

    # Independent authentic forensic evidence classes (Excludes advisory ML and generic keywords)
    EVIDENCE_CLASSES = {
        "CRYPTO_AUTH": {"DMARC_FAIL", "SPF_FAIL", "FORGED_OR_UNTRUSTED_AUTHSERV", "RECEIVER_PASS_CRYPTO_MISMATCH", "DKIM_CRYPTO_FAILED"},
        "IDENTITY_ROUTING": {"DISPLAY_NAME_SPOOFING", "REPLY_TO_ORG_MISMATCH", "REVERSED_TIMING_ANOMALY"},
        "INFRA_URL": {"SSRF_INTERNAL_TARGET", "PUNYCODE_LOOKALIKE", "IP_LITERAL_URL", "SUSPICIOUS_URL", "HOMOGLYPH_BRAND_IMPERSONATION", "MIXED_SCRIPT_HOMOGLYPH", "LINK_TARGET_MISMATCH", "INVISIBLE_CHAR_OBFUSCATION"},
        "PAYLOAD_SECURITY": {"WEAPONIZED_ATTACHMENT", "DOUBLE_EXTENSION_DECEPTION", "MIME_EXTENSION_MISMATCH"},
        "BEC_FINANCIAL_FRAUD": {"BEC_VENDOR_FINANCIAL_DIVERSION", "BEC_VERIFICATION_EVASION"},
        "EXTORTION_THREAT": {"EXTORTION_BLACKMAIL", "SEXTORTION", "RANSOMWARE_THREAT"},
    }

    def __init__(
        self,
        parsed_email: Dict[str, Any],
        auth_results: Dict[str, Any],
        hop_results: Dict[str, Any],
        ml_result: Dict[str, Any] = None,
        allowlist: Optional[Set[str]] = None
    ):
        self.parsed = parsed_email
        self.auth = auth_results
        self.hop = hop_results
        self.ml_result = ml_result or {}
        self.allowlist = {s.lower().strip() for s in (allowlist or set()) if s}
        self.score = 0.0
        self.confidence = 85.0
        self.factors: List[Dict[str, Any]] = []
        self.detections: List[str] = []
        self.headers = parsed_email.get("headers", {})

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
        self._score_extortion_and_blackmail()

        # Invariant Protection: If the message exhibits severe BEC financial diversion,
        # impersonation, dangerous links, or crypto tampering, do NOT allow reported auth passes to suppress risk.
        # This protects against Account Takeover (ATO) and forged Authentication-Results.
        auth_discount_eligible = composite_pass and not any(d in self.detections for d in [
            "BEC_VENDOR_FINANCIAL_DIVERSION",
            "REPLY_TO_ORG_MISMATCH",
            "DISPLAY_NAME_SPOOFING",
            "SSRF_INTERNAL_TARGET",
            "PUNYCODE_LOOKALIKE",
            "HOMOGLYPH_BRAND_IMPERSONATION",
            "MIXED_SCRIPT_HOMOGLYPH",
            "LINK_TARGET_MISMATCH",
            "WEAPONIZED_ATTACHMENT",
            "FORGED_OR_UNTRUSTED_AUTHSERV",
            "RECEIVER_PASS_CRYPTO_MISMATCH",
            "SEXTORTION",
            "EXTORTION_BLACKMAIL",
            "RANSOMWARE_THREAT"
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

        # 4. Determine Active Independent Evidence Classes & Evidence Strength
        active_hard_classes = []
        for class_name, det_set in self.EVIDENCE_CLASSES.items():
            if any(d in self.detections for d in det_set):
                active_hard_classes.append(class_name)

        if len(active_hard_classes) >= 2:
            evidence_strength = "STRONG"
        elif len(active_hard_classes) == 1:
            evidence_strength = "MODERATE"
        else:
            evidence_strength = "LOW"

        # 5. Clamp score between 0 and 100
        final_score = max(0.0, min(100.0, round(self.score, 1)))
        final_conf = max(10.0, min(99.0, round(self.confidence, 0)))

        # 6. Policy Gate: High-risk categorization requires >=2 independent evidence classes,
        # or a direct critical payload execution threat (WEAPONIZED_ATTACHMENT, SSRF_INTERNAL_TARGET, or EXTORTION).
        # Prevents high-risk false-positive quarantine from isolated heuristics or text ML alone.
        has_critical_payload = any(d in self.detections for d in [
            "WEAPONIZED_ATTACHMENT", "SSRF_INTERNAL_TARGET",
            "SEXTORTION", "EXTORTION_BLACKMAIL", "RANSOMWARE_THREAT"
        ])
        if final_score >= 70.0 and len(active_hard_classes) < 2 and not has_critical_payload:
            final_score = min(final_score, 65.0)
            self.factors.append({
                "category": "EVIDENCE_PRECEDENCE_POLICY",
                "impact": "Policy Gate: Score Capped at 65",
                "severity": "INFO",
                "detail": (
                    "High-risk classification suppressed: TraceMail policy requires at least two independent "
                    "corroborating evidence classes (e.g. cryptographic failure, routing divergence, suspicious URL) "
                    "before recommending quarantine. Advisory signals alone cannot trigger high risk."
                )
            })

        # 7. Determine Risk Category and Enforcement Policy
        is_bec_diversion = "BEC_VENDOR_FINANCIAL_DIVERSION" in self.detections
        is_extortion = any(d in self.detections for d in ["SEXTORTION", "EXTORTION_BLACKMAIL", "RANSOMWARE_THREAT"])
        if final_score >= 70.0:
            category = "HIGH_RISK"
            color = "#F87171"  # Red
            if is_extortion:
                verdict = "CRITICAL EXTORTION / BLACKMAIL THREAT — LAW ENFORCEMENT ESCALATION"
            elif is_bec_diversion:
                verdict = "CRITICAL BEC DIVERSION — OUT-OF-BAND VERIFICATION REQUIRED"
            else:
                verdict = "HIGH RISK — ANALYST REVIEW REQUIRED"
            enforcement = "QUARANTINE_RECOMMENDED" if final_conf >= 70 else "WARN_REVIEW"
        elif final_score >= 35.0 or is_bec_diversion or is_extortion:
            category = "SUSPICIOUS"
            color = "#FFD166"
            if is_extortion:
                verdict = "ELEVATED EXTORTION RISK — DO NOT PAY OR ENGAGE"
            elif is_bec_diversion:
                verdict = "ELEVATED BEC RISK — OUT-OF-BAND VERIFICATION REQUIRED"
            else:
                verdict = "ELEVATED RISK — REVIEW RECOMMENDED"
            enforcement = "WARN_REVIEW"
        else:
            category = "LOW_OBSERVED_RISK"
            color = "#4ADE80"  # Green
            verdict = "LOW OBSERVED RISK — NOT A SAFETY GUARANTEE"
            enforcement = "MONITOR" if is_unverified else "ALLOW"
        # 4. Scoped Allowlist Policy Evaluation (P1 Fix)
        # Allows exact sender emails; allows domains only if cryptographically authenticated.
        # CRITICAL SAFETY INVARIANT: NEVER suppresses weaponized attachments or SSRF targets!
        from_hdr = str(self.headers.get("from", "")).lower()
        sender_email_match = re.search(r'[\w\.-]+@[\w\.-]+', from_hdr)
        sender_email = sender_email_match.group(0) if sender_email_match else ""
        sender_domain = (self.auth.get("sender_domain") or "").lower()

        is_allowlisted = False
        allowlist_reason = ""
        if self.allowlist:
            if sender_email and sender_email in self.allowlist:
                is_allowlisted = True
                allowlist_reason = f"Exact sender email '{sender_email}' is allowlisted by analyst policy."
            elif sender_domain and sender_domain in self.allowlist:
                if composite_pass or self.auth.get("evidence_status") in ["INDEPENDENTLY_VERIFIED_PASS", "RECEIVER_REPORTED_PASS"]:
                    is_allowlisted = True
                    allowlist_reason = f"Cryptographically verified domain '@{sender_domain}' is allowlisted by analyst policy."
                else:
                    self.factors.append({
                        "category": "ALLOWLIST_POLICY",
                        "impact": "Allowlist Inactive (0 pts)",
                        "severity": "WARNING",
                        "detail": f"Domain '@{sender_domain}' matches allowlist, but authentication failed or is unverified (spoofing protection)."
                    })

        has_critical_payload = any(d in self.detections for d in [
            "WEAPONIZED_ATTACHMENT", "DOUBLE_EXTENSION_DECEPTION", "MIME_EXTENSION_MISMATCH",
            "SSRF_INTERNAL_TARGET", "SEXTORTION", "EXTORTION_BLACKMAIL", "RANSOMWARE_THREAT"
        ])

        if is_allowlisted:
            if has_critical_payload:
                self.factors.append({
                    "category": "ALLOWLIST_POLICY",
                    "impact": "Allowlist Bypassed (+0 pts)",
                    "severity": "CRITICAL",
                    "detail": f"Allowlist bypassed: dangerous executable payload or internal SSRF target detected despite allowlist ({allowlist_reason})."
                })
            else:
                final_score = 0.0
                category = "LOW_OBSERVED_RISK"
                color = "#4ADE80"
                verdict = "ALLOWLISTED SENDER — TRUSTED POLICY APPLIED"
                enforcement = "ALLOW"
                evidence_strength = "LOW"
                self.factors.append({
                    "category": "ALLOWLIST_POLICY",
                    "impact": "Score Suppressed to 0",
                    "severity": "BENIGN",
                    "detail": allowlist_reason
                })

        limitations = [
            "Receiver-reported cryptographic status depends on boundary MTA integrity.",
            "GeoIP coordinates identify mail transfer infrastructure, not the physical location of the sender.",
            "Text model scores are advisory heuristics; authentic forensic evidence requires header/routing validation.",
            "Cryptographic verification (SPF/DKIM/DMARC) confirms domain delivery origin, but does not guarantee the account is free from compromise (ATO)."
        ]

        return {
            "threat_score": final_score,
            "confidence_score": final_conf,
            "risk_category": category,
            "evidence_strength": evidence_strength,
            "corroborated_classes": active_hard_classes,
            "badge_color": color,
            "verdict": verdict,
            "enforcement_action": enforcement,
            "detections": self.detections,
            "explainability_factors": self.factors,
            "limitations": limitations,
            "analysis_method": "TWO_CLASS_EVIDENCE_PRECEDENCE_HYBRID_SCORING",
            "model_status": "Evidence-first rule precedence + Advisory text signal (Experimental)"
        }

    def _score_authentication(self):
        """Scores cryptographic SPF, DKIM, and DMARC alignment."""
        spf_status = self.auth.get("spf", {}).get("status", "NONE")
        dkim_status = self.auth.get("dkim", {}).get("status", "NONE")
        dmarc_status = self.auth.get("dmarc", {}).get("status", "NONE")
        dmarc_aligned = self.auth.get("dmarc", {}).get("dkim_aligned", False) or self.auth.get("dmarc", {}).get("spf_aligned", False)
        evidence_status = self.auth.get("evidence_status", "")

        if evidence_status in ["RECEIVER_PASS_CRYPTO_MISMATCH", "DKIM_CRYPTO_FAILED"]:
            self.score += 45.0
            self.detections.append("RECEIVER_PASS_CRYPTO_MISMATCH")
            self.factors.append({
                "category": "AUTHENTICATION",
                "impact": "+45 pts (Critical Crypto Conflict)",
                "severity": "CRITICAL",
                "detail": "Severe cryptographic mismatch: Receiver MTA reported DKIM pass, but independent RFC 6376 verification failed against DNS public key. Tampered body/headers or forged receiver report."
            })
        elif evidence_status == "FORGED_OR_UNTRUSTED_AUTHSERV":
            self.score += 30.0
            self.detections.append("FORGED_OR_UNTRUSTED_AUTHSERV")
            self.factors.append({
                "category": "AUTHENTICATION",
                "impact": "+30 pts",
                "severity": "CRITICAL",
                "detail": f"Authentication-Results header claims authserv-id '{self.auth.get('authserv_id')}', but does not match recipient domain or observed boundary MTAs (potential header injection)."
            })
        elif dmarc_status == "FAIL":
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
            elif l.get("is_homoglyph_brand"):
                self.score += 50.0
                self.detections.append("HOMOGLYPH_BRAND_IMPERSONATION")
                self.factors.append({
                    "category": "URL_REPUTATION",
                    "impact": "+50 pts (Critical Homoglyph)",
                    "severity": "CRITICAL",
                    "detail": f"Visual homoglyph brand impersonation targeting '{l.get('impersonated_brand')}': {l.get('hostname')} (Skeleton: {l.get('skeleton_hostname')})"
                })
                break
            elif l.get("is_mixed_script"):
                self.score += 40.0
                self.detections.append("MIXED_SCRIPT_HOMOGLYPH")
                self.factors.append({
                    "category": "URL_REPUTATION",
                    "impact": "+40 pts (Mixed-Script IDN)",
                    "severity": "CRITICAL",
                    "detail": f"Mixed-script domain label detected violating RFC 5890: {l.get('hostname')}"
                })
                break
            elif l.get("has_invisible_chars"):
                self.score += 30.0
                self.detections.append("INVISIBLE_CHAR_OBFUSCATION")
                self.factors.append({
                    "category": "URL_REPUTATION",
                    "impact": "+30 pts (Zero-Width Evasion)",
                    "severity": "HIGH",
                    "detail": f"Zero-width or invisible Unicode characters detected in URL: {l.get('hostname')}"
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

        # Visual Link Deception: Anchor text displays brand/domain but href points elsewhere
        link_spoofs = self.parsed.get("body", {}).get("link_spoofs", [])
        for sp in link_spoofs:
            self.score += 45.0
            self.detections.append("LINK_TARGET_MISMATCH")
            self.factors.append({
                "category": "URL_REPUTATION",
                "impact": "+45 pts (Visual Link Deception)",
                "severity": "CRITICAL",
                "detail": f"HTML anchor spoofing: Displayed link claims '{sp.get('displayed_domain')}' but actual destination is '{sp.get('destination_domain')}' ({sp.get('actual_url')[:60]})."
            })
            break

        # Attachments inspection (e.g. .exe, .scr, .iso, .vbs, double-extensions, MIME mismatch)
        dangerous_exts = [".exe", ".scr", ".iso", ".vbs", ".bat", ".hta", ".docm", ".xlsm", ".cmd", ".ps1", ".wsf", ".cpl", ".jar"]
        double_ext_pattern = re.compile(r'\.(pdf|docx?|xlsx?|txt|jpg|png|csv)\.(exe|scr|vbs|bat|hta|cmd|ps1|js|jar|cpl|iso)\b', re.I)

        for att in self.parsed.get("attachments", []):
            fname = att.get("filename", "").lower()
            content_type = (att.get("content_type") or "").lower()

            # 1. Double extension deception (e.g. invoice.pdf.exe)
            if double_ext_pattern.search(fname):
                self.score += 45.0
                self.detections.append("DOUBLE_EXTENSION_DECEPTION")
                self.detections.append("WEAPONIZED_ATTACHMENT")
                self.factors.append({
                    "category": "ATTACHMENT_SECURITY",
                    "impact": "+45 pts (Critical Double-Extension)",
                    "severity": "CRITICAL",
                    "detail": f"Malicious double-extension deception detected: '{fname}'. Disguises executable malware as a benign document."
                })
                break

            # 2. MIME type mismatch (declared as document/image but carrying executable payload)
            if ("pdf" in content_type or "word" in content_type or "image" in content_type) and any(fname.endswith(ext) for ext in [".exe", ".scr", ".vbs", ".hta", ".bat"]):
                self.score += 40.0
                self.detections.append("MIME_EXTENSION_MISMATCH")
                self.detections.append("WEAPONIZED_ATTACHMENT")
                self.factors.append({
                    "category": "ATTACHMENT_SECURITY",
                    "impact": "+40 pts",
                    "severity": "CRITICAL",
                    "detail": f"MIME header mismatch: Payload declared as '{content_type}' but filename is '{fname}'."
                })
                break

            # 3. Direct weaponized extension
            if any(fname.endswith(ext) for ext in dangerous_exts):
                self.score += 35.0
                self.detections.append("WEAPONIZED_ATTACHMENT")
                self.factors.append({
                    "category": "ATTACHMENT_SECURITY",
                    "impact": "+35 pts",
                    "severity": "CRITICAL",
                    "detail": f"Potentially executable or macro-weaponized attachment detected: {fname}"
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

    def _score_extortion_and_blackmail(self):
        """
        Detects extortion, sextortion, and ransomware threat emails.

        These are emails where an attacker claims to possess sensitive/private data
        about the victim (webcam footage, passwords, browsing history, company files)
        and demands cryptocurrency payment to prevent exposure/leaking.

        Three sub-categories:
        - SEXTORTION: Claims of intimate recordings, webcam access, browsing history
        - EXTORTION_BLACKMAIL: Generic threats to expose data, reputation damage
        - RANSOMWARE_THREAT: Claims of file encryption, demands decryption payment

        Extortion signals are NEVER suppressed by authentication passes because
        even a legitimately-authenticated mailbox can be used to send threats
        (compromised account / ATO scenario).
        """
        subject = self.parsed.get("headers", {}).get("subject", "").lower()
        body = self.parsed.get("body", {}).get("plain_text", "").lower()
        combined = subject + " " + body

        if not combined.strip():
            return

        # ── Phase 1: Detect threat phrases ──
        matched_threats = []
        for phrase in self.EXTORTION_THREAT_PHRASES:
            if re.search(re.escape(phrase).replace(r'\.\*', '.*'), combined):
                matched_threats.append(phrase)

        # ── Phase 2: Detect payment/crypto demand indicators ──
        matched_demands = []
        for kw in self.EXTORTION_DEMAND_KEYWORDS:
            if re.search(re.escape(kw).replace(r'\.\*', '.*'), combined):
                matched_demands.append(kw)

        # ── Phase 3: Detect cryptocurrency wallet addresses ──
        # Bitcoin addresses: 1xxx, 3xxx, or bc1xxx (26-62 chars)
        btc_pattern = re.compile(r'\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
        # Monero addresses: 4xxx or 8xxx (95 chars)
        xmr_pattern = re.compile(r'\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')
        # Ethereum addresses: 0x followed by 40 hex chars
        eth_pattern = re.compile(r'\b0x[a-fA-F0-9]{40}\b')

        found_wallets = []
        for pat, name in [(btc_pattern, "Bitcoin"), (xmr_pattern, "Monero"), (eth_pattern, "Ethereum")]:
            m = pat.search(combined)
            if m:
                found_wallets.append({"type": name, "address": m.group(0)[:20] + "..."})

        if found_wallets:
            matched_demands.append(f"crypto wallet address ({found_wallets[0]['type']})")

        # ── Phase 4: Classification & Scoring ──
        if not matched_threats and not matched_demands:
            return

        # Need at least one threat phrase to classify as extortion
        # (crypto keywords alone could be legitimate financial discussion)
        if not matched_threats:
            return

        # Determine sub-category
        sextortion_indicators = [
            "webcam", "intimate", "recorded you", "captured you",
            "embarrassing", "shameful", "dirty secret", "private video"
        ]
        ransomware_indicators = [
            "encrypted your files", "decryption key", "decrypt your",
            "pay the ransom", "files have been encrypted"
        ]

        is_sextortion = any(ind in combined for ind in sextortion_indicators)
        is_ransomware = any(ind in combined for ind in ransomware_indicators)

        # Score based on severity
        if is_sextortion:
            detection_type = "SEXTORTION"
            weight = 55.0
            category_label = "Sextortion"
            severity_detail = (
                f"Sextortion threat detected: Email claims to possess intimate recordings or private material "
                f"about the recipient. Matched threat phrases: {', '.join(matched_threats[:3])}."
            )
        elif is_ransomware:
            detection_type = "RANSOMWARE_THREAT"
            weight = 60.0
            category_label = "Ransomware"
            severity_detail = (
                f"Ransomware threat detected: Email claims files have been encrypted and demands payment "
                f"for decryption. Matched indicators: {', '.join(matched_threats[:3])}."
            )
        else:
            detection_type = "EXTORTION_BLACKMAIL"
            weight = 50.0
            category_label = "Extortion / Blackmail"
            severity_detail = (
                f"Extortion/blackmail threat detected: Email threatens to expose sensitive data or "
                f"damage reputation unless demands are met. Matched phrases: {', '.join(matched_threats[:3])}."
            )

        # Escalate if crypto payment demand is present
        has_payment_demand = bool(matched_demands)
        if has_payment_demand:
            weight += 10.0
            severity_detail += (
                f" Payment demand detected: {', '.join(matched_demands[:3])}."
            )

        # Escalate further if actual wallet address found
        if found_wallets:
            weight += 5.0
            wallet_info = ", ".join(f"{w['type']}: {w['address']}" for w in found_wallets[:2])
            severity_detail += f" Cryptocurrency wallet address found: {wallet_info}."

        self.score += weight
        self.detections.append(detection_type)
        self.factors.append({
            "category": "EXTORTION_DETECTION",
            "impact": f"+{weight:.0f} pts (Critical {category_label})",
            "severity": "CRITICAL",
            "detail": severity_detail
        })

        # Add victim guidance
        self.factors.append({
            "category": "VICTIM_GUIDANCE",
            "impact": "Informational",
            "severity": "WARNING",
            "detail": (
                f"⚠️ {category_label.upper()} ALERT: Do NOT pay the attacker. "
                "These threats are almost always automated mass-scams with no actual data. "
                "Report to: (1) Local Cyber Crime Cell / Police, "
                "(2) IC3.gov (FBI Internet Crime Center) or national CERT, "
                "(3) Your organization's security team. "
                "Preserve this email as evidence for law enforcement."
            )
        })
