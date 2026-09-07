"""
Threat Scorer & Explainable Risk Engine
Evaluates linguistic urgency, BEC indicators (wire transfer, gift cards),
domain typosquatting, link reputation, and generates an explainability matrix.
"""

import re
from typing import Dict, Any, List

class ThreatScorer:
    """Calculates a composite threat score (0-100) with explainable risk breakdown."""

    # High-risk financial & coercion triggers (BEC)
    URGENCY_KEYWORDS = [
        "urgent", "immediately", "overdue", "account suspended", "verify your account",
        "action required", "wire transfer", "bank transfer", "invoice attached",
        "gift card", "direct deposit", "payroll", "swift", "confidential request",
        "fund transfer", "payment diversion", "credentials expired", "password reset"
    ]

    SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work", ".cam"}

    def __init__(self, parsed_email: Dict[str, Any], auth_results: Dict[str, Any], hop_results: Dict[str, Any], ml_result: Dict[str, Any] = None):
        self.parsed = parsed_email
        self.auth = auth_results
        self.hop = hop_results
        self.ml_result = ml_result or {}
        self.score = 0.0
        self.factors: List[Dict[str, Any]] = []

    def calculate(self) -> Dict[str, Any]:
        """Calculates total score and builds the explainability breakdown."""
        self._score_authentication()
        self._score_hops_and_latency()
        self._score_linguistic_urgency()
        self._score_ml_baseline()
        self._score_links_and_attachments()
        self._score_display_spoofing()

        # Clamp score between 0 and 100
        final_score = max(0.0, min(100.0, round(self.score, 1)))

        # Categorize
        if final_score >= 70:
            category = "HIGH_RISK"
            color = "#F87171" # Red
            verdict = "HIGH RISK — ANALYST REVIEW REQUIRED"
        elif final_score >= 35:
            category = "SUSPICIOUS"
            color = "#FFD166" # Gold
            verdict = "ELEVATED RISK — REVIEW RECOMMENDED"
        else:
            category = "LOW_OBSERVED_RISK"
            color = "#4ADE80" # Green
            verdict = "LOW OBSERVED RISK — NOT A SAFETY GUARANTEE"

        return {
            "threat_score": final_score,
            "risk_category": category,
            "badge_color": color,
            "verdict": verdict,
            "explainability_factors": self.factors,
            "analysis_method": "HYBRID_RULES_PLUS_NAIVE_BAYES",
            "model_status": "Prototype ML baseline; production dataset validation is still required"
        }

    def _score_authentication(self):
        """Penalizes failed SPF, DKIM, and DMARC alignment."""
        spf_status = self.auth.get("spf", {}).get("status", "NONE")
        dkim_status = self.auth.get("dkim", {}).get("status", "NONE")
        dmarc_status = self.auth.get("dmarc", {}).get("status", "NONE")

        if dmarc_status == "FAIL":
            self.score += 35.0
            self.factors.append({
                "category": "AUTHENTICATION",
                "impact": "+35 pts",
                "detail": "The submitted Authentication-Results header reports DMARC failure."
            })
        elif dmarc_status == "NONE":
            self.score += 15.0
            self.factors.append({
                "category": "AUTHENTICATION",
                "impact": "+15 pts",
                "detail": "No receiver-reported DMARC result was present in the submitted message."
            })

        if spf_status == "FAIL":
            self.score += 20.0
            self.factors.append({
                "category": "AUTHENTICATION",
                "impact": "+20 pts",
                "detail": "The submitted authentication headers report SPF failure."
            })

    def _score_hops_and_latency(self):
        """Penalizes forged relay headers and negative latency."""
        if self.hop.get("has_timing_anomalies"):
            self.score += 40.0
            self.factors.append({
                "category": "RELAY_INTEGRITY",
                "impact": "+40 pts",
                "detail": "Reversed relay timestamps were detected. Possible causes include clock skew, malformed data, or header manipulation."
            })

    def _score_linguistic_urgency(self):
        """Scans subject and body for urgency and financial fraud keywords."""
        subject = self.parsed.get("headers", {}).get("subject", "").lower()
        body = self.parsed.get("body", {}).get("plain_text", "").lower()
        combined = subject + " " + body

        matched_keywords = []
        for kw in self.URGENCY_KEYWORDS:
            if re.search(r'\b' + re.escape(kw) + r'\b', combined):
                matched_keywords.append(kw)

        if matched_keywords:
            weight = min(30.0, len(matched_keywords) * 6.0)
            self.score += weight
            self.factors.append({
                "category": "CONTENT_ANALYSIS",
                "impact": f"+{weight:.0f} pts",
                "detail": f"Detected {len(matched_keywords)} social engineering / BEC urgency indicators: {', '.join(matched_keywords[:4])}"
            })

    def _score_ml_baseline(self):
        """Adds a bounded contribution from the trained demonstration classifier."""
        probability = float(self.ml_result.get("phishing_probability", 0.5))
        if probability < 0.65:
            return
        weight = 18.0 if probability >= 0.85 else 12.0
        indicators = self.ml_result.get("matched_indicators", [])
        detail = f"Prototype Naive Bayes model estimated {probability * 100:.1f}% phishing probability"
        if indicators:
            detail += f"; influential terms: {', '.join(indicators)}"
        self.score += weight
        self.factors.append({
            "category": "ML_BASELINE",
            "impact": f"+{weight:.0f} pts",
            "detail": detail + ". This model uses a small demonstration corpus and is not production validated."
        })

    def _score_links_and_attachments(self):
        """Inspects embedded links and attachments for known evasion tactics."""
        links = self.parsed.get("body", {}).get("links", [])
        for link in links:
            lower_link = link.lower()
            if any(lower_link.endswith(tld) or f"{tld}/" in lower_link for tld in self.SUSPICIOUS_TLDS):
                self.score += 15.0
                self.factors.append({
                    "category": "URL_REPUTATION",
                    "impact": "+15 pts",
                    "detail": f"Suspicious top-level domain (TLD) found in link: {link[:50]}"
                })
                break

            # Check if link is an IP address instead of a domain (common phishing pattern)
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link):
                self.score += 20.0
                self.factors.append({
                    "category": "URL_REPUTATION",
                    "impact": "+20 pts",
                    "detail": f"Link uses a raw IP address instead of a hostname: {link[:50]}"
                })
                break

        # Attachments inspection (e.g. .exe, .scr, .iso, .vbs)
        for att in self.parsed.get("attachments", []):
            fname = att.get("filename", "").lower()
            if any(fname.endswith(ext) for ext in [".exe", ".scr", ".iso", ".vbs", ".bat", ".hta", ".docm"]):
                self.score += 35.0
                self.factors.append({
                    "category": "ATTACHMENT_SECURITY",
                    "impact": "+35 pts",
                    "detail": f"Executable or weaponized attachment detected: {fname}"
                })
                break

    def _score_display_spoofing(self):
        """Detects display name spoofing (e.g. 'CEO Name' <random_gmail@gmail.com>)."""
        from_hdr = self.parsed.get("headers", {}).get("from", "")
        # If display name looks corporate/executive but sender is free email
        free_providers = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
        if "<" in from_hdr and ">" in from_hdr:
            display_name = from_hdr.split("<")[0].strip().strip('"').lower()
            addr = from_hdr.split("<")[1].split(">")[0].strip().lower()
            if any(executive_title in display_name for executive_title in ["ceo", "director", "principal", "hr", "payroll", "admin"]):
                if any(fp in addr for fp in free_providers):
                    self.score += 25.0
                    self.factors.append({
                        "category": "IMPERSONATION",
                        "impact": "+25 pts",
                        "detail": f"Display-name spoofing detected: Executive persona '{display_name}' sent from personal address '{addr}'."
                    })
