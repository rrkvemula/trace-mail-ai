"""Small, dependency-free Multinomial Naive Bayes baseline for the SIH prototype.

The bundled corpus is deliberately labelled as demonstration data. It proves the
ML integration path but is not represented as a production-trained detector.
"""

import math
import re
from collections import Counter
from typing import Dict, List


PHISHING_EXAMPLES = [
    "urgent wire transfer required immediately keep this confidential",
    "verify your account now or mailbox access will be suspended",
    "invoice overdue update bank details and send payment today",
    "executive request purchase gift cards and reply with the codes",
    "security alert password expired click the login link immediately",
    "payroll update confirm credentials using the attached form",
    "unusual sign in detected validate your identity within two hours",
    "supplier bank account changed transfer funds to the new account",
    "confidential acquisition payment requested by chief executive officer",
    "your cloud storage is full sign in to prevent permanent deletion",
    "tax refund available enter card and identity information to claim",
    "shared document requires microsoft login open secure portal",
    "account suspended action required confirm username and password",
    "payment diversion request do not call me complete transfer now",
    "courier delivery failed pay a small fee using this link",
    "scholarship approved submit otp and bank details urgently",
]

LEGITIMATE_EXAMPLES = [
    "department meeting scheduled for monday agenda is attached",
    "smart india hackathon guidelines and campus screening schedule",
    "monthly project status update for review by the faculty mentor",
    "library reminder borrowed books are due next week",
    "class timetable revision for the upcoming semester",
    "minutes from the cybersecurity club planning meeting",
    "conference registration confirmation and venue information",
    "student attendance report available on the college portal",
    "approved leave request recorded by the human resources office",
    "software maintenance notification for saturday evening",
    "research paper feedback from the project supervisor",
    "invoice receipt for the previously completed approved purchase",
    "campus placement orientation schedule and eligibility criteria",
    "password change confirmation requested by the signed in user",
    "weekly security awareness bulletin from the internal team",
    "course assignment submission acknowledgement and reference number",
]

STOPWORDS = {
    "the", "and", "for", "from", "to", "this", "that", "with", "your", "you", "our", "are", "was",
    "were", "will", "have", "has", "had", "into", "using", "use", "not", "but", "all", "new",
    "now", "today", "please", "their", "they", "them", "its", "can", "may", "email", "message",
    "required", "available", "information", "submitted", "request", "account", "portal", "within",
}


class PrototypeTextClassifier:
    """Trains a Naive Bayes text classifier on the bundled demonstration corpus."""

    def __init__(self):
        self.class_counts = {"phishing": Counter(), "legitimate": Counter()}
        for sample in PHISHING_EXAMPLES:
            self.class_counts["phishing"].update(self._tokens(sample))
        for sample in LEGITIMATE_EXAMPLES:
            self.class_counts["legitimate"].update(self._tokens(sample))
        self.vocabulary = set(self.class_counts["phishing"]) | set(self.class_counts["legitimate"])
        self.totals = {label: sum(counts.values()) for label, counts in self.class_counts.items()}

    @staticmethod
    def _tokens(value: str) -> List[str]:
        return re.findall(r"[a-z0-9]{2,}", value.lower())

    def predict(self, text: str) -> Dict[str, object]:
        tokens = self._tokens(text)
        if not tokens:
            return self._result(0.5, [])

        vocab_size = max(1, len(self.vocabulary))
        log_scores = {"phishing": math.log(0.5), "legitimate": math.log(0.5)}
        token_counts = Counter(tokens)

        for label in log_scores:
            denominator = self.totals[label] + vocab_size
            for token, frequency in token_counts.items():
                probability = (self.class_counts[label][token] + 1) / denominator
                log_scores[label] += frequency * math.log(probability)

        normalized_log_odds = (log_scores["phishing"] - log_scores["legitimate"]) / max(1.0, math.sqrt(len(token_counts)))
        normalized_log_odds = max(-12.0, min(12.0, normalized_log_odds))
        phishing_probability = 1.0 / (1.0 + math.exp(-normalized_log_odds))

        indicators = []
        for token in set(tokens):
            if token in STOPWORDS:
                continue
            phishing_weight = (self.class_counts["phishing"][token] + 1) / (self.totals["phishing"] + vocab_size)
            legitimate_weight = (self.class_counts["legitimate"][token] + 1) / (self.totals["legitimate"] + vocab_size)
            log_odds = math.log(phishing_weight / legitimate_weight)
            if log_odds > 0.45:
                indicators.append((log_odds, token))
        indicators = [token for _, token in sorted(indicators, reverse=True)[:5]]
        return self._result(phishing_probability, indicators)

    @staticmethod
    def _result(probability: float, indicators: List[str]) -> Dict[str, object]:
        return {
            "label": "PHISHING_LIKELY" if probability >= 0.65 else "LEGITIMATE_LIKELY" if probability <= 0.35 else "UNCERTAIN",
            "phishing_probability": round(probability, 4),
            "matched_indicators": indicators,
            "algorithm": "MULTINOMIAL_NAIVE_BAYES",
            "training_source": "Bundled demonstration corpus (32 labelled phrases)",
            "validation_status": "PROTOTYPE_NOT_PRODUCTION_VALIDATED",
        }


CLASSIFIER = PrototypeTextClassifier()
