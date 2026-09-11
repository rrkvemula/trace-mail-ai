"""
Production Text Threat Classifier for TRACE-MAIL AI.
Integrates trained Scikit-Learn TF-IDF N-gram Logistic Regression model,
with seamless fallback to the lightweight Multinomial Naive Bayes baseline.
"""

import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import joblib
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
CLF_PATH = MODELS_DIR / "threat_classifier.joblib"
VEC_PATH = MODELS_DIR / "tfidf_vectorizer.joblib"

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


class ProductionTextClassifier:
    """Trained ML Text Threat Classifier with fallback to Prototype Naive Bayes."""

    def __init__(self):
        self.trained_clf = None
        self.vectorizer = None
        self.feature_names = None
        self._load_trained_model()

        # Initialize fallback baseline
        self.class_counts = {"phishing": Counter(), "legitimate": Counter()}
        for sample in PHISHING_EXAMPLES:
            self.class_counts["phishing"].update(self._tokens(sample))
        for sample in LEGITIMATE_EXAMPLES:
            self.class_counts["legitimate"].update(self._tokens(sample))
        self.vocabulary = set(self.class_counts["phishing"]) | set(self.class_counts["legitimate"])
        self.totals = {label: sum(counts.values()) for label, counts in self.class_counts.items()}

    def _load_trained_model(self):
        if SKLEARN_AVAILABLE and CLF_PATH.exists() and VEC_PATH.exists():
            try:
                self.trained_clf = joblib.load(CLF_PATH)
                self.vectorizer = joblib.load(VEC_PATH)
                self.feature_names = np.array(self.vectorizer.get_feature_names_out())
            except Exception:
                self.trained_clf = None
                self.vectorizer = None

    @staticmethod
    def _tokens(value: str) -> List[str]:
        return re.findall(r"[a-z0-9]{2,}", value.lower())

    def predict(self, text: str) -> Dict[str, object]:
        if not text or not text.strip():
            return self._result(0.5, [], is_fallback=True)

        # 1. Use Production Scikit-Learn Model if available
        if self.trained_clf is not None and self.vectorizer is not None:
            try:
                X = self.vectorizer.transform([text])
                probs = self.trained_clf.predict_proba(X)[0]  # [Legit, Phishing, BEC]
                p_legit = float(probs[0])
                p_phish = float(probs[1])
                p_bec = float(probs[2])
                threat_prob = max(0.0, min(1.0, p_phish + p_bec))

                # Extract top indicative features present in input
                indicators = []
                nz = X.nonzero()[1]
                if len(nz) > 0 and self.feature_names is not None:
                    # Combined threat weight (phishing + BEC coefficients)
                    threat_coef = self.trained_clf.coef_[1] + self.trained_clf.coef_[2]
                    scored_features = [(threat_coef[i] * X[0, i], self.feature_names[i]) for i in nz]
                    scored_features.sort(reverse=True)
                    indicators = [feat for score, feat in scored_features[:5] if score > 0]

                # If benign, extract top benign indicators
                if not indicators and p_legit > 0.6 and len(nz) > 0:
                    legit_coef = self.trained_clf.coef_[0]
                    scored_features = [(legit_coef[i] * X[0, i], self.feature_names[i]) for i in nz]
                    scored_features.sort(reverse=True)
                    indicators = [feat for score, feat in scored_features[:3] if score > 0]

                # Label determination
                if p_bec >= 0.5:
                    label = "PHISHING_LIKELY"
                elif threat_prob >= 0.65:
                    label = "PHISHING_LIKELY"
                elif threat_prob <= 0.35:
                    label = "LEGITIMATE_LIKELY"
                else:
                    label = "UNCERTAIN"

                return {
                    "label": label,
                    "phishing_probability": round(threat_prob, 4),
                    "matched_indicators": indicators,
                    "algorithm": "TF-IDF + Calibrated Multi-Class Logistic Regression",
                    "training_source": "Curated 1,245-sample corpus (Legitimate, Phishing, BEC)",
                    "validation_status": "TRAINED_PRODUCTION_SCIKIT_LEARN",
                    "class_probabilities": {
                        "legitimate": round(p_legit, 4),
                        "phishing": round(p_phish, 4),
                        "bec_fraud": round(p_bec, 4)
                    }
                }
            except Exception:
                pass  # Fall back to Naive Bayes baseline on error

        # 2. Fallback: Prototype Naive Bayes
        tokens = self._tokens(text)
        if not tokens:
            return self._result(0.5, [], is_fallback=True)

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
        return self._result(phishing_probability, indicators, is_fallback=True)

    @staticmethod
    def _result(probability: float, indicators: List[str], is_fallback: bool = False) -> Dict[str, object]:
        return {
            "label": "PHISHING_LIKELY" if probability >= 0.65 else "LEGITIMATE_LIKELY" if probability <= 0.35 else "UNCERTAIN",
            "phishing_probability": round(probability, 4),
            "matched_indicators": indicators,
            "algorithm": "MULTINOMIAL_NAIVE_BAYES" if is_fallback else "TF-IDF + Calibrated Logistic Regression",
            "training_source": "Bundled demonstration corpus (32 labelled phrases)" if is_fallback else "Curated 1,245-sample corpus (Legitimate, Phishing, BEC)",
            "validation_status": "PROTOTYPE_NOT_PRODUCTION_VALIDATED" if is_fallback else "TRAINED_PRODUCTION_SCIKIT_LEARN",
        }


PrototypeTextClassifier = ProductionTextClassifier
CLASSIFIER = ProductionTextClassifier()
