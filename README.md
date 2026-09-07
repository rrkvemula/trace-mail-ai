# TRACE-MAIL AI 🛡️
### AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
**Smart India Hackathon 2026** • **PS ID: SIH26106 (AICTE)**  
**Institution:** Sir C. R. Reddy College of Engineering (Autonomous), Eluru, AP  
**Team:** ShadowGuard  

---

## ⚡ Executive Overview
TRACE-MAIL AI is an SIH prototype that combines deterministic email forensics, a small trained Naive Bayes text baseline, network enrichment, and a tamper-evident local hash chain.

**TRACE-MAIL AI** bridges the gap between passive email filtering and active criminal investigation:
1. **DETECT:** Scores phishing and BEC indicators using explainable rules and a demonstration ML classifier.
2. **TRACE:** Reviews RFC 5322 `Received:` headers, timestamp consistency, and approximate network-level GeoIP data.
3. **PRESERVE:** Hashes the exact submitted bytes, stores a hash-only ledger receipt, and exports an analyst-review PDF.

The prototype does not claim a person's identity or exact location. Authentication statuses are parsed from message headers rather than independently replayed, and exported reports are technical review aids rather than automatic legal certificates.

---

## 🚀 Quickstart & Execution

```bash
cd /home/rkvemula/trace-mail-ai
python3 app.py
```

Then open your browser to:
👉 **`http://127.0.0.1:8899`**

### Pre-loaded Test Scenarios:
* **CEO BEC Fraud:** Realistic wire transfer scam with forged headers and malicious IP link.
* **Forged Relay Attack:** Demonstrates the anti-forged relay heuristic by detecting negative transit time travel ($\Delta T < 0$).
* **Legitimate Delivery:** Authenticated communication passing SPF, DKIM, and DMARC.
