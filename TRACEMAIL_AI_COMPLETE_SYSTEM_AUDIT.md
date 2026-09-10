# 🛡️ TRACE-MAIL AI: COMPLETE FORENSIC PLATFORM EXPORT & BUG-HUNTING AUDIT DOSSIER
**Author / Security Architect:** Ram Karthik (RK) — Shadow Monarch
**Project Focus:** Production-Grade RFC 5322 Forensic Email Threat Intelligence, BEC Invariant Verification, GeoINT Planetary Radar, and Cryptographic Evidence Chain
**Target Audience for this Document:** Advanced AI Code Reviewers, Security Researchers, and Vulnerability Auditors (Claude 3.5 Sonnet, GPT-4o, DeepSeek-R1, o1-preview)

---

## 🎯 INSTRUCTIONS FOR THE AUDITING AI MODEL
> You are acting as an **Elite Principal Application Security & RFC Compliance Auditor**.
> Below is the entire production source code for **TraceMail AI** (Frontend, REST API, Core Forensic Engine, and Test Suite).
> 
> ### Your Audit Mandate:
> 1. **RFC 5322 & Email Invariant Violations**: Check `engine/parser.py` and `engine/hop_analyzer.py` for edge cases (CRLF injection, header folding, multi-line headers, missing Message-ID, malformed Received hops, IPv6 parsing bugs).
> 2. **Threat Detection & Scoring Flaws**: Check `engine/threat_scorer.py` and `engine/auth_validator.py` for logic bypasses, false positives on legitimate urgent business communications, and false negatives in compromised vendor account takeovers (BEC).
> 3. **Application Security & Exploitation**:
>    - **SSRF**: Ensure `engine/url_scanner.py` never issues outbound HTTP calls to attacker-controlled targets.
>    - **XSS**: Audit `templates/index.html` (specifically tooltip generation, innerHTML insertions, and JSON rendering) for stored/DOM XSS via attacker-crafted headers or email body.
>    - **ReDoS / Algorithmic Complexity**: Check all regular expressions across the engine for catastrophic backtracking.
> 4. **Evidence & Cryptographic Chain Integrity**: Verify `engine/evidence_ledger.py` ensures tamper-evident SHA-256 hash chains.
> 5. **Frontend / Backend Schema Cohesion**: Verify that all fields returned by `app.py` are properly rendered and handled in `templates/index.html` without null reference crashes.
> 6. **Production Robustness**: Identify blocking synchronous I/O in async FastAPI routes or memory bottlenecks when parsing 5MB multipart payloads.

---

## 🏗️ SYSTEM ARCHITECTURE & DATA FLOW

```
[ Inbound Raw RFC 5322 Email / .eml ]
                   │
                   ▼
       [ EmailParser (parser.py) ]
       ├── Computes SHA-256 Forensic Hash
       ├── Extracts Headers, MIME Body, Attachments
       └── Isolates Received Hops & Client Origin IP
                   │
                   ▼
     [ HopAnalyzer (hop_analyzer.py) ] <─── [ GeoIPResolver (geoip_resolver.py) ]
     ├── Traversal from Ingestion to Edge   ├── ASN & ISP Enrichment
     ├── Latency Delta Timing (ΔT)          ├── Tor Exit Node Detection
     └── Forged Relay Detection             └── Datacenter / Bulletproof Flagging
                   │
                   ▼
     [ AuthValidator (auth_validator.py) ]
     ├── SPF Evaluation (Envelope vs Header From)
     ├── DKIM Alignment & Cryptographic Signatures
     └── DMARC Policy Enforcement (Reject / Quarantine / None)
                   │
                   ▼
     [ Safe URLScanner (url_scanner.py) ]
     ├── Zero-Request Static Inspection
     ├── Punycode / IDN Homograph Detection
     └── Cloud Metadata / Private IP SSRF Shield
                   │
                   ▼
     [ ThreatScorer (threat_scorer.py) ] <─── [ MLClassifier (ml_classifier.py) ]
     ├── Multi-Signal BEC Engine             └── Logistic / TF-IDF Heuristic
     ├── Financial Diversion / Wire Urgency
     └── Out-of-Band Verification Requirement
                   │
                   ▼
    ┌──────────────┴──────────────────┐
    ▼                                 ▼
[ IOCGraphBuilder (ioc_graph.py) ]   [ EvidenceLedger (evidence_ledger.py) ]
└── Generates D3-compatible Nodes/Edges  └── Merkle-style Append-Only Chain
                   │
                   ▼
      [ FastAPI Backend (app.py) ]
                   │
                   ▼
     [ Frontend (templates/index.html) ]
     ├── 3D Globe GeoINT Telemetry Radar (Three-Globe)
     ├── In-Console Sample Repository (9 Attack Scenarios)
     ├── 6-Tab Forensic Deep Dive Explorer
     └── Court-Ready PDF Dossier Export
```

---

## 📂 COMPLETE SOURCE CODE REPOSITORY


### 📄 File: `requirements.txt`
```text
fastapi>=0.100.0
uvicorn>=0.22.0
dnspython>=2.3.0
reportlab>=4.0.0
requests>=2.31.0
aiofiles>=23.1.0
python-multipart>=0.0.6
jinja2>=3.1.0

```


### 📄 File: `app.py`
```python
"""
TRACE-MAIL AI - FastAPI Forensic Intelligence Server
AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
Adheres strictly to RFC 5322/7489, zero-request safe link inspection (anti-SSRF),
tamper-evident evidence ledger, and explainable multi-signal threat scoring.
"""

import os
import re
import tempfile
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.background import BackgroundTask

from engine.pipeline import ForensicPipeline
from engine.evidence_generator import EvidenceGenerator
from engine.evidence_ledger import EvidenceLedger
from engine.url_scanner import URLScanner

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
SAMPLES_DIR = os.path.join(BASE_DIR, "sample_emails")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DATA_DIR = os.path.join(BASE_DIR, "data")

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

MAX_INPUT_BYTES = 5 * 1024 * 1024
MAX_CACHED_ANALYSES = 50
ANALYSIS_CACHE = OrderedDict()
LEDGER = EvidenceLedger(os.path.join(DATA_DIR, "evidence_ledger.jsonl"))

app = FastAPI(
    title="TRACE-MAIL AI Forensic Server",
    version="2.1.0",
    description="Evidence-Based Email Threat Detection, Geolocation & Forensic Intelligence Platform"
)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ExportRequest(BaseModel):
    analysis_id: str


class ChatRequest(BaseModel):
    message: str
    report: Optional[Dict[str, Any]] = None
    analysis_id: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = None
    model: Optional[str] = None


def remember_analysis(report: dict) -> None:
    ANALYSIS_CACHE[report["analysis_id"]] = report
    ANALYSIS_CACHE.move_to_end(report["analysis_id"])
    while len(ANALYSIS_CACHE) > MAX_CACHED_ANALYSES:
        ANALYSIS_CACHE.popitem(last=False)


def remove_file(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def build_ui_compatible_payload(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms the consolidated ForensicPipeline report into the structure
    expected by the interactive web dashboard without losing forensic fidelity.
    """
    threat = report.get("threat_analysis", {})
    auth = report.get("authentication", {})
    hdr = report.get("headers", {})
    hops_data = report.get("hops_analysis", {})
    origin_geo = report.get("origin_geo", {})
    body_summary = report.get("body_summary", {})
    scanned_links = body_summary.get("scanned_links", [])

    # Format links for the UI (zero network calls, purely static)
    ui_links = []
    for sl in scanned_links:
        ui_links.append({
            "original": sl.get("original", ""),
            "final": sl.get("normalized", ""),
            "redirects": 0,
            "punycode": sl.get("punycode", False),
            "suspicious": sl.get("suspicious", False),
            "is_internal_or_ssrf": sl.get("is_internal_or_ssrf", False),
            "risk_reasons": sl.get("risk_reasons", [])
        })

    # Header invariants and summary
    spf_pass = auth.get("spf", {}).get("status") == "PASS"
    dkim_pass = auth.get("dkim", {}).get("status") == "PASS"
    dmarc_pass = auth.get("dmarc", {}).get("status") == "PASS" or auth.get("composite_pass", False)

    reasons = [f.get("detail", "") for f in threat.get("explainability_factors", [])]
    if not reasons:
        reasons = ["Normal forensic delivery profile; cryptographic invariants verified."]

    # Hosting flags from origin GeoIP
    hosting_flags = []
    if origin_geo.get("is_tor"):
        hosting_flags.append("Tor Exit Node")
    if origin_geo.get("is_cloud_hosting"):
        hosting_flags.append(f"Cloud/Datacenter Provider ({origin_geo.get('asn', '')})")
    if origin_geo.get("is_suspicious_infra"):
        hosting_flags.append("Anonymized / Proxy Network")

    threat_score = int(threat.get("threat_score", 0))
    risk_level = threat.get("risk_category", "LOW_OBSERVED_RISK").replace("_", " ")

    bec_type = "none"
    for det in threat.get("detections", []):
        if "BEC_VENDOR_FINANCIAL_DIVERSION" in det:
            bec_type = "payment diversion / wire fraud"
            break
        elif "DISPLAY_NAME_SPOOFING" in det:
            bec_type = "executive impersonation"
        elif "SSRF_INTERNAL_TARGET" in det or "PUNYCODE_LOOKALIKE" in det:
            bec_type = "credential harvesting"

    # ML label
    ml_prob = report.get("ml_analysis", {}).get("phishing_probability", 0.1)
    if threat_score >= 70 or ml_prob > 0.8:
        label = "fraud" if bec_type != "none" else "phishing"
    elif threat_score >= 35 or ml_prob > 0.5:
        label = "suspicious"
    else:
        label = "legitimate"

    hops_analyzed = hops_data.get("analyzed_hops", [])
    hops_count = len(hops_analyzed)

    # Safe MX list mapping (never a raw string to prevent frontend .map() crash)
    mx_list = auth.get("dns_published_policies", {}).get("mx_records") or []
    if not mx_list:
        spf_rec = auth.get("dns_published_policies", {}).get("spf_record")
        if isinstance(spf_rec, str) and spf_rec.strip():
            mx_list = [f"SPF: {spf_rec.strip()}"]
        elif isinstance(spf_rec, list):
            mx_list = spf_rec
        else:
            mx_list = []
    elif isinstance(mx_list, str):
        mx_list = [mx_list]

    # Map GeoIP properties for 3D Globe (lat, lon, loc, org)
    geo_payload = dict(origin_geo)
    lat_val = geo_payload.get("latitude") or geo_payload.get("lat")
    lon_val = geo_payload.get("longitude") or geo_payload.get("lon")
    org_val = geo_payload.get("organization") or geo_payload.get("org") or "Internal / ISP"
    geo_payload["lat"] = lat_val
    geo_payload["lon"] = lon_val
    geo_payload["latitude"] = lat_val
    geo_payload["longitude"] = lon_val
    geo_payload["org"] = org_val
    geo_payload["organization"] = org_val
    geo_payload["loc"] = f"{lat_val},{lon_val}" if lat_val is not None and lon_val is not None else None

    return {
        "fraud_score": threat_score,
        "risk_level": risk_level,
        "label": label,
        "confidence": int(threat.get("confidence_score", 85)),
        "enforcement_action": threat.get("enforcement_action", "ALLOW"),
        "headers": {
            "spf": spf_pass,
            "dkim": dkim_pass,
            "dmarc": dmarc_pass,
            "from": hdr.get("from", ""),
            "return_path": hdr.get("return_path", ""),
            "reply_to": hdr.get("reply_to", ""),
            "message_id": hdr.get("message_id", ""),
            "origin_ip": report.get("origin_ip") or "Loopback / Internal",
            "hops": hops_count,
            "total_hops": hops_count,
            "hops_list": hops_analyzed,
            "spoof_score": threat_score,
            "reasons": reasons
        },
        "links": ui_links,
        "ai": {
            "label": label,
            "bec_type": bec_type,
            "fraud_score": threat_score,
            "confidence": int(threat.get("confidence_score", 85)),
            "reasons": reasons
        },
        "trace": {
            "geo": geo_payload,
            "mx": mx_list,
            "hosting_flags": hosting_flags
        },
        "hops_analysis": hops_data,
        "authentication": auth,
        "threat_analysis": threat,
        "ml_analysis": report.get("ml_analysis", {}),
        "ioc_graph": report.get("ioc_graph", {}),
        "body_summary": body_summary,
        "evidence_hash": report.get("forensic_hash"),
        "timestamp": report.get("parsed_at_utc") or datetime.now(timezone.utc).isoformat()
    }


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the primary forensic dashboard."""
    index_path = os.path.join(TEMPLATES_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>TRACE-MAIL AI Forensic Dashboard Loading...</h1>"


@app.get("/api/samples")
async def list_samples():
    """Lists available test sample emails."""
    samples = []
    if os.path.exists(SAMPLES_DIR):
        for fname in os.listdir(SAMPLES_DIR):
            if fname.endswith(".eml"):
                samples.append(fname)
    return {"samples": sorted(samples)}


@app.get("/api/sample/{name}")
async def get_sample_content(name: str):
    """Retrieves content of a pre-built sample email."""
    if Path(name).name != name or not name.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Invalid sample name")
    file_path = Path(SAMPLES_DIR, name).resolve()
    if file_path.parent != Path(SAMPLES_DIR).resolve() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Sample not found")
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        return {"filename": name, "content": f.read()}


@app.get("/health")
@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "platform": "TRACE-MAIL AI Forensic Intelligence",
        "version": app.version,
        "pipeline": "Active (RFC 5322/7489, Safe URL Inspection, Tamper-Evident Ledger)",
        "cached_analyses": len(ANALYSIS_CACHE)
    }


@app.post("/scan")
async def scan(
    request: Request,
    eml: Optional[UploadFile] = File(None),
    email_body: Optional[str] = Form(None)
):
    """
    Primary scanning endpoint for the web interface.
    Safely routes raw content through the ForensicPipeline without SSRF risks.
    """
    content = b""
    filename = "pasted-email.eml"

    if eml and eml.filename:
        filename = Path(eml.filename).name
        content = await eml.read(MAX_INPUT_BYTES + 1)
    elif email_body and email_body.strip():
        content = email_body.strip().encode("utf-8")
    else:
        # Check if sent as raw JSON
        try:
            body_json = await request.json()
            if isinstance(body_json, dict):
                raw_val = body_json.get("body", "") or body_json.get("email_body", "")
                if raw_val:
                    content = raw_val.encode("utf-8")
        except Exception:
            pass

    if not content or not content.strip():
        raise HTTPException(status_code=400, detail="Provide an email file (.eml) or raw RFC 5322 email text.")

    if len(content) > MAX_INPUT_BYTES:
        raise HTTPException(status_code=413, detail="Email payload exceeds the 5 MB limit.")

    try:
        # Run through single source of truth: ForensicPipeline
        report = ForensicPipeline.process_raw_email(content)
        analysis_id = f"ANL-{uuid.uuid4().hex[:12].upper()}"
        report["analysis_id"] = analysis_id
        report["input_metadata"] = {
            "filename": filename,
            "size_bytes": len(content),
            "is_demo_sample": filename in set(os.listdir(SAMPLES_DIR)) if os.path.exists(SAMPLES_DIR) else False,
        }
        report["ledger_receipt"] = LEDGER.append(analysis_id, report["forensic_hash"])
        remember_analysis(report)

        # Return UI-compatible consolidated payload
        return build_ui_compatible_payload(report)

    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Forensic analysis failed: {str(ex)}")


@app.post("/api/analyze")
async def analyze_email(
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    source_name: Optional[str] = Form(None),
):
    """API endpoint for raw forensic analysis pipeline."""
    content = b""
    filename = source_name or "pasted-email.eml"

    if file and file.filename:
        filename = Path(file.filename).name
        file_bytes = await file.read(MAX_INPUT_BYTES + 1)
        if file_bytes and file_bytes.strip():
            content = file_bytes

    if not content and raw_text and raw_text.strip():
        content = raw_text.encode("utf-8")
        filename = source_name or "pasted-email.eml"

    if not content or not content.strip():
        raise HTTPException(status_code=400, detail="Provide an email file or raw text.")

    if len(content) > MAX_INPUT_BYTES:
        raise HTTPException(status_code=413, detail="Email exceeds the 5 MB prototype limit")

    try:
        report = ForensicPipeline.process_raw_email(content)
        report["analysis_id"] = f"ANL-{uuid.uuid4().hex[:12].upper()}"
        report["input_metadata"] = {
            "filename": filename,
            "size_bytes": len(content),
            "is_demo_sample": filename in set(os.listdir(SAMPLES_DIR)) if os.path.exists(SAMPLES_DIR) else False,
        }
        report["ledger_receipt"] = LEDGER.append(report["analysis_id"], report["forensic_hash"])
        remember_analysis(report)
        return report

    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Forensic analysis failed: {str(ex)}")


@app.post("/api/export-pdf")
async def export_forensic_pdf(payload: ExportRequest):
    """Generates a certified PDF forensic report from a cached analysis."""
    report = ANALYSIS_CACHE.get(payload.analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Analysis expired or was not found; please scan again.")
    tmp_path = None
    try:
        tmp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf", dir=REPORTS_DIR)
        tmp_pdf.close()
        tmp_path = tmp_pdf.name
        EvidenceGenerator.generate_pdf(report, tmp_path)
        return FileResponse(
            tmp_path,
            media_type="application/pdf",
            filename=f"TRACE-MAIL-REPORT-{report.get('forensic_hash', 'DOC')[:8].upper()}.pdf",
            background=BackgroundTask(remove_file, tmp_path),
        )
    except Exception as ex:
        if tmp_path:
            remove_file(tmp_path)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(ex)}")


@app.post("/api/copilot/chat")
@app.post("/api/chat")
async def copilot_chat(payload: ChatRequest):
    """
    Forensic AI Copilot Endpoint.
    Conversational assistant for explaining investigation reports, RFC 5322
    headers, domain WHOIS telemetry, MTA hops, and out-of-band verification.
    """
    from engine.copilot_engine import ForensicCopilot

    report_context = payload.report
    if not report_context and payload.analysis_id:
        cached = ANALYSIS_CACHE.get(payload.analysis_id)
        if cached:
            report_context = build_ui_compatible_payload(cached)

    # Fallback to the latest analysis in cache if report is empty
    if not report_context and ANALYSIS_CACHE:
        try:
            latest_id = list(ANALYSIS_CACHE.keys())[-1]
            report_context = build_ui_compatible_payload(ANALYSIS_CACHE[latest_id])
        except Exception:
            pass

    response = ForensicCopilot.query(
        user_message=payload.message,
        report=report_context,
        history=payload.history,
        preferred_model=payload.model
    )
    return response


if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting TRACE-MAIL AI Forensic Platform on http://127.0.0.1:8899")
    uvicorn.run(app, host="0.0.0.0", port=8899)

```


### 📄 File: `engine/pipeline.py`
```python
"""
Consolidated Forensic Pipeline Orchestrator
Coordinates ingestion, hop unrolling, cryptographic auth,
GeoIP enrichment, latency delta heuristics, and threat scoring.
"""

from typing import Dict, Any, Union
from .parser import EmailParser
from .hop_analyzer import HopAnalyzer
from .auth_validator import AuthValidator
from .geoip_resolver import GeoIPResolver
from .threat_scorer import ThreatScorer
from .ml_classifier import CLASSIFIER
from .ioc_graph import IOCGraphBuilder

class ForensicPipeline:
    """Orchestrates the entire TRACE-MAIL AI forensic workflow."""

    @classmethod
    def process_raw_email(cls, raw_email_content: Union[str, bytes]) -> Dict[str, Any]:
        # 1. Parse Envelope & MIME Structure
        parser = EmailParser(raw_email_content)
        parsed_data = parser.parse()

        # 2. Enrich Hops with Geolocation Telemetry
        enriched_hops = []
        for h in parsed_data.get("hops", []):
            hop_copy = dict(h)
            ip_to_resolve = hop_copy.get("ip")
            hop_copy["geo"] = GeoIPResolver.resolve(ip_to_resolve)
            enriched_hops.append(hop_copy)

        # 3. Analyze Hop Latency & Anti-Forged Relay Heuristics (ΔT)
        hop_analyzer = HopAnalyzer(enriched_hops)
        hop_results = hop_analyzer.analyze()

        # 4. Cryptographic Authentication & DMARC Alignment
        auth_validator = AuthValidator(parsed_data.get("headers", {}))
        auth_results = auth_validator.audit()

        # 5. Train-at-start prototype ML baseline plus explainable rule scoring
        ml_text = " ".join([
            parsed_data.get("headers", {}).get("subject", ""),
            parsed_data.get("body", {}).get("plain_text", ""),
        ])
        ml_results = CLASSIFIER.predict(ml_text)
        threat_scorer = ThreatScorer(parsed_data, auth_results, hop_results, ml_results)
        threat_results = threat_scorer.calculate()
        ioc_graph = IOCGraphBuilder.build(parsed_data, hop_results.get("analyzed_hops", []))

        # 6. Resolve Origin IP Geolocation
        origin_ip = parsed_data.get("origin_ip")
        origin_geo = GeoIPResolver.resolve(origin_ip)

        # 7. Safe Static Link Analysis (Zero SSRF)
        from .url_scanner import URLScanner
        scanned_links = URLScanner.scan_all(parsed_data.get("body", {}).get("links", []))

        # Build Consolidated Forensic Payload
        return {
            "forensic_hash": parsed_data.get("forensic_hash"),
            "parsed_at_utc": parsed_data.get("parsed_at_utc"),
            "headers": parsed_data.get("headers"),
            "origin_ip": origin_ip,
            "origin_evidence": parsed_data.get("origin_evidence"),
            "origin_geo": origin_geo,
            "hops_analysis": hop_results,
            "authentication": auth_results,
            "threat_analysis": threat_results,
            "ml_analysis": ml_results,
            "ioc_graph": ioc_graph,
            "body_summary": {
                "plain_text_snippet": parsed_data.get("body", {}).get("plain_text", "")[:350],
                "links": parsed_data.get("body", {}).get("links", []),
                "scanned_links": scanned_links,
                "total_links": parsed_data.get("body", {}).get("total_links", 0),
                "attachments": parsed_data.get("attachments", [])
            }
        }

```


### 📄 File: `engine/parser.py`
```python
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
    URL_PATTERN = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')

    def __init__(self, raw_content: Union[str, bytes]):
        self.raw_bytes = raw_content if isinstance(raw_content, bytes) else raw_content.encode('utf-8')
        self.raw_content = self.raw_bytes.decode('utf-8', errors='replace')
        self.sha256_hash = hashlib.sha256(self.raw_bytes).hexdigest()
        sanitized = self._sanitize_raw_text(self.raw_content)
        self.msg = email.message_from_string(sanitized, policy=email.policy.default)

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

        # Extract IPs
        found_ips = self.IPV4_PATTERN.findall(clean_text)
        candidate_ip = None
        for ip in found_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    candidate_ip = ip
                    break
            except ValueError:
                continue

        # If no public IP, take the first valid IP or None
        if not candidate_ip and found_ips:
            candidate_ip = found_ips[0]

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
            # Clean comments like (UTC)
            raw_ts = re.sub(r'\(.*?\)', '', raw_ts).strip()
            try:
                parsed_dt = parsedate_to_datetime(raw_ts)
                if parsed_dt:
                    iso_timestamp = parsed_dt.astimezone(timezone.utc).isoformat()
                    timestamp_str = raw_ts
            except Exception:
                timestamp_str = raw_ts

        return {
            "hop_number": hop_index,
            "ip": candidate_ip,
            "from_mta": from_mta,
            "by_mta": by_mta,
            "protocol": protocol,
            "raw_timestamp": timestamp_str,
            "timestamp_iso": iso_timestamp,
            "is_public_ip": bool(candidate_ip and not ipaddress.ip_address(candidate_ip).is_private if candidate_ip else False),
            "raw_header": header_str[:250] + ("..." if len(header_str) > 250 else "")
        }

    def _determine_origin_candidate(self, hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Returns a candidate source IP with an explicit evidence limitation."""
        x_orig = str(self.msg.get("X-Originating-IP", ""))
        ips = self.IPV4_PATTERN.findall(x_orig)
        for ip in ips:
            try:
                if not ipaddress.ip_address(ip).is_private:
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
                    "confidence": "LOW",
                    "note": "This identifies candidate mail infrastructure, not a person or exact physical origin."
                }

        if hops and hops[0].get("ip"):
            return {
                "ip": hops[0]["ip"],
                "source": "Earliest Received header",
                "confidence": "LOW",
                "note": "Only a private or otherwise unverified relay address was available."
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

        return {
            "plain_text": plain_text.strip(),
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

```


### 📄 File: `engine/hop_analyzer.py`
```python
"""
Hop timestamp consistency analyzer.
Detects reversed or unusually delayed timestamps without claiming attribution.
"""

from datetime import datetime
from typing import List, Dict, Any, Tuple

class HopAnalyzer:
    """Evaluates the integrity of the SMTP Received: relay chain."""

    # Maximum acceptable reverse clock skew before flagging as suspicious (seconds)
    CLOCK_TOLERANCE_SECONDS = 60.0

    def __init__(self, hops: List[Dict[str, Any]]):
        self.hops = hops

    def analyze(self) -> Dict[str, Any]:
        """Performs full hop-by-hop latency and integrity analysis."""
        if not self.hops or len(self.hops) < 2:
            return {
                "analyzed_hops": self.hops,
                "anomalies": [],
                "has_timing_anomalies": False,
                "total_transit_seconds": 0.0,
                "hop_reliability_index": 100.0,
                "header_consistency_score": 100.0,
                "verdict": "Single hop or internal delivery; integrity intact."
            }

        analyzed_hops = []
        anomalies = []
        has_timing_anomalies = False
        total_transit_time = 0.0

        for i in range(len(self.hops)):
            current_hop = dict(self.hops[i])
            delta_seconds = None
            anomaly_detected = False
            anomaly_reason = None

            if i > 0:
                prev_hop = analyzed_hops[i - 1]
                t_prev_iso = prev_hop.get("timestamp_iso")
                t_curr_iso = current_hop.get("timestamp_iso")

                if t_prev_iso and t_curr_iso:
                    try:
                        dt_prev = datetime.fromisoformat(t_prev_iso)
                        dt_curr = datetime.fromisoformat(t_curr_iso)
                        delta_seconds = (dt_curr - dt_prev).total_seconds()
                        total_transit_time += max(0.0, delta_seconds)

                        # Reversed timestamps may indicate manipulation, clock skew, or malformed data.
                        if delta_seconds < -self.CLOCK_TOLERANCE_SECONDS:
                            anomaly_detected = True
                            has_timing_anomalies = True
                            anomaly_reason = (
                                f"Reversed relay timestamp ({delta_seconds:.1f}s). "
                                "Possible causes include clock skew, malformed data, or header manipulation."
                            )
                            anomalies.append({
                                "hop_index": current_hop["hop_number"],
                                "severity": "HIGH",
                                "type": "REVERSED_RELAY_TIMESTAMP",
                                "details": anomaly_reason
                            })

                        # Check 2: Severe Delay (> 2 hours) indicating greylisting or queue hijacking
                        elif delta_seconds > 7200.0:
                            anomaly_detected = True
                            anomaly_reason = f"Abnormal relay delay ({delta_seconds / 3600.0:.1f} hours)."
                            anomalies.append({
                                "hop_index": current_hop["hop_number"],
                                "severity": "WARNING",
                                "type": "EXCESSIVE_RELAY_DELAY",
                                "details": anomaly_reason
                            })

                    except Exception as ex:
                        delta_seconds = None

            current_hop["delta_seconds"] = delta_seconds
            current_hop["anomaly"] = anomaly_detected
            current_hop["anomaly_reason"] = anomaly_reason
            current_hop["integrity_status"] = "TIMESTAMP_ANOMALY" if anomaly_detected else "OBSERVED"
            analyzed_hops.append(current_hop)

        # Calculate Hop Reliability Index (HRI)
        penalty = 0.0
        for a in anomalies:
            if a["severity"] == "HIGH":
                penalty += 40.0
            elif a["severity"] == "WARNING":
                penalty += 15.0
            elif a["severity"] == "MEDIUM":
                penalty += 10.0

        hri = max(5.0, min(100.0, 100.0 - penalty))

        verdict = "No timestamp inconsistencies detected in the submitted relay headers."
        if has_timing_anomalies:
            verdict = "Reversed relay timestamps require analyst review; manipulation is one possible explanation."
        elif anomalies:
            verdict = "Unusual relay delay detected and requires analyst review."

        return {
            "analyzed_hops": analyzed_hops,
            "anomalies": anomalies,
            "has_timing_anomalies": has_timing_anomalies,
            "total_transit_seconds": round(total_transit_time, 2),
            "hop_reliability_index": round(hri, 1),
            "header_consistency_score": round(hri, 1),
            "verdict": verdict
        }

```


### 📄 File: `engine/auth_validator.py`
```python
"""
Authentication evidence interpreter.
Evaluates receiver-reported SPF, DKIM, DMARC results and RFC 7489 alignment.
Distinguishes between PASS, explicit FAIL, and neutral/UNVERIFIED states.
Supports ESP bounce-relay awareness (SendGrid, Mailchimp, Amazon SES, Google Workspace).
"""

import re
from typing import Dict, Any, List, Optional

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class AuthValidator:
    """Evaluates cryptographic email authentication and domain alignment under RFC 7489."""

    # Recognized ESP bounce domains where Return-Path differs from From: but DKIM aligns
    KNOWN_ESP_DOMAINS = {
        "sendgrid.net", "sendgrid.info", "mailgun.org", "mailgun.net",
        "amazonses.com", "mcsv.net", "mcdlv.net", "mailchimpapp.net",
        "google.com", "googlemail.com", "outlook.com", "protection.outlook.com",
        "hubspot.com", "postmarkapp.com", "sparkpostmail.com", "mandrillapp.com"
    }

    def __init__(self, headers: Dict[str, Any]):
        self.headers = headers
        self.from_header = headers.get("from", "")
        self.return_path_header = headers.get("return_path", "")
        self.from_domain = self._extract_domain(self.from_header)
        self.return_path_domain = self._extract_domain(self.return_path_header)

    @staticmethod
    def _extract_domain(email_str: str) -> str:
        """Extracts the domain portion from an email address or header."""
        match = re.search(r'@([a-zA-Z0-9.\-_]+)', email_str or "")
        if match:
            return match.group(1).lower().strip('> \t\r\n')
        return ""

    @classmethod
    def get_organizational_domain(cls, domain: str) -> str:
        """
        Extracts the base organizational domain (e.g. bounce.email.github.com -> github.com).
        Handles common two-part public suffixes such as .co.uk, .gov.in, .edu.in.
        """
        if not domain:
            return ""
        parts = domain.lower().strip('.').split('.')
        if len(parts) <= 2:
            return ".".join(parts)

        two_part_suffixes = {
            "co.uk", "gov.in", "edu.in", "org.in", "ac.in", "nic.in",
            "res.in", "com.au", "co.jp", "com.br", "co.za"
        }
        if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_suffixes:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    def audit(self) -> Dict[str, Any]:
        """Runs complete authentication audit adhering to RFC 7489."""
        spf_info = self._audit_spf()
        dkim_info = self._audit_dkim()
        dmarc_info = self._audit_dmarc(spf_info, dkim_info)
        dns_policies = self._query_dns_records(self.from_domain)

        # RFC 7489 Section 4.2: DMARC passes if EITHER SPF aligns & passes OR DKIM aligns & passes
        spf_passed_and_aligned = (spf_info.get("status") == "PASS" and dmarc_info.get("spf_aligned", False))
        dkim_passed_and_aligned = (dkim_info.get("status") == "PASS" and dmarc_info.get("dkim_aligned", False))
        composite_pass = (
            dmarc_info.get("status") == "PASS" or
            spf_passed_and_aligned or
            dkim_passed_and_aligned
        )

        # Explicit failure vs unverified
        if composite_pass:
            overall_verdict = "REPORTED_PASS"
        elif dmarc_info.get("status") == "FAIL" or (spf_info.get("status") == "FAIL" and dkim_info.get("status") == "FAIL"):
            overall_verdict = "REPORTED_FAIL"
        elif spf_info.get("status") == "NONE" and dkim_info.get("status") == "NONE":
            overall_verdict = "UNVERIFIED"
        else:
            overall_verdict = "PARTIAL_OR_UNVERIFIED"

        return {
            "overall_status": overall_verdict,
            "sender_domain": self.from_domain,
            "from_organizational_domain": self.get_organizational_domain(self.from_domain),
            "spf": spf_info,
            "dkim": dkim_info,
            "dmarc": dmarc_info,
            "composite_pass": composite_pass,
            "is_unverified": overall_verdict == "UNVERIFIED",
            "dns_published_policies": dns_policies,
            "trust_notice": (
                "Statuses are parsed from Authentication-Results and Received-SPF headers under RFC 7489. "
                "Neutral or missing headers indicate unverified telemetry, not confirmed malice."
            )
        }

    def _audit_spf(self) -> Dict[str, Any]:
        """Extracts SPF authentication status and evaluated domain."""
        auth_results = " ".join(self.headers.get("authentication_results", []))
        rec_spf = " ".join(self.headers.get("received_spf", []))
        combined = (auth_results + " " + rec_spf).lower()

        status = "NONE"
        details = "No SPF verification header present."
        spf_domain = ""

        match = re.search(r'\bspf=([a-z]+)', combined)
        if match:
            status = match.group(1).upper()
            details = f"Authentication-Results header reports SPF={status}."
        elif "pass" in rec_spf.lower():
            status = "PASS"
            details = "Received-SPF header reports PASS."
        elif "fail" in rec_spf.lower():
            status = "FAIL"
            details = "Received-SPF header reports FAIL."
        elif "softfail" in rec_spf.lower():
            status = "SOFTFAIL"
            details = "Received-SPF header reports SOFTFAIL."

        # Extract domain/sender evaluated in SPF
        dom_match = (
            re.search(r'smtp\.mailfrom=([^\s;]+)', combined) or
            re.search(r'envelope-from=([^\s;]+)', combined) or
            re.search(r'domain of ([^\s;]+)', combined)
        )
        if dom_match:
            raw_dom = dom_match.group(1).strip()
            spf_domain = self._extract_domain(raw_dom) or raw_dom.lower().strip('> ')
        elif self.return_path_domain:
            spf_domain = self.return_path_domain

        return {
            "status": status,
            "evaluated_domain": spf_domain,
            "details": details,
            "evidence_source": "Message authentication headers",
            "independently_verified": False
        }

    def _audit_dkim(self) -> Dict[str, Any]:
        """Extracts DKIM signature verification status, selector, and signing domain."""
        auth_results = " ".join(self.headers.get("authentication_results", []))
        dkim_sigs = self.headers.get("dkim_signatures", [])
        combined = auth_results.lower()

        status = "NONE"
        details = "No DKIM verification record found."
        dkim_domain = ""
        selector = ""

        match = re.search(r'\bdkim=([a-z]+)', combined)
        if match:
            status = match.group(1).upper()
            details = f"Authentication-Results header reports DKIM={status}."

        # Parse DKIM-Signature header if available
        if dkim_sigs:
            first_sig = str(dkim_sigs[0])
            d_match = re.search(r'\bd=([^\s;]+)', first_sig)
            s_match = re.search(r'\bs=([^\s;]+)', first_sig)
            if d_match:
                dkim_domain = d_match.group(1).lower().strip('"')
            if s_match:
                selector = s_match.group(1).lower().strip('"')
        # Also extract signing domain from Authentication-Results (header.d= or header.i=)
        if not dkim_domain:
            header_d = re.search(r'header\.d=([^\s;]+)', combined)
            if header_d:
                dkim_domain = header_d.group(1).lower().strip('"')
        if not dkim_domain:
            header_i = re.search(r'header\.i=@?([^\s;]+)', combined)
            if header_i:
                raw_i = header_i.group(1).lower().strip('"')
                dkim_domain = self._extract_domain(raw_i) or raw_i
        if not selector:
            header_s = re.search(r'header\.s=([^\s;]+)', combined)
            if header_s:
                selector = header_s.group(1).lower().strip('"')

        return {
            "status": status,
            "signature_domain": dkim_domain,
            "selector": selector,
            "details": details,
            "evidence_source": "Message authentication headers",
            "independently_verified": False
        }

    def _audit_dmarc(self, spf_info: Dict[str, Any], dkim_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validates DMARC alignment between From: domain and SPF/DKIM domains (RFC 7489)."""
        auth_results = " ".join(self.headers.get("authentication_results", [])).lower()

        dmarc_status = "NONE"
        match = re.search(r'\bdmarc=([a-z]+)', auth_results)
        if match:
            dmarc_status = match.group(1).upper()

        from_dom = self.from_domain
        from_org = self.get_organizational_domain(from_dom)

        spf_dom = spf_info.get("evaluated_domain", "")
        spf_org = self.get_organizational_domain(spf_dom)

        dkim_dom = dkim_info.get("signature_domain", "")
        dkim_org = self.get_organizational_domain(dkim_dom)

        # Relaxed alignment: Organizational domains match
        spf_aligned = bool(from_org and spf_org and from_org == spf_org)
        dkim_aligned = bool(from_org and dkim_org and from_org == dkim_org)

        # Strict alignment: Exact FQDN match
        spf_strict_aligned = bool(from_dom and spf_dom and from_dom == spf_dom)
        dkim_strict_aligned = bool(from_dom and dkim_dom and from_dom == dkim_dom)

        # Check for legitimate ESP relay pattern (e.g. From: co.com, Return-Path: bounces.sendgrid.net, DKIM: co.com)
        is_esp_relay = bool(
            spf_dom and any(esp in spf_dom for esp in self.KNOWN_ESP_DOMAINS) and
            dkim_aligned and dkim_info.get("status") == "PASS"
        )

        return {
            "status": dmarc_status,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "spf_strict_aligned": spf_strict_aligned,
            "dkim_strict_aligned": dkim_strict_aligned,
            "is_esp_relay": is_esp_relay,
            "aligned_from_domain": from_dom,
            "details": (
                f"Header DMARC: {dmarc_status} "
                f"(SPF aligned: {spf_aligned}, DKIM aligned: {dkim_aligned}, ESP relay: {is_esp_relay})"
            ),
            "evidence_source": "Authentication-Results header & RFC 7489 calculation",
            "independently_verified": False
        }

    def _query_dns_records(self, domain: str) -> Dict[str, Any]:
        """Queries public DNS for SPF and DMARC TXT records."""
        if not DNS_AVAILABLE or not domain:
            return {"spf_record": None, "dmarc_record": None, "dns_query_status": "DNS_NOT_AVAILABLE"}

        spf_rec = None
        dmarc_rec = None
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 1.5

        try:
            answers = resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_str = rdata.to_text().strip('"')
                if "v=spf1" in txt_str:
                    spf_rec = txt_str
                    break
        except Exception:
            spf_rec = None

        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in dmarc_answers:
                txt_str = rdata.to_text().strip('"')
                if "v=DMARC1" in txt_str:
                    dmarc_rec = txt_str
                    break
        except Exception:
            dmarc_rec = None

        return {
            "spf_record": spf_rec,
            "dmarc_record": dmarc_rec,
            "dns_query_status": "OK" if (spf_rec or dmarc_rec) else "NO_RECORDS"
        }

```


### 📄 File: `engine/url_scanner.py`
```python
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
        # 1. De-obfuscate common defanging notation
        clean = (
            url_str.replace("hxxps://", "https://")
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

        # 4. Check Punycode / IDN Homograph attacks
        if "xn--" in hostname:
            is_punycode = True
            is_suspicious = True
            risk_reasons.append(f"Internationalized Punycode homograph domain detected ({hostname})")

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
            "is_shortener": is_shortener,
            "suspicious": is_suspicious,
            "risk_reasons": risk_reasons,
            "redirects": 0,  # Zero active redirects followed (safe static analysis)
            "inspection_method": "STATIC_SAFE_INSPECTION_NO_SSRF"
        }

```


### 📄 File: `engine/geoip_resolver.py`
```python
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

```


### 📄 File: `engine/threat_scorer.py`
```python
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
        self._score_linguistic_urgency(crypto_authenticated=composite_pass)
        self._score_ml_baseline(crypto_authenticated=composite_pass)

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

```


### 📄 File: `engine/ml_classifier.py`
```python
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

```


### 📄 File: `engine/ioc_graph.py`
```python
"""Builds a compact evidence relationship graph for one analyzed email."""

import re
from urllib.parse import urlparse
from typing import Any, Dict, List


class IOCGraphBuilder:
    @staticmethod
    def _domain(value: str) -> str:
        match = re.search(r"@([A-Za-z0-9._-]+)", value or "")
        return match.group(1).lower().rstrip(">") if match else ""

    @classmethod
    def build(cls, parsed: Dict[str, Any], analyzed_hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        root_id = f"email:{parsed.get('forensic_hash', '')[:12]}"
        nodes = [{"id": root_id, "type": "EMAIL", "label": "Submitted email"}]
        edges = []
        seen = {root_id}

        def add_node(node_id: str, node_type: str, label: str, relation: str):
            if not node_id or node_id == f"{node_type.lower()}:":
                return
            if node_id not in seen:
                nodes.append({"id": node_id, "type": node_type, "label": label})
                seen.add(node_id)
            edges.append({"source": root_id, "target": node_id, "relation": relation})

        headers = parsed.get("headers", {})
        for field in ("from", "reply_to", "return_path"):
            domain = cls._domain(headers.get(field, ""))
            if domain:
                add_node(f"domain:{domain}", "DOMAIN", domain, field.upper())

        for hop in analyzed_hops:
            ip = hop.get("ip")
            if ip:
                add_node(f"ip:{ip}", "IP", ip, f"RELAY_HOP_{hop.get('hop_number')}")

        for link in parsed.get("body", {}).get("links", []):
            normalized = link if "://" in link else f"http://{link}"
            host = (urlparse(normalized).hostname or "").lower()
            if host:
                add_node(f"url-domain:{host}", "URL_DOMAIN", host, "EMBEDDED_LINK")

        for attachment in parsed.get("attachments", []):
            digest = attachment.get("sha256")
            if digest:
                add_node(f"attachment:{digest[:16]}", "ATTACHMENT", attachment.get("filename", "attachment"), "ATTACHMENT")

        counts = {}
        for node in nodes:
            counts[node["type"]] = counts.get(node["type"], 0) + 1
        return {"nodes": nodes, "edges": edges, "counts": counts, "scope": "SINGLE_EMAIL_EVIDENCE_GRAPH"}

```


### 📄 File: `engine/evidence_ledger.py`
```python
"""Minimal append-only hash-chain ledger for tamper-evident demo receipts.

Only analysis identifiers and evidence hashes are written. Email content and PII
remain off-ledger. This demonstrates the integrity pattern without pretending to
be a production blockchain network.
"""

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict


class EvidenceLedger:
    _lock = threading.Lock()

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, analysis_id: str, evidence_hash: str) -> Dict[str, str]:
        with self._lock:
            previous_hash = self._last_hash()
            record = {
                "analysis_id": analysis_id,
                "evidence_hash": evidence_hash,
                "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
                "previous_record_hash": previous_hash,
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
            record_hash = hashlib.sha256(canonical).hexdigest()
            record["record_hash"] = record_hash
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            return {
                "record_hash": record_hash,
                "previous_record_hash": previous_hash,
                "recorded_at_utc": record["recorded_at_utc"],
                "ledger_type": "LOCAL_APPEND_ONLY_HASH_CHAIN",
                "privacy": "Only identifiers and SHA-256 hashes are stored; message content remains off-ledger.",
            }

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        last = ""
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if not last:
            return "GENESIS"
        try:
            return json.loads(last).get("record_hash", "GENESIS")
        except json.JSONDecodeError:
            return "INVALID_PREVIOUS_RECORD"

```


### 📄 File: `engine/evidence_generator.py`
```python
"""
Forensic analysis report generator.
Produces a review aid with provenance and limitation notices.
"""

import os
import uuid
from datetime import datetime, timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from xml.sax.saxutils import escape

class EvidenceGenerator:
    """Creates a standardized forensic PDF report with cryptographic chain of custody."""

    @classmethod
    def generate_pdf(cls, analysis_data: dict, output_path: str) -> str:
        safe = lambda value: escape(str(value if value is not None else ""))
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=36, leftMargin=36,
            topMargin=36, bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom Forensic Styles
        title_style = ParagraphStyle(
            'ForensicTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=16,
            textColor=colors.HexColor('#0B1F3A'),
            alignment=1, # Center
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'ForensicSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=colors.HexColor('#008080'),
            alignment=1,
            spaceAfter=12
        )
        heading_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=12,
            textColor=colors.HexColor('#0B1F3A'),
            spaceBefore=8,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'ForensicBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.HexColor('#1E293B'),
            leading=12
        )
        code_style = ParagraphStyle(
            'ForensicCode',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            textColor=colors.HexColor('#0F172A'),
            leading=10
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph("TRACE-MAIL AI • FORENSIC ANALYSIS REPORT", title_style))
        story.append(Paragraph("TECHNICAL REVIEW AID • NOT AN AUTOMATIC CERTIFICATE OF ADMISSIBILITY OR ATTRIBUTION", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0B1F3A'), spaceAfter=10))

        # 2. Case Identification & Evidence Hash
        case_id = analysis_data.get("analysis_id") or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        hash_val = analysis_data.get("forensic_hash", "UNKNOWN")
        threat_verdict = analysis_data.get("threat_analysis", {}).get("verdict", "N/A")
        threat_score = analysis_data.get("threat_analysis", {}).get("threat_score", 0.0)
        ml_data = analysis_data.get("ml_analysis", {})
        ledger = analysis_data.get("ledger_receipt", {})

        meta_table_data = [
            [Paragraph("<b>Case Reference ID:</b>", body_style), Paragraph(case_id, code_style),
             Paragraph("<b>Examination Date:</b>", body_style), Paragraph(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'), body_style)],
            [Paragraph("<b>Exact submitted-byte SHA-256:</b>", body_style), Paragraph(hash_val, code_style),
             Paragraph("<b>Threat Assessment:</b>", body_style), Paragraph(f"<b>{threat_score}/100</b> ({threat_verdict})", body_style)],
            [Paragraph("<b>Ledger record hash:</b>", body_style), Paragraph(ledger.get("record_hash", "N/A"), code_style),
             Paragraph("<b>ML baseline:</b>", body_style), Paragraph(f"{float(ml_data.get('phishing_probability', 0.5)) * 100:.1f}% ({ml_data.get('label', 'UNCERTAIN')})", body_style)]
        ]
        t_meta = Table(meta_table_data, colWidths=[115, 195, 90, 120])
        t_meta.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_meta)
        story.append(Spacer(1, 10))

        # 3. Message Envelope Details
        story.append(Paragraph("1. Message Envelope & Authentication Posture", heading_style))
        headers = analysis_data.get("headers", {})
        auth = analysis_data.get("authentication", {})

        env_data = [
            [Paragraph("<b>From:</b>", body_style), Paragraph(safe(headers.get("from", "N/A")), body_style)],
            [Paragraph("<b>To:</b>", body_style), Paragraph(safe(headers.get("to", "N/A")), body_style)],
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(safe(headers.get("subject", "N/A")), body_style)],
            [Paragraph("<b>Sender Date:</b>", body_style), Paragraph(safe(headers.get("date", "N/A")), body_style)],
            [Paragraph("<b>Reported SPF:</b>", body_style), Paragraph(safe(f"{auth.get('spf', {}).get('status', 'NONE')} ({auth.get('spf', {}).get('details', '')})"), body_style)],
            [Paragraph("<b>Reported DKIM:</b>", body_style), Paragraph(safe(f"{auth.get('dkim', {}).get('status', 'NONE')} ({auth.get('dkim', {}).get('details', '')})"), body_style)],
            [Paragraph("<b>Reported DMARC:</b>", body_style), Paragraph(safe(f"{auth.get('dmarc', {}).get('status', 'NONE')} ({auth.get('dmarc', {}).get('details', '')})"), body_style)]
        ]
        t_env = Table(env_data, colWidths=[115, 405])
        t_env.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F8FAFC')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_env)
        story.append(Spacer(1, 10))

        # 4. Hop-by-Hop Transmission Audit Table
        story.append(Paragraph("2. Chronological Relay Hop & Latency (ΔT) Audit", heading_style))
        hops = analysis_data.get("hops_analysis", {}).get("analyzed_hops", [])

        hop_table_data = [["Hop", "Relaying IP", "From MTA -> By MTA", "Geolocation", "Latency (ΔT)", "Integrity"]]
        for h in hops:
            ip_val = h.get("ip") or "Internal"
            geo_str = f"{h.get('geo', {}).get('city', '')}, {h.get('geo', {}).get('country_code', '')}"
            delta_val = f"{h.get('delta_seconds', 0.0):.1f}s" if h.get('delta_seconds') is not None else "--"
            status_str = "TIMESTAMP ANOMALY" if h.get("anomaly") else "OBSERVED"
            
            mta_str = f"{h.get('from_mta', '')[:18]} -> {h.get('by_mta', '')[:18]}"
            
            hop_table_data.append([
                str(h.get("hop_number", "")),
                ip_val,
                mta_str,
                geo_str,
                delta_val,
                status_str
            ])

        if len(hop_table_data) > 1:
            t_hops = Table(hop_table_data, colWidths=[28, 82, 165, 105, 60, 80])
            t_hops.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0B1F3A')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('ALIGN', (2, 1), (2, -1), 'LEFT'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(t_hops)
        else:
            story.append(Paragraph("No intermediate hops recorded.", body_style))

        story.append(Spacer(1, 10))

        # 5. Indicators of Compromise (IOCs) & Threat Factors
        story.append(Paragraph("3. Forensic Indicators of Compromise (IOCs) & Findings", heading_style))
        factors = analysis_data.get("threat_analysis", {}).get("explainability_factors", [])
        if factors:
            for f in factors:
                bullet_p = Paragraph(f"• <b>[{safe(f.get('category'))}] ({safe(f.get('impact'))}):</b> {safe(f.get('detail'))}", body_style)
                story.append(bullet_p)
                story.append(Spacer(1, 2))
        else:
            story.append(Paragraph("No malicious indicators or anomalies identified.", body_style))

        story.append(Spacer(1, 14))

        # 6. Evidence integrity and limitations
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0B1F3A'), spaceAfter=8))
        story.append(Paragraph("4. Evidence Integrity, Provenance & Limitations", heading_style))
        cert_text = (
            "The SHA-256 value above was calculated from the exact bytes submitted to this analysis. Authentication statuses "
            "are interpreted from headers contained in the message and are not independently replayed by this prototype. "
            "GeoIP describes approximate network infrastructure, not a person's identity or physical location. Relay headers "
            "may contain untrusted claims. This report supports analyst review and does not by itself establish legal admissibility, "
            "authorship, or attribution. An authorized investigator must preserve the source evidence and document custody."
        )
        story.append(Paragraph(cert_text, ParagraphStyle('CertBody', parent=body_style, fontSize=8, leading=11)))
        story.append(Spacer(1, 20))

        # Sign-off box
        sign_data = [
            [Paragraph("<b>Analysis System:</b> TRACE-MAIL AI (SIH Prototype)", body_style),
             Paragraph("<b>Analyst Review:</b> ___________________________", body_style)],
            [Paragraph("<b>Institution:</b> Sir C.R. Reddy College of Engineering (Autonomous)", body_style),
             Paragraph("<b>Official Seal / Date:</b> ___________________________", body_style)]
        ]
        t_sign = Table(sign_data, colWidths=[260, 260])
        t_sign.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_sign)

        # Build Document
        doc.build(story)
        return output_path

```


### 📄 File: `engine/copilot_engine.py`
```python
"""
Forensic AI Copilot & Neural Threat Triage Engine.
Provides conversational explanation of email investigation reports,
RFC 5322 header invariants, domain WHOIS telemetry, MTA hop latency,
and out-of-band verification recommendations.
Supports local Ollama LLMs with an instant, deterministic forensic reasoning fallback.
"""

import json
import re
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

class ForensicCopilot:
    """Conversational AI Analyst for TraceMail Forensic Intelligence."""

    OLLAMA_URL = "http://localhost:11434/api/chat"
    OLLAMA_TIMEOUT = 3.5  # Fast fallback if Ollama hangs or requires auth

    @classmethod
    def query(
        cls,
        user_message: str,
        report: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, str]]] = None,
        preferred_model: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Processes user query against current forensic report context.
        Attempts Ollama neural inference first; seamlessly falls back
        to deterministic forensic reasoning engine.
        """
        user_msg = (user_message or "").strip()
        if not user_msg:
            return {
                "reply": "Greetings Analyst. How can I assist with your email forensic investigation today? You can ask about headers, domain verification, threat score, or MTA hops.",
                "category": "GREETING",
                "engine": "deterministic",
                "suggested_prompts": cls._get_default_prompts(report)
            }

        # 1. Try local Ollama if configured and available
        ollama_res = cls._try_ollama(user_msg, report, history, preferred_model)
        if ollama_res:
            return {
                "reply": ollama_res,
                "category": "NEURAL_INFERENCE",
                "engine": "ollama",
                "suggested_prompts": cls._get_contextual_prompts(user_msg, report)
            }

        # 2. Deterministic Forensic Reasoning Engine
        reasoned_reply, category = cls._reason_expert(user_msg, report, history)
        return {
            "reply": reasoned_reply,
            "category": category,
            "engine": "trace_mail_neural_rules",
            "suggested_prompts": cls._get_contextual_prompts(user_msg, report)
        }

    @classmethod
    def _try_ollama(
        cls,
        query: str,
        report: Optional[Dict[str, Any]],
        history: Optional[List[Dict[str, str]]],
        model_name: Optional[str]
    ) -> Optional[str]:
        """Attempts to query local Ollama instance with timeout."""
        try:
            context_summary = "No active report scanned yet."
            if report:
                context_summary = json.dumps({
                    "fraud_score": report.get("fraud_score"),
                    "risk_level": report.get("risk_level"),
                    "label": report.get("label"),
                    "confidence": report.get("confidence"),
                    "bec_type": report.get("ai", {}).get("bec_type"),
                    "headers": report.get("headers"),
                    "trace": report.get("trace"),
                    "links_count": len(report.get("links", [])),
                    "reasons": report.get("ai", {}).get("reasons", [])
                })

            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are TraceMail AI Forensic Copilot, an expert cybersecurity engineer "
                        "and RFC 5322 email forensics specialist. You assist SOC analysts in evaluating "
                        "phishing, BEC, spoofing, and malicious headers. Keep responses concise, professional, "
                        "and formatted with Markdown bullet points.\n\n"
                        f"ACTIVE EMAIL INVESTIGATION REPORT CONTEXT:\n{context_summary}"
                    )
                }
            ]

            if history:
                for h in history[-4:]:
                    if h.get("role") in ("user", "assistant") and h.get("content"):
                        messages.append({"role": h["role"], "content": h["content"]})

            messages.append({"role": "user", "content": query})

            model = model_name or "glm-5.3:cloud"
            payload = json.dumps({"model": model, "messages": messages, "stream": False}).encode("utf-8")
            req = urllib.request.Request(cls.OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})

            with urllib.request.urlopen(req, timeout=cls.OLLAMA_TIMEOUT) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    content = data.get("message", {}).get("content", "").strip()
                    if content:
                        return content
        except Exception:
            pass  # Fall back cleanly
        return None

    @classmethod
    def _reason_expert(
        cls,
        query: str,
        report: Optional[Dict[str, Any]],
        history: Optional[List[Dict[str, str]]]
    ) -> tuple[str, str]:
        """Deterministic forensic analyst engine matching semantic intent."""
        q = query.lower()

        if not report or (not report.get("fraud_score") and not report.get("headers")):
            return (
                "### 🛰️ TraceMail AI Copilot Standby Mode\n\n"
                "No email has been actively scanned in the forensic console yet.\n\n"
                "**How to get started:**\n"
                "1. Select any pre-loaded threat vector from the **Pre-loaded Forensic Samples** menu (e.g. *Credential Harvest SSRF Attack* or *Vendor Bank Change BEC*).\n"
                "2. Click **Load & Deep Scan**.\n"
                "3. Return here, and I will dissect its RFC headers, domain WHOIS telemetry, timing anomalies, and out-of-band verification steps for you!\n\n"
                "*You can also ask general email security questions right now, such as 'What is DMARC alignment?' or 'How does display name spoofing work?'*",
                "STANDBY"
            )

        # Extract Report Telemetry
        score = report.get("fraud_score", 0)
        risk = report.get("risk_level", "UNKNOWN")
        label = str(report.get("label", "analyzed")).upper()
        conf = report.get("confidence", 85)
        headers = report.get("headers") or {}
        ai_data = report.get("ai") or {}
        bec_type = ai_data.get("bec_type", "none")
        reasons = ai_data.get("reasons") or headers.get("reasons") or []
        trace = report.get("trace") or {}
        geo = trace.get("geo") or {}
        links = report.get("links") or []
        origin_ip = headers.get("origin_ip") or geo.get("ip") or "Unknown Relay"
        from_hdr = headers.get("from", "N/A")
        reply_to = headers.get("reply_to", "N/A")
        ret_path = headers.get("return_path", "N/A")
        hops_count = headers.get("hops", 0)
        spf_pass = headers.get("spf", False)
        dkim_pass = headers.get("dkim", False)
        dmarc_pass = headers.get("dmarc", False)

        # --- INTENT ROUTING ---

        # 1. OVERALL INVESTIGATION REPORT / SUMMARY
        if any(w in q for w in ["report", "summary", "summarize", "overview", "verdict", "score", "why flagged", "explain this"]):
            reply = [
                "### 📊 Executive Forensic Investigation Report",
                f"- **Composite Threat Score:** `{score}/100` ({risk} Risk)",
                f"- **Risk Classification:** **{label}** ({conf}% Confidence)",
                f"- **Attack Pattern Isolation:** `{bec_type.upper()}`",
                f"- **Origin Geolocation:** {geo.get('city', 'Unknown City')}, {geo.get('country', 'Unknown Country')} (`{origin_ip}`)",
                f"- **Authentication Posture:** SPF: {'✅ PASS' if spf_pass else '❌ FAIL'} | DKIM: {'✅ PASS' if dkim_pass else '❌ FAIL'} | DMARC: {'✅ PASS' if dmarc_pass else '❌ FAIL'}",
                "",
                "#### 🔬 Key Forensic Findings:"
            ]
            if reasons:
                for r in reasons:
                    reply.append(f"- ⚠️ **{r}**")
            else:
                reply.append("- ✅ No invariant anomalies or deceptive patterns detected.")

            reply.extend([
                "",
                "#### 🛡️ Analyst Verdict & Action:",
                "- **Recommendation:** " + (
                    "**CRITICAL CONTAINMENT:** Isolate message immediately. Quarantine origin IP on mail gateway. Issue security notice regarding financial diversion." if score >= 70
                    else "**SUSPICIOUS:** Require secondary out-of-band verification before clicking links or processing requests." if score >= 35
                    else "**SAFE / BENIGN:** RFC 5322 invariants and cryptographic signatures conform with normal operational baselines."
                )
            ])
            return "\n".join(reply), "REPORT_SUMMARY"

        # 2. DOMAIN & WHOIS ANALYSIS
        if any(w in q for w in ["domain", "whois", "mx", "registrar", "reply-to", "reply to", "lookalike", "punycode", "creation date"]):
            whois = geo.get("whois") or {}
            reg = whois.get("registrar", "Private / Cloudflare Registrar")
            created = whois.get("creation", "Recently Observed / Privacy Protected")
            mx_list = trace.get("mx", [])
            mx_str = ", ".join(mx_list) if mx_list else "Standard SMTP Exchange"

            reply = [
                "### 🌐 Domain & Identity Infrastructure Dissection",
                f"- **Header From:** `{from_hdr}`",
                f"- **Envelope Return-Path:** `{ret_path}`",
                f"- **Reply-To Target:** `{reply_to}`",
                "",
                "#### 🔍 Identity Invariant Assessment:"
            ]

            if reply_to and reply_to != from_hdr and reply_to != "N/A":
                reply.append(f"- 🚨 **Reply-To Organizational Mismatch Detected:** The email claims to be sent from `{from_hdr}`, but responses are directed to `{reply_to}`. This is a classic tactic used to hijack legitimate vendor conversation threads.")
            else:
                reply.append("- ✅ **Alignment Check:** Header From and Reply-To domains are mutually aligned.")

            reply.extend([
                "",
                "#### 🏢 WHOIS & Routing Telemetry:",
                f"- **Registered Registrar:** `{reg}`",
                f"- **Domain Creation Age:** `{created}`",
                f"- **Mail Exchange (MX) Route:** `{mx_str}`",
                f"- **Host Organization:** `{geo.get('org', geo.get('organization', 'N/A'))}`"
            ])

            if any("punycode" in str(r).lower() for r in reasons):
                reply.append("- ⚠️ **Punycode / Homograph Warning:** Domain contains internationalized characters (`xn--`) mimicking a trusted enterprise brand.")

            return "\n".join(reply), "DOMAIN_ANALYSIS"

        # 3. RFC HEADERS & CRYPTOGRAPHIC AUTHENTICATION
        if any(w in q for w in ["header", "spf", "dkim", "dmarc", "authentication", "return-path", "message-id", "crypto", "invariant"]):
            reply = [
                "### 🛡️ RFC 5322 Headers & Cryptographic Integrity Audit",
                f"- **SPF (Sender Policy Framework):** {'✅ PASS' if spf_pass else '❌ FAIL / MISSING'}",
                f"  *Validation:* Checks if client IP `{origin_ip}` is authorized in sender's DNS TXT record.",
                f"- **DKIM (DomainKeys Identified Mail):** {'✅ PASS' if dkim_pass else '❌ FAIL / MISSING'}",
                "  *Validation:* Cryptographic public/private keypair signature over email headers & body.",
                f"- **DMARC (Domain-based Message Authentication):** {'✅ PASS' if dmarc_pass else '❌ FAIL / MISSING'}",
                "  *Validation:* Enforces strict alignment between RFC 5322 `From:` and SPF/DKIM domains.",
                "",
                "#### 🔑 Forensic Takeaway:"
            ]

            if spf_pass and dkim_pass and score >= 70:
                reply.append("- ⚠️ **Crucial Detection Insight:** Notice that SPF and DKIM **PASSED**, yet the Threat Score is **CRITICAL**. This highlights compromised account takeover (Account Takeover / BEC). Attackers who compromise real enterprise mailboxes have valid cryptographic signatures, but our behavioral heuristics caught the fraudulent banking/wire language and Reply-To redirection!")
            elif not spf_pass or not dkim_pass:
                reply.append("- 🚨 **Spoofing Alert:** Lack of valid SPF/DKIM indicates this email was injected from an unauthorized SMTP relay attempting to forge the sender's identity.")
            else:
                reply.append("- ✅ All cryptographic checks match authentic corporate mail gateway policies.")

            return "\n".join(reply), "HEADER_ANALYSIS"

        # 4. MTA HOPS & TIMING LATENCY
        if any(w in q for w in ["hop", "hops", "latency", "relay", "routing", "delta t", "transit", "time delay", "timing"]):
            has_latency_anomaly = any("latency" in str(r).lower() or "forged" in str(r).lower() or "timing" in str(r).lower() for r in reasons)
            reply = [
                "### ✈️ MTA Transmission Hops & Latency Delta (ΔT) Analysis",
                f"- **Total Analyzed Routing Hops:** `{hops_count}` MTA relay checkpoints",
                f"- **Client Origin Node:** `{origin_ip}` ({geo.get('country', 'N/A')})",
                f"- **Transit Anomaly Flag:** {'🚨 ANOMALOUS / FORGED DELAY' if has_latency_anomaly else '✅ NORMAL TRANSIT INTERVALS'}",
                "",
                "#### ⏱️ How Hop Forensics Works:",
                "Every Mail Transfer Agent (MTA) prepends a timestamped `Received:` header. TraceMail AI unpacks these in reverse chronological order to calculate delta latency (`ΔT = T_in - T_out`).",
                ""
            ]
            if has_latency_anomaly:
                reply.append("- ⚠️ **Suspicious Time Gap:** A jump exceeding 1,200 seconds or a negative time delta was identified between intermediate relays, typical of artificial `Received:` header forgery or malicious store-and-forward proxying.")
            else:
                reply.append("- ✅ Relays demonstrate sub-second or expected regional delivery intervals consistent with normal SMTP processing.")

            return "\n".join(reply), "HOP_ANALYSIS"

        # 5. GEOINT & INFRASTRUCTURE
        if any(w in q for w in ["geo", "geoint", "where", "location", "ip", "tor", "frantech", "datacenter", "city", "country", "globe"]):
            is_tor = geo.get("is_tor", False)
            reply = [
                "### 🌍 Geospatial Intelligence (GeoINT) Radar Telemetry",
                f"- **Originating Public IP:** `{origin_ip}`",
                f"- **Physical Location:** {geo.get('city', 'Unknown City')}, {geo.get('region', '')} {geo.get('country', 'Unknown')}",
                f"- **Registered ISP / Organization:** `{geo.get('org', geo.get('organization', 'N/A'))}`",
                f"- **Autonomous System (ASN):** `{geo.get('asn', 'N/A')}`",
                f"- **High-Risk Network Flags:** {'🚨 TOR Exit Node Detected' if is_tor else 'Standard Commercial / Datacenter Infrastructure'}",
                "",
                "#### 🌐 3D Globe Radar Correlation:",
                f"The 3D Globe in the top-right viewport has locked its sensor coordinates onto (`{geo.get('lat', '0')}°, {geo.get('lon', '0')}°`). Clicking **🎯 Focus** will track the camera directly into this physical hosting site."
            ]
            return "\n".join(reply), "GEOINT_ANALYSIS"

        # 6. LINKS & ATTACHMENTS (SSRF / PUNYCODE)
        if any(w in q for w in ["link", "links", "url", "ssrf", "attachment", "malware", "click", "safe to open"]):
            susp_links = [l for l in links if l.get("suspicious")]
            reply = [
                "### 🔗 Link & Attachment Threat Isolation",
                f"- **Total Hyperlinks Discovered:** `{len(links)}`",
                f"- **Suspicious / Obfuscated Links:** `{len(susp_links)}`",
                "",
                "#### 🛡️ Safe Static Inspection Safeguard:",
                "TraceMail AI utilizes a **Zero-Request Static URL Inspection** model. It inspects URL components, punycode lookalikes, and internal probe patterns without ever making active outbound HTTP requests to attacker servers.",
                ""
            ]

            if susp_links:
                reply.append("#### ⚠️ Identified Threat Targets:")
                for l in susp_links[:3]:
                    reply.append(f"- 🛑 `{l.get('original')}` → Redirects: {l.get('redirects', 0)}")
                reply.append("\n**Verdict:** **DO NOT CLICK.** High risk of credential harvesting or internal network metadata extraction.")
            else:
                reply.append("- ✅ No malicious redirectors, IP literals, or metadata probing endpoints detected.")

            return "\n".join(reply), "LINK_ANALYSIS"

        # 7. REMEDIATION & OUT-OF-BAND PROTOCOL
        if any(w in q for w in ["what should i do", "action", "out of band", "verify", "remediation", "next step", "incident"]):
            reply = [
                "### 📋 SOC Incident Response & Out-of-Band Verification Protocol",
                "",
                "When dealing with emails flagged for financial diversion or account takeover, follow these mandatory steps:",
                "",
                "1. **Mandatory Out-of-Band (OOB) Verification:**",
                "   - **NEVER** reply to the email or use the phone numbers listed in the email body/signature.",
                "   - Obtain the vendor/executive's pre-established contact number from an approved internal ERP or CRM system.",
                "   - Call and verify the request via direct voice authentication with secondary signatory sign-off.",
                "",
                "2. **Mail Gateway & Firewall Defense:**",
                f"   - Block sender IP: `{origin_ip}`",
                f"   - Block deceptive Reply-To address: `{reply_to}`",
                "   - Invalidate any active web sessions or credentials if an employee clicked external links.",
                "",
                "3. **Cryptographic Ledger Archival:**",
                f"   - Retain Evidence SHA-256 Hash: `{report.get('forensic_hash', 'N/A')}` for chain-of-custody compliance.",
                "   - Click **Export PDF Dossier** in the console to generate the court-ready forensic incident packet."
            ]
            return "\n".join(reply), "REMEDIATION"

        # 8. DEFAULT COMPREHENSIVE ANSWER
        return (
            f"### 🧠 TraceMail AI Forensic Copilot Analysis\n\n"
            f"Regarding your inquiry on **'{query}'**:\n\n"
            f"The current target email is categorized as **{label}** with a threat score of **{score}/100** ({risk} risk).\n\n"
            f"- **Sender Identity:** `{from_hdr}`\n"
            f"- **Reply-To Alignment:** `{reply_to}`\n"
            f"- **Origin Physical Relay:** {geo.get('city', 'Unknown')}, {geo.get('country', 'N/A')} (`{origin_ip}`)\n"
            f"- **Key Threat Factors:** {', '.join(str(r) for r in reasons) if reasons else 'Clean / Standard Corporate Communication'}\n\n"
            f"**Suggested Next Inquiries:**\n"
            f"- Ask: *'Explain the domain WHOIS details'*\n"
            f"- Ask: *'Why did SPF or DKIM pass/fail?'*\n"
            f"- Ask: *'What out-of-band verification steps are required?'*",
            "GENERAL_INQUIRY"
        )

    @classmethod
    def _get_default_prompts(cls, report: Optional[Dict[str, Any]]) -> List[str]:
        return [
            "Explain Overall Threat Verdict",
            "Explain SPF, DKIM & DMARC Headers",
            "Inspect Sender Domain & WHOIS",
            "Explain MTA Hops & Timing Delays (ΔT)",
            "Is it safe to open or click links?",
            "What out-of-band verification is needed?"
        ]

    @classmethod
    def _get_contextual_prompts(cls, query: str, report: Optional[Dict[str, Any]]) -> List[str]:
        q = query.lower()
        if "header" in q or "spf" in q:
            return [
                "Why can an authenticated email still be BEC?",
                "Explain DMARC alignment rules",
                "Inspect the Reply-To mismatch"
            ]
        if "domain" in q or "whois" in q:
            return [
                "What are the MX records for this domain?",
                "Is this domain newly registered?",
                "How to block this domain in firewall"
            ]
        if "hop" in q:
            return [
                "Where did this email physically originate?",
                "Is the origin IP connected to TOR?",
                "Explain how attackers forge Received headers"
            ]
        return cls._get_default_prompts(report)

```


### 📄 File: `templates/index.html`
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TraceMail AI — Forensic Intelligence Platform</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/lenis@1.1.20/dist/lenis.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/ScrollTrigger.min.js"></script>
  <script src="https://unpkg.com/globe.gl"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    * { font-family: 'Space Grotesk', sans-serif; box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    body { background: #030508; color: #e2e8f0; overflow-x: hidden; }
    .grain { position: fixed; inset: 0; pointer-events: none; opacity: .04; background-image: url("https://grainy-gradients.vercel.app/noise.svg"); z-index: 999; }
    #fluid { position: fixed; inset: 0; z-index: -1; }
    
    /* Frosted Glass Base */
    .glass { 
      background: rgba(10, 16, 30, 0.65); 
      backdrop-filter: blur(24px); 
      -webkit-backdrop-filter: blur(24px); 
      border: 1px solid rgba(255, 255, 255, 0.08); 
      transition: border-color 0.25s ease, box-shadow 0.25s ease, background-color 0.25s ease;
    }
    
    /* Interactive Cards - clean lift without boundary distortion */
    .glass-card {
      transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease, background-color 0.2s ease;
    }
    .glass-card:hover {
      transform: translateY(-2px);
      border-color: rgba(6, 182, 212, 0.45);
      box-shadow: 0 10px 25px -8px rgba(6, 182, 212, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.1);
      background-color: rgba(16, 26, 48, 0.85);
    }

    /* Tabs & Pill Buttons - glowing pop without scale overlap */
    .res-tab, .scenario-pill, .tab-btn {
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      position: relative;
    }
    .res-tab:hover, .scenario-pill:hover, .tab-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px -2px rgba(6, 182, 212, 0.4);
      background: rgba(6, 182, 212, 0.18) !important;
      border-color: rgba(6, 182, 212, 0.5) !important;
      color: #38bdf8 !important;
      opacity: 1 !important;
    }
    .res-tab.active {
      background: rgba(6, 182, 212, 0.25) !important;
      border-color: rgba(6, 182, 212, 0.6) !important;
      color: #ffffff !important;
      box-shadow: 0 0 16px rgba(6, 182, 212, 0.35);
    }

    .glow { box-shadow: 0 0 40px rgba(6, 182, 212, 0.15); }
    .magnet { transition: transform .2s cubic-bezier(.23, 1, .32, 1); }
    .reveal { clip-path: inset(0 0 100% 0); }
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.18); border-radius: 999px; }
    @keyframes marquee { 0% { transform: translateX(0); } 100% { transform: translateX(-50%); } }
  </style>
</head>
<body>
  <div class="grain"></div>
  <canvas id="fluid"></canvas>

  <!-- NAV -->
  <nav class="fixed top-0 w-full z-50 glass border-b border-white/5">
    <div class="max-w-7xl mx-auto px-4 md:px-8 py-4 flex justify-between items-center">
      <div class="flex gap-3 items-center">
        <div class="w-8 h-8 rounded-xl bg-cyan-400 glow flex items-center justify-center text-black font-black text-sm">T</div>
        <span class="font-bold tracking-widest text-xs md:text-sm">TRACEMAIL / FORENSIC INTELLIGENCE v2</span>
      </div>
      <div class="hidden md:flex gap-8 text-[11px] tracking-widest opacity-60">
        <a href="#scan" class="hover:opacity-100 transition">HEADER FORENSICS</a>
        <a href="#scan" class="hover:opacity-100 transition">LINK SANDBOX</a>
        <a href="#scan" class="hover:opacity-100 transition">GEO TRACE</a>
        <a href="#results" class="hover:opacity-100 transition">FORENSIC RESULTS</a>
      </div>
      <div class="flex items-center gap-3">
        <a href="#scan" class="magnet glass px-5 py-2 rounded-full text-xs tracking-widest hover:bg-white hover:text-black transition">DASHBOARD ● LIVE</a>
      </div>
    </div>
  </nav>

  <!-- HERO -->
  <section class="max-w-7xl mx-auto px-4 md:px-8 min-h-[85vh] flex flex-col justify-center pt-28 pb-10">
    <div class="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full glass border border-cyan-400/20 text-cyan-400 text-xs tracking-[0.2em] mb-6 w-fit">
      <span class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
      <span>EVIDENCE-BASED FORENSIC PIPELINE • RFC 5322/7489</span>
    </div>
    <h1 class="text-[11vw] md:text-[6vw] leading-[0.92] font-light tracking-tight">
      Trace <span class="font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-violet-400">Every</span><br>
      <span class="reveal inline-block">Email.</span> <span class="reveal inline-block font-bold">Expose</span> Fraud.
    </h1>
    <p class="max-w-xl mt-6 opacity-60 text-sm leading-relaxed">
      Lusion-grade forensic intelligence platform. Deep cryptographic header analysis, zero-SSRF static link inspection, explainable multi-signal BEC threat scoring & IP geolocation with ISP telemetry — visualized on a live 3D trace globe.
    </p>

    <!-- Quick Scenarios on Hero -->
    <div class="flex flex-wrap gap-2.5 mt-8 items-center">
      <span class="text-xs opacity-50 font-mono mr-1">Demo Scenarios:</span>
      <button onclick="loadScenario('vendor_bank_change_bec.eml')" class="scenario-pill glass px-4 py-2 rounded-full text-xs text-rose-400 border border-rose-500/30 hover:bg-rose-500/10 transition flex items-center gap-1.5">
        <i class="fa-solid fa-building-columns"></i> Vendor BEC Bank Change
      </button>
      <button onclick="loadScenario('credential_harvest_ssrf_attack.eml')" class="scenario-pill glass px-4 py-2 rounded-full text-xs text-red-400 border border-red-500/30 hover:bg-red-500/10 transition flex items-center gap-1.5">
        <i class="fa-solid fa-skull"></i> Credential Harvest / SSRF
      </button>
      <button onclick="loadScenario('payroll_direct_deposit_bec.eml')" class="scenario-pill glass px-4 py-2 rounded-full text-xs text-amber-400 border border-amber-500/30 hover:bg-amber-500/10 transition flex items-center gap-1.5">
        <i class="fa-solid fa-money-check-dollar"></i> Payroll Spoofing BEC
      </button>
      <button onclick="loadScenario('legitimate_urgent_executive.eml')" class="scenario-pill glass px-4 py-2 rounded-full text-xs text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/10 transition flex items-center gap-1.5">
        <i class="fa-solid fa-circle-check"></i> Legit Urgent Exec (Evidence Precedence)
      </button>
      <button onclick="loadScenario('forged_relay_attack.eml')" class="scenario-pill glass px-4 py-2 rounded-full text-xs text-indigo-400 border border-indigo-500/30 hover:bg-indigo-500/10 transition flex items-center gap-1.5">
        <i class="fa-solid fa-route"></i> Forged Relay Attack
      </button>
    </div>

    <div class="flex flex-wrap gap-4 mt-8">
      <a href="#scan" class="magnet bg-white text-black px-8 py-4 rounded-full font-bold text-xs tracking-wider shadow-lg shadow-white/10 hover:bg-slate-200 transition flex items-center gap-2">
        <span>RUN FORENSIC SCAN</span>
        <i class="fa-solid fa-arrow-right"></i>
      </a>
      <span class="glass px-6 py-4 rounded-full text-xs flex items-center gap-2 opacity-80 font-mono">
        <i class="fa-solid fa-fingerprint text-cyan-400"></i> Evidence Hash • Chain of Custody • Tamper-Evident Ledger
      </span>
    </div>
  </section>

  <!-- SCAN BENTO -->
  <section id="scan" class="max-w-7xl mx-auto px-4 md:px-8 pb-12">
    <div class="grid lg:grid-cols-12 gap-6 w-full items-start">

      <!-- LEFT: SCAN CONSOLE -->
      <div class="lg:col-span-7 w-full min-w-0 glass rounded-3xl p-6 md:p-8 glow flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center mb-4">
            <div>
              <h2 class="text-xl font-bold tracking-tight">Forensic Scan Console</h2>
              <p class="text-[11px] opacity-40 mt-0.5">Parse raw headers, RFC 5322 invariants, safe link inspection, and BEC heuristics</p>
            </div>
            <span class="text-[10px] tracking-widest bg-cyan-400 text-black font-bold px-3 py-1 rounded-full">FORENSIC PIPELINE</span>
          </div>

          <!-- In-App Sample Threat Repository Selector -->
          <div class="bg-cyan-950/40 border border-cyan-500/30 rounded-2xl p-4 mb-5 shadow-lg shadow-cyan-950/20">
            <div class="flex items-center justify-between mb-2">
              <span class="text-xs font-bold text-cyan-300 flex items-center gap-2">
                <i class="fa-solid fa-folder-open text-cyan-400"></i>
                <span>Sample Threat Repository (In-App)</span>
              </span>
              <span id="sampleLoadBadge" class="text-[10px] font-mono opacity-60 text-cyan-200">9 pre-loaded attacks & clean samples</span>
            </div>
            <div class="flex flex-col sm:flex-row gap-2.5">
              <select id="sampleSelect" onchange="onSampleDropdownChange(this.value)" class="w-full sm:flex-1 bg-black/70 text-xs font-mono rounded-xl p-2.5 border border-white/20 text-white focus:border-cyan-400 outline-none cursor-pointer min-w-0">
                <option value="">-- Select In-App Sample Email to Load into Console --</option>
                <option value="vendor_bank_change_bec.eml">🚨 Vendor BEC: Bank Change Wire Fraud (High Risk / Payment Diversion)</option>
                <option value="credential_harvest_ssrf_attack.eml">☠️ Credential Harvest: SSRF & Punycode (High Risk / Harvest)</option>
                <option value="payroll_direct_deposit_bec.eml">⚠️ Payroll BEC: VIP Display Name Spoofing (High Risk)</option>
                <option value="ceo_bec_fraud.eml">💼 CEO BEC: Urgent Wire Fraud Scam (High Risk)</option>
                <option value="forged_relay_attack.eml">🔄 Forged Relay: Hop Spoofing & IP Mismatch (Suspicious)</option>
                <option value="credential_phishing_portal.eml">🎣 Credential Phishing: O365 Fake Portal (High Risk)</option>
                <option value="legitimate_urgent_executive.eml">🛡️ Legit Urgent Executive Memo (Evidence Precedence / Clean Pass)</option>
                <option value="legitimate_delivery.eml">✅ Legitimate Delivery (SPF / DKIM / DMARC Pass)</option>
                <option value="legitimate_password_expiry_notice.eml">✅ Legitimate Password Expiry Notice (Corporate IT / Clean)</option>
              </select>
              <div class="flex gap-2 shrink-0">
                <button type="button" onclick="importSelectedSample(false)" class="px-3.5 py-2 bg-white/10 hover:bg-white/20 text-white rounded-xl text-xs font-semibold transition flex items-center gap-1.5 border border-white/10" title="Load sample text into console without scanning">
                  <i class="fa-solid fa-file-import text-cyan-400"></i>
                  <span>Load Into Console</span>
                </button>
                <button type="button" onclick="importSelectedSample(true)" class="px-3.5 py-2 bg-cyan-400 hover:bg-cyan-300 text-black font-bold rounded-xl text-xs transition flex items-center gap-1.5 shadow-md shadow-cyan-400/20" title="Load sample and immediately run deep scan">
                  <i class="fa-solid fa-bolt"></i>
                  <span>Load & Deep Scan</span>
                </button>
              </div>
            </div>
            <!-- Feedback banner on import -->
            <div id="importNotice" class="hidden mt-2.5 p-2 bg-cyan-900/30 border border-cyan-400/40 rounded-xl text-[11px] font-mono text-cyan-300 flex items-center gap-2">
              <i class="fa-solid fa-circle-check text-cyan-400"></i>
              <span id="importNoticeText">Sample email loaded into console editor.</span>
            </div>
          </div>

          <form id="f" action="javascript:void(0);" onsubmit="runForensicScan(); return false;" class="space-y-4">
            <label id="dropZone" class="glass rounded-2xl p-5 flex flex-col items-center justify-center border-dashed border-white/20 cursor-pointer hover:bg-white/5 transition group">
              <i class="fa-solid fa-cloud-arrow-up text-cyan-400 text-xl mb-1 group-hover:scale-110 transition"></i>
              <span class="text-xs opacity-70 group-hover:opacity-100 transition" id="fileLabel">Drop .eml file or click to browse</span>
              <span class="text-[10px] opacity-30 mt-0.5">MIME • Headers • RFC 5322/7489 Invariants</span>
              <input type="file" name="eml" id="fileInput" accept=".eml" class="hidden">
            </label>

            <div class="relative">
              <textarea name="email_body" id="emailBody" placeholder="Or paste raw email with headers (Return-Path, Received, Authentication-Results, Subject...)" class="w-full h-36 bg-black/40 rounded-2xl p-4 text-xs font-mono border border-white/10 focus:border-cyan-400 outline-none transition leading-relaxed"></textarea>
              <button type="button" onclick="clearForm()" class="absolute top-3 right-3 text-[10px] opacity-40 hover:opacity-100 transition">Clear</button>
            </div>

            <input name="from" id="fromInput" placeholder="Sender Override: e.g. ceo@victim-company.com" class="w-full bg-black/40 rounded-xl p-3.5 text-xs font-mono border border-white/10 focus:border-cyan-400 outline-none transition">

            <button type="button" onclick="runForensicScan()" id="scanBtn" class="magnet w-full bg-cyan-400 text-black py-4 rounded-full font-bold tracking-widest text-xs hover:bg-cyan-300 transition shadow-lg shadow-cyan-400/20 active:scale-[0.99] flex items-center justify-center gap-2 cursor-pointer">
              <i class="fa-solid fa-bolt"></i>
              <span>RUN FORENSIC DEEP SCAN</span>
            </button>
          </form>
        </div>

        <!-- Quick Status Pill in Console -->
        <div class="mt-4 pt-3 border-t border-white/5 flex justify-between items-center text-[10px] opacity-50 font-mono">
          <span>PIPELINE: RFC-5322 + ZERO-SSRF LINKS + GEOIP</span>
          <span id="scanStatusMsg">READY</span>
        </div>
      </div>

      <!-- RIGHT: 3D GLOBE + TELEMETRY -->
      <div class="lg:col-span-5 w-full min-w-0 space-y-6">
        <!-- 3D GLOBE & GEOSPATIAL INTELLIGENCE RADAR -->
        <div class="glass rounded-3xl p-3 overflow-hidden relative group">
          <!-- Top HUD Overlay on Globe -->
          <div class="absolute top-5 left-5 right-5 z-20 flex justify-between items-center pointer-events-none">
            <span class="px-2.5 py-1 rounded-full bg-black/75 border border-cyan-400/30 text-[10px] font-mono text-cyan-300 flex items-center gap-1.5 shadow-lg shadow-black/50 backdrop-blur-md">
              <span class="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping"></span>
              <span>GEOINT RADAR ● LIVE</span>
            </span>
            <div class="flex gap-1.5 pointer-events-auto">
              <button type="button" onclick="toggleGlobeOrbit()" id="orbitBtn" class="px-2.5 py-1 bg-black/75 hover:bg-black text-cyan-300 border border-cyan-400/30 rounded-lg text-[10px] font-mono transition backdrop-blur-md shadow-md cursor-pointer" title="Toggle automatic planetary orbit">
                ⟳ Orbit: ON
              </button>
              <button type="button" onclick="focusThreatOrigin()" class="px-2.5 py-1 bg-black/75 hover:bg-black text-white border border-white/20 rounded-lg text-[10px] font-mono transition backdrop-blur-md shadow-md cursor-pointer" title="Center camera on detected threat origin node">
                🎯 Focus
              </button>
              <button type="button" onclick="resetGlobeView()" class="px-2.5 py-1 bg-black/75 hover:bg-black text-white border border-white/20 rounded-lg text-[10px] font-mono transition backdrop-blur-md shadow-md cursor-pointer" title="Reset global perspective">
                🌍 Reset
              </button>
            </div>
          </div>

          <div id="globe" class="h-[320px] w-full rounded-2xl bg-black cursor-grab active:cursor-grabbing"></div>

          <!-- Bottom Telemetry Bar -->
          <div class="p-3 flex justify-between items-center text-[10px] tracking-widest font-mono border-t border-white/5 bg-black/30 rounded-b-2xl">
            <span class="flex items-center gap-1.5 opacity-60">
              <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              ORIGIN TRACE → INBOX
            </span>
            <span id="ipLabel" class="text-cyan-300 font-bold">AWAITING SCAN TARGET</span>
          </div>

          <!-- Quick Tip Pill -->
          <div class="px-3 pb-1 pt-1.5 text-[9px] font-mono opacity-40 flex justify-between items-center">
            <span>🖱️ Drag to rotate • Scroll to zoom</span>
            <span id="hudCoords">Sensor Grid Active</span>
          </div>
        </div>

        <!-- SCORE METRIC TABS -->
        <div class="glass rounded-3xl p-6 grid grid-cols-3 gap-4 text-center">
          <div>
            <p id="score" class="text-4xl font-bold font-mono text-slate-500">--</p>
            <p class="text-[10px] tracking-widest opacity-50 mt-1">THREAT SCORE</p>
            <div class="w-full bg-white/10 h-1.5 rounded-full mt-2 overflow-hidden">
              <div id="bar" class="h-1.5 bg-gradient-to-r from-emerald-400 via-amber-400 to-red-500 rounded-full transition-all duration-700" style="width:0%"></div>
            </div>
          </div>
          <div class="flex flex-col justify-center">
            <p id="label" class="text-sm font-bold leading-tight text-slate-400">AWAITING<br>CLASSIFICATION</p>
            <p class="text-[10px] tracking-widest opacity-50 mt-1">RISK VERDICT</p>
          </div>
          <div class="flex flex-col justify-center">
            <p id="bec" class="text-xs font-bold font-mono text-cyan-300">—</p>
            <p class="text-[10px] tracking-widest opacity-50 mt-1">BEC PATTERN</p>
            <p id="conf" class="text-[10px] mt-0.5 opacity-60 font-mono"></p>
          </div>
        </div>

        <!-- AUTH PILLS -->
        <div class="glass rounded-3xl p-4 flex flex-wrap gap-2 text-[10px] items-center justify-around font-mono">
          <div class="flex items-center gap-1.5">
            <span class="bg-white/10 text-slate-300 px-2.5 py-1 rounded-full">SPF</span>
            <span id="spf" class="px-3 py-1 rounded-full border border-white/20 text-slate-400">—</span>
          </div>
          <div class="flex items-center gap-1.5">
            <span class="bg-white/10 text-slate-300 px-2.5 py-1 rounded-full">DKIM</span>
            <span id="dkim" class="px-3 py-1 rounded-full border border-white/20 text-slate-400">—</span>
          </div>
          <div class="flex items-center gap-1.5">
            <span class="bg-white/10 text-slate-300 px-2.5 py-1 rounded-full">DMARC</span>
            <span id="dmarc" class="px-3 py-1 rounded-full border border-white/20 text-slate-400">—</span>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- COMPREHENSIVE FORENSIC AI RESULTS SECTION -->
  <section id="results" class="max-w-7xl mx-auto px-4 md:px-8 pb-24">
    <div class="glass rounded-3xl p-6 md:p-10 glow space-y-6">

      <!-- Section Header -->
      <div class="flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-5">
        <div>
          <div class="flex items-center gap-2.5">
            <i class="fa-solid fa-dna text-cyan-400 text-lg"></i>
            <h3 class="text-2xl font-bold tracking-tight">Forensic Intelligence Suite</h3>
          </div>
          <p class="text-xs opacity-50 mt-1">Deep visual breakdown of forensic artifacts, invariant checks & chain-of-custody</p>
        </div>

        <!-- View Switcher Tabs -->
        <div class="flex flex-wrap gap-1.5 glass p-1.5 rounded-2xl border border-white/10 text-xs">
          <button onclick="switchResultTab('verdict')" class="res-tab active px-3.5 py-1.5 rounded-xl font-medium transition" data-res="verdict">Executive Verdict</button>
          <button onclick="switchResultTab('headers')" class="res-tab px-3.5 py-1.5 rounded-xl font-medium opacity-60 hover:opacity-100 transition" data-res="headers">RFC Headers</button>
          <button onclick="switchResultTab('links')" class="res-tab px-3.5 py-1.5 rounded-xl font-medium opacity-60 hover:opacity-100 transition" data-res="links">Link Sandbox</button>
          <button onclick="switchResultTab('geo')" class="res-tab px-3.5 py-1.5 rounded-xl font-medium opacity-60 hover:opacity-100 transition" data-res="geo">Geo & WHOIS</button>
          <button onclick="switchResultTab('ioc')" class="res-tab px-3.5 py-1.5 rounded-xl font-medium opacity-60 hover:opacity-100 transition" data-res="ioc">IOC Graph</button>
          <button onclick="switchResultTab('raw')" class="res-tab px-3.5 py-1.5 rounded-xl font-medium opacity-60 hover:opacity-100 transition" data-res="raw">Raw Evidence JSON</button>
          <button onclick="switchResultTab('copilot')" class="res-tab px-3.5 py-1.5 rounded-xl font-medium opacity-75 hover:opacity-100 transition flex items-center gap-1.5 text-cyan-300 border border-cyan-500/30 bg-cyan-950/20" data-res="copilot">
            <span class="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
            <i class="fa-solid fa-brain-circuit"></i>
            <span>AI Copilot</span>
          </button>
        </div>
      </div>

      <!-- Empty State -->
      <div id="resEmptyState" class="py-16 text-center opacity-40 space-y-3">
        <i class="fa-solid fa-radar text-4xl mb-2 block"></i>
        <p class="text-sm">No forensic scan triggered yet.</p>
        <p class="text-xs max-w-md mx-auto">Upload an .eml email file or select a pre-loaded test scenario above to review detailed forensic indicators.</p>
      </div>

      <!-- Dynamic Report Content -->
      <div id="resReport" class="hidden space-y-6">

        <!-- TAB 1: EXECUTIVE VERDICT -->
        <div id="tab-verdict" class="space-y-6">
          <!-- Verdict Hero Banner -->
          <div id="verdictBanner" class="glass rounded-2xl p-6 border flex flex-wrap items-center justify-between gap-4">
            <div class="flex items-center gap-4">
              <div id="verdictIconBox" class="w-14 h-14 rounded-2xl flex items-center justify-center text-2xl"></div>
              <div>
                <span id="verdictBadge" class="text-[10px] uppercase font-bold tracking-widest px-2.5 py-0.5 rounded-full"></span>
                <h4 id="verdictHeadline" class="text-xl font-bold tracking-wide mt-1"></h4>
                <p id="verdictSummary" class="text-xs opacity-60 mt-0.5 max-w-xl"></p>
              </div>
            </div>
            <div class="text-right">
              <span class="text-[10px] tracking-widest opacity-40 block font-mono">CONFIDENCE INDEX</span>
              <span id="confidenceNum" class="text-2xl font-bold font-mono text-cyan-400">--%</span>
            </div>
          </div>

          <!-- 2 Columns: Reasons & BEC Vector -->
          <div class="grid md:grid-cols-2 gap-6">
            <!-- Key Risk Indicators -->
            <div class="glass rounded-2xl p-6 space-y-3">
              <h5 class="text-xs font-bold tracking-widest text-cyan-400 uppercase flex items-center gap-2">
                <i class="fa-solid fa-shield-virus"></i> Key Risk Indicators Flagged
              </h5>
              <ul id="reasonsList" class="space-y-2 text-xs"></ul>
            </div>

            <!-- BEC Pattern Vector Analysis -->
            <div class="glass rounded-2xl p-6 space-y-4">
              <h5 class="text-xs font-bold tracking-widest text-cyan-400 uppercase flex items-center gap-2">
                <i class="fa-solid fa-user-ninja"></i> Business Email Compromise Vector
              </h5>
              <div class="bg-black/40 rounded-xl p-4 border border-white/10 space-y-2">
                <div class="flex justify-between items-center text-xs">
                  <span class="opacity-50 font-mono">DETECTED VECTOR</span>
                  <span id="becVectorBadge" class="font-bold font-mono text-cyan-300">--</span>
                </div>
                <p id="becGuidance" class="text-xs opacity-70 leading-relaxed"></p>
              </div>
            </div>
          </div>

          <!-- Chain of Custody & Tamper-Evident SHA-256 -->
          <div class="glass rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4 font-mono text-xs border border-cyan-400/20">
            <div class="flex items-center gap-3">
              <i class="fa-solid fa-fingerprint text-cyan-400 text-lg"></i>
              <div>
                <span class="text-[10px] tracking-widest opacity-40 block">CRYPTOGRAPHIC EVIDENCE HASH (SHA-256)</span>
                <span id="hashVal" class="text-cyan-300 select-all break-all">--</span>
              </div>
            </div>
            <div class="flex items-center gap-3">
              <span id="timestampVal" class="text-[11px] opacity-40"></span>
              <button onclick="copyEvidenceHash()" class="magnet glass px-4 py-1.5 rounded-full text-xs hover:bg-white hover:text-black transition">
                <i class="fa-regular fa-copy mr-1"></i> Copy Hash
              </button>
            </div>
          </div>
        </div>

        <!-- TAB 2: RFC HEADERS FORENSICS -->
        <div id="tab-headers" class="hidden space-y-6">
          <div class="grid sm:grid-cols-3 gap-4 text-center">
            <div id="spfBox" class="glass rounded-2xl p-4">
              <span class="text-[10px] opacity-50 tracking-widest block mb-1">SPF AUTHENTICATION</span>
              <span id="spfStatus" class="text-xs font-bold font-mono px-3 py-1 rounded-full">--</span>
            </div>
            <div id="dkimBox" class="glass rounded-2xl p-4">
              <span class="text-[10px] opacity-50 tracking-widest block mb-1">DKIM CRYPTO SIGNATURE</span>
              <span id="dkimStatus" class="text-xs font-bold font-mono px-3 py-1 rounded-full">--</span>
            </div>
            <div id="dmarcBox" class="glass rounded-2xl p-4">
              <span class="text-[10px] opacity-50 tracking-widest block mb-1">DMARC POLICY COMPLIANCE</span>
              <span id="dmarcStatus" class="text-xs font-bold font-mono px-3 py-1 rounded-full">--</span>
            </div>
          </div>

          <!-- Discrepancy Table -->
          <div class="glass rounded-2xl p-6 overflow-x-auto">
            <h5 class="text-xs font-bold tracking-widest text-cyan-400 uppercase mb-4">Header Invariant & Discrepancy Audit</h5>
            <table class="w-full text-xs font-mono">
              <tbody class="divide-y divide-white/10">
                <tr><td class="py-2.5 opacity-50 w-48">Sender From Header:</td><td id="hdrFrom" class="py-2.5 text-white">--</td></tr>
                <tr><td class="py-2.5 opacity-50">Envelope Return-Path:</td><td id="hdrReturnPath" class="py-2.5 text-white">--</td></tr>
                <tr><td class="py-2.5 opacity-50">Reply-To Route:</td><td id="hdrReplyTo" class="py-2.5 text-white">--</td></tr>
                <tr><td class="py-2.5 opacity-50">Originating IP:</td><td id="hdrOriginIp" class="py-2.5 text-cyan-300">--</td></tr>
                <tr><td class="py-2.5 opacity-50">Total Intermediate Hops:</td><td id="hdrHops" class="py-2.5 text-white">--</td></tr>
                <tr><td class="py-2.5 opacity-50">Spoof Index:</td><td id="hdrSpoof" class="py-2.5 text-white">--</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- TAB 3: LINK DEEP SCAN -->
        <div id="tab-links" class="hidden space-y-4">
          <div class="glass rounded-2xl p-6">
            <div class="flex justify-between items-center mb-4">
              <h5 class="text-xs font-bold tracking-widest text-cyan-400 uppercase">Hyperlink Threat & Redirection Sandbox</h5>
              <span id="linksSummary" class="text-[10px] font-mono opacity-50"></span>
            </div>
            <div id="linksList" class="space-y-2.5">
              <p class="text-xs opacity-40 text-center py-6">No links parsed yet.</p>
            </div>
          </div>
        </div>

        <!-- TAB 4: GEO & WHOIS -->
        <div id="tab-geo" class="hidden space-y-6">
          <div class="grid md:grid-cols-2 gap-6">
            <div class="glass rounded-2xl p-6 space-y-3">
              <h5 class="text-xs font-bold tracking-widest text-cyan-400 uppercase flex items-center gap-2">
                <i class="fa-solid fa-map-location-dot"></i> Origin GeoLocation
              </h5>
              <div class="space-y-2 text-xs font-mono">
                <div class="flex justify-between py-1.5 border-b border-white/5"><span class="opacity-50">IP Address:</span><span id="geoIpVal" class="text-white">--</span></div>
                <div class="flex justify-between py-1.5 border-b border-white/5"><span class="opacity-50">Location:</span><span id="geoLocVal" class="text-white">--</span></div>
                <div class="flex justify-between py-1.5 border-b border-white/5"><span class="opacity-50">Coordinates:</span><span id="geoCoordsVal" class="text-white">--</span></div>
                <div class="flex justify-between py-1.5"><span class="opacity-50">Organization / ISP:</span><span id="geoOrgVal" class="text-white truncate max-w-[200px]">--</span></div>
              </div>
            </div>

            <div class="glass rounded-2xl p-6 space-y-3">
              <h5 class="text-xs font-bold tracking-widest text-cyan-400 uppercase flex items-center gap-2">
                <i class="fa-solid fa-globe"></i> Domain WHOIS & Cloud Status
              </h5>
              <div class="space-y-2 text-xs font-mono">
                <div class="flex justify-between py-1.5 border-b border-white/5"><span class="opacity-50">Registrar:</span><span id="whoisReg" class="text-white truncate max-w-[200px]">--</span></div>
                <div class="flex justify-between py-1.5 border-b border-white/5"><span class="opacity-50">Creation Date:</span><span id="whoisDate" class="text-white">--</span></div>
                <div class="flex justify-between py-1.5"><span class="opacity-50">Cloud / Hosting Flag:</span><span id="hostingFlag" class="text-white">--</span></div>
              </div>
            </div>
          </div>

          <div class="glass rounded-2xl p-6">
            <h5 class="text-xs font-bold tracking-widest text-cyan-400 uppercase mb-3">MX Mail Exchange Route</h5>
            <div id="mxRecords" class="text-xs font-mono opacity-60">No MX records parsed yet.</div>
          </div>
        </div>

        <!-- TAB 5: IOC GRAPH -->
        <div id="tab-ioc" class="hidden space-y-4">
          <div class="glass rounded-2xl p-6">
            <div class="flex justify-between items-center mb-4">
              <h5 class="text-xs font-bold tracking-widest text-cyan-400 uppercase flex items-center gap-2">
                <i class="fa-solid fa-network-wired"></i> IOC Evidence Relationship Graph
              </h5>
              <span id="iocCountBadge" class="text-[10px] font-mono text-cyan-300">0 Nodes</span>
            </div>
            <p class="text-xs opacity-50 mb-4">Cryptographically linked evidence graph connecting sender identity, intermediate hops, link domains, and forensic hashes.</p>
            <div id="iocGraphContainer" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              <p class="text-xs opacity-40 col-span-full py-8 text-center">Run a scan to build the IOC relationship graph.</p>
            </div>
          </div>
        </div>

        <!-- TAB 6: RAW EVIDENCE JSON -->
        <div id="tab-raw" class="hidden space-y-4">
          <div class="flex justify-between items-center">
            <span class="text-xs opacity-50 font-mono">Consolidated Forensic JSON Payload:</span>
            <button onclick="copyRawEvidence()" class="magnet glass px-4 py-1.5 rounded-full text-xs font-mono hover:bg-white hover:text-black transition">
              <i class="fa-regular fa-copy mr-1"></i> Copy Payload
            </button>
          </div>
          <pre id="out" class="bg-black/60 rounded-2xl p-5 text-[11px] leading-relaxed whitespace-pre-wrap max-h-96 overflow-auto border border-white/10 font-mono text-cyan-300">Awaiting scan... Evidence hash & chain-of-custody will appear here.</pre>
        </div>

        <!-- TAB 7: AI FORENSIC COPILOT -->
        <div id="tab-copilot" class="hidden space-y-5">
          <!-- Copilot HUD Banner -->
          <div class="glass rounded-2xl p-5 border border-cyan-500/30 flex flex-wrap items-center justify-between gap-4 bg-gradient-to-r from-cyan-950/30 via-black/40 to-violet-950/30">
            <div class="flex items-center gap-3.5">
              <div class="w-12 h-12 rounded-2xl bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center text-cyan-300 text-xl shadow-lg shadow-cyan-500/20">
                <i class="fa-solid fa-brain-circuit animate-pulse"></i>
              </div>
              <div>
                <div class="flex items-center gap-2">
                  <span class="text-sm font-bold tracking-wide text-white">Forensic AI Copilot</span>
                  <span class="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                    ONLINE
                  </span>
                  <span id="copilotReportBadge" class="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-white/10 text-cyan-300">
                    Awaiting Target Scan
                  </span>
                </div>
                <p class="text-xs opacity-60 mt-0.5 font-mono">Real-time reasoning over RFC headers, domain WHOIS, MTA latency & out-of-band protocols</p>
              </div>
            </div>
            <div class="flex gap-2">
              <button type="button" onclick="clearCopilotChat()" class="px-3 py-1.5 glass rounded-xl text-xs font-mono opacity-70 hover:opacity-100 hover:text-red-400 transition" title="Clear conversation stream">
                <i class="fa-solid fa-trash-can mr-1"></i> Clear Chat
              </button>
            </div>
          </div>

          <!-- Quick Suggestion Prompt Chips -->
          <div class="space-y-1.5">
            <span class="text-[10px] font-mono tracking-widest opacity-50 uppercase flex items-center gap-1">
              <i class="fa-solid fa-bolt text-amber-400"></i> Forensic Inquiry Presets
            </span>
            <div id="copilotChips" class="flex flex-wrap gap-2">
              <button type="button" onclick="askCopilotPrompt('Explain Overall Threat Verdict')" class="px-3 py-1.5 rounded-xl bg-black/40 hover:bg-cyan-500/20 border border-white/10 hover:border-cyan-400/50 text-xs font-mono text-cyan-300 transition">
                📊 Explain Verdict
              </button>
              <button type="button" onclick="askCopilotPrompt('Explain SPF, DKIM & DMARC Headers')" class="px-3 py-1.5 rounded-xl bg-black/40 hover:bg-cyan-500/20 border border-white/10 hover:border-cyan-400/50 text-xs font-mono text-cyan-300 transition">
                🛡️ Explain Headers (SPF/DKIM)
              </button>
              <button type="button" onclick="askCopilotPrompt('Inspect Sender Domain & WHOIS')" class="px-3 py-1.5 rounded-xl bg-black/40 hover:bg-cyan-500/20 border border-white/10 hover:border-cyan-400/50 text-xs font-mono text-cyan-300 transition">
                🌐 Inspect Domain & WHOIS
              </button>
              <button type="button" onclick="askCopilotPrompt('Explain MTA Hops & Timing Delays (ΔT)')" class="px-3 py-1.5 rounded-xl bg-black/40 hover:bg-cyan-500/20 border border-white/10 hover:border-cyan-400/50 text-xs font-mono text-cyan-300 transition">
                ✈️ Analyze MTA Hops
              </button>
              <button type="button" onclick="askCopilotPrompt('Is it safe to open or click links?')" class="px-3 py-1.5 rounded-xl bg-black/40 hover:bg-cyan-500/20 border border-white/10 hover:border-cyan-400/50 text-xs font-mono text-cyan-300 transition">
                🚨 Is it Safe to Open?
              </button>
              <button type="button" onclick="askCopilotPrompt('What out-of-band verification is needed?')" class="px-3 py-1.5 rounded-xl bg-black/40 hover:bg-cyan-500/20 border border-white/10 hover:border-cyan-400/50 text-xs font-mono text-cyan-300 transition">
                🔒 Out-of-Band Steps
              </button>
            </div>
          </div>

          <!-- Chat Stream Container -->
          <div id="copilotChatStream" class="glass rounded-2xl p-5 min-h-[360px] max-h-[500px] overflow-y-auto space-y-4 border border-white/10 font-sans text-sm">
            <!-- Initial Assistant Greeting -->
            <div class="flex gap-3 items-start">
              <div class="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-400/40 flex-shrink-0 flex items-center justify-center text-cyan-300 text-xs">
                <i class="fa-solid fa-robot"></i>
              </div>
              <div class="glass bg-white/5 p-4 rounded-2xl border border-white/10 max-w-2xl space-y-2 text-slate-200">
                <div class="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider flex items-center justify-between">
                  <span>TraceMail Forensic Copilot</span>
                  <span class="opacity-50">READY</span>
                </div>
                <p class="text-xs leading-relaxed">
                  Greetings Analyst. I am your specialized RFC 5322 & Email Threat Intelligence assistant.
                  When you scan an email, I ingest its authentication invariants, routing timestamps, domain records, and link telemetry to explain any threat factor in clear detail.
                </p>
                <p class="text-xs opacity-75 font-mono text-slate-300">
                  Try selecting a demo sample above or click one of the quick inquiry presets!
                </p>
              </div>
            </div>
          </div>

          <!-- Chat Input Bar -->
          <div class="glass rounded-2xl p-2.5 border border-white/10 flex items-center gap-2 focus-within:border-cyan-400/60 transition">
            <div class="pl-2 text-cyan-400 text-sm">
              <i class="fa-solid fa-terminal"></i>
            </div>
            <textarea id="copilotInput" rows="1" placeholder="Ask about this email's headers, domain, WHOIS, hop latency, or safety..." class="w-full bg-transparent border-0 focus:ring-0 focus:outline-none text-xs font-mono text-white placeholder-white/30 resize-none py-2 px-1"></textarea>
            <button id="copilotSendBtn" type="button" onclick="sendCopilotMessage()" class="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-bold font-mono text-xs rounded-xl flex items-center gap-1.5 transition cursor-pointer shadow-lg shadow-cyan-500/20">
              <span>ASK</span>
              <i class="fa-solid fa-paper-plane text-[10px]"></i>
            </button>
          </div>
        </div>

      </div>
    </div>
  </section>

  <!-- FLOATING COPILOT LAUNCHER BUTTON -->
  <button id="copilotFloatingBtn" type="button" onclick="openCopilotTab()" class="fixed bottom-6 right-6 z-50 px-4 py-3 rounded-2xl bg-black/85 hover:bg-black text-cyan-300 border border-cyan-400/40 shadow-2xl shadow-cyan-500/30 backdrop-blur-xl flex items-center gap-2.5 font-mono text-xs font-bold transition transform hover:translate-y-[-2px] cursor-pointer group">
    <span class="relative flex h-2.5 w-2.5">
      <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
      <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
    </span>
    <i class="fa-solid fa-robot text-cyan-400 group-hover:rotate-12 transition-transform"></i>
    <span>AI Forensic Copilot</span>
  </button>

  <!-- MARQUEE -->
  <div class="mt-8 glass rounded-full py-4 overflow-hidden whitespace-nowrap border-y border-white/10">
    <div class="animate-[marquee_25s_linear_infinite] flex gap-10 text-xs tracking-[0.2em] opacity-60 font-mono">
      <span>SPOOFED SENDER DETECTION •</span>
      <span>DECEPTIVE DOMAINS •</span>
      <span>MALICIOUS LINKS •</span>
      <span>OBFUSCATED URLS •</span>
      <span>PAYMENT DIVERSION •</span>
      <span>FAKE INVOICE •</span>
      <span>CREDENTIAL HARVESTING •</span>
      <span>EXECUTIVE IMPERSONATION •</span>
      <span>SPOOFED SENDER DETECTION •</span>
      <span>DECEPTIVE DOMAINS •</span>
      <span>MALICIOUS LINKS •</span>
      <span>OBFUSCATED URLS •</span>
    </div>
  </div>

  <script>
    // =========================================================================
    // TRACE-MAIL AI FORENSIC INTELLIGENCE ENGINE (ZERO-DEPENDENCY CORE)
    // =========================================================================
    let currentForensicReport = null;
    let globe = null;
    let lastThreatOrigin = null;
    let globeAutoRotate = true;

    // Globe HUD Controls
    function toggleGlobeOrbit() {
      if (!globe || typeof globe.controls !== 'function') return;
      globeAutoRotate = !globeAutoRotate;
      try {
        globe.controls().autoRotate = globeAutoRotate;
      } catch (e) {}
      const btn = document.getElementById('orbitBtn');
      if (btn) {
        btn.innerText = globeAutoRotate ? '⟳ Orbit: ON' : '⟳ Orbit: OFF';
        btn.className = globeAutoRotate
          ? 'px-2.5 py-1 bg-black/75 hover:bg-black text-cyan-300 border border-cyan-400/30 rounded-lg text-[10px] font-mono transition backdrop-blur-md shadow-md cursor-pointer'
          : 'px-2.5 py-1 bg-black/75 hover:bg-black text-slate-400 border border-white/20 rounded-lg text-[10px] font-mono transition backdrop-blur-md shadow-md cursor-pointer';
      }
    }

    function focusThreatOrigin() {
      if (!globe || typeof globe.pointOfView !== 'function') return;
      if (lastThreatOrigin && !isNaN(lastThreatOrigin.lat) && !isNaN(lastThreatOrigin.lng)) {
        if (typeof globe.controls === 'function') {
          try {
            globe.controls().autoRotate = false;
            globeAutoRotate = false;
          } catch (e) {}
          const btn = document.getElementById('orbitBtn');
          if (btn) {
            btn.innerText = '⟳ Orbit: OFF';
            btn.className = 'px-2.5 py-1 bg-black/75 hover:bg-black text-slate-400 border border-white/20 rounded-lg text-[10px] font-mono transition backdrop-blur-md shadow-md cursor-pointer';
          }
        }
        globe.pointOfView({ lat: lastThreatOrigin.lat, lng: lastThreatOrigin.lng, altitude: 1.5 }, 1200);
      } else {
        alert('No external threat origin detected in current scan. Please select or paste a sample email with external hops (e.g., SSRF Attack or BEC Wire Fraud).');
      }
    }

    function resetGlobeView() {
      if (!globe || typeof globe.pointOfView !== 'function') return;
      globe.pointOfView({ lat: 20.5937, lng: 78.9629, altitude: 2.2 }, 1200);
    }

    // 1. Clear Console Form
    function clearForm() {
      const eb = document.getElementById('emailBody');
      const fi = document.getElementById('fromInput');
      const fl = document.getElementById('fileInput');
      const lb = document.getElementById('fileLabel');
      const nt = document.getElementById('importNotice');
      if (eb) eb.value = '';
      if (fi) fi.value = '';
      if (fl) fl.value = '';
      if (lb) lb.innerText = 'Drop .eml file or click to browse';
      if (nt) nt.classList.add('hidden');
    }

    // 2. Switch Results Tab
    function switchResultTab(tabKey) {
      const emptyState = document.getElementById('resEmptyState');
      if (emptyState && tabKey === 'copilot') emptyState.classList.add('hidden');
      const repState = document.getElementById('resReport');
      if (repState && tabKey === 'copilot') repState.classList.remove('hidden');

      document.querySelectorAll('.res-tab').forEach(b => {
        b.classList.remove('active', 'bg-white', 'text-black', 'shadow');
        b.classList.add('opacity-60');
      });
      document.querySelectorAll('#resReport > div').forEach(div => div.classList.add('hidden'));

      const activeBtn = document.querySelector('.res-tab[data-res="' + tabKey + '"]');
      if (activeBtn) {
        activeBtn.classList.add('active', 'bg-white', 'text-black', 'shadow');
        activeBtn.classList.remove('opacity-60');
      }

      const pane = document.getElementById('tab-' + tabKey);
      if (pane) pane.classList.remove('hidden');
    }

    // -------------------------------------------------------------------------
    // AI FORENSIC COPILOT CONTROLS & CHAT STREAM
    // -------------------------------------------------------------------------
    let copilotChatHistory = [];

    function openCopilotTab() {
      const resEl = document.getElementById('results');
      if (resEl) resEl.scrollIntoView({ behavior: 'smooth' });
      switchResultTab('copilot');
      const inp = document.getElementById('copilotInput');
      if (inp) setTimeout(() => inp.focus(), 400);
    }

    function clearCopilotChat() {
      copilotChatHistory = [];
      const stream = document.getElementById('copilotChatStream');
      if (stream) {
        stream.innerHTML = `
          <div class="flex gap-3 items-start">
            <div class="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-400/40 flex-shrink-0 flex items-center justify-center text-cyan-300 text-xs">
              <i class="fa-solid fa-robot"></i>
            </div>
            <div class="glass bg-white/5 p-4 rounded-2xl border border-white/10 max-w-2xl space-y-2 text-slate-200">
              <div class="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider flex items-center justify-between">
                <span>TraceMail Forensic Copilot</span>
                <span class="opacity-50">SESSION RESET</span>
              </div>
              <p class="text-xs leading-relaxed">
                Chat history cleared. You can ask me any question about the current email headers, domain WHOIS records, routing hops, or incident remediation.
              </p>
            </div>
          </div>
        `;
      }
    }

    function askCopilotPrompt(promptText) {
      const inp = document.getElementById('copilotInput');
      if (inp) inp.value = promptText;
      sendCopilotMessage();
    }

    function formatCopilotMarkdown(md) {
      if (!md) return '';
      let escaped = md
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

      escaped = escaped.replace(/^### (.*$)/gim, '<h4 class="text-sm font-bold text-cyan-300 mt-2 mb-1 border-b border-white/10 pb-1">$1</h4>');
      escaped = escaped.replace(/^#### (.*$)/gim, '<h5 class="text-xs font-bold text-amber-300 mt-2 mb-1">$1</h5>');
      escaped = escaped.replace(/\*\*(.*?)\*\*/g, '<strong class="text-white font-bold">$1</strong>');
      escaped = escaped.replace(/\*(.*?)\*/g, '<em class="text-slate-300 italic">$1</em>');
      escaped = escaped.replace(/`([^`]+)`/g, '<code class="bg-white/10 text-cyan-300 px-1.5 py-0.5 rounded font-mono text-[11px]">$1</code>');
      escaped = escaped.replace(/^- (.*$)/gim, '<div class="flex items-start gap-1.5 my-1 ml-1"><span class="text-cyan-400 font-bold">›</span><span>$1</span></div>');
      escaped = escaped.replace(/\n\n/g, '<div class="h-2"></div>');
      escaped = escaped.replace(/\n/g, '<br/>');
      return escaped;
    }

    async function sendCopilotMessage() {
      const inputEl = document.getElementById('copilotInput');
      const sendBtn = document.getElementById('copilotSendBtn');
      const stream = document.getElementById('copilotChatStream');
      if (!inputEl || !stream) return;

      const userText = inputEl.value.trim();
      if (!userText) return;

      const userBubble = document.createElement('div');
      userBubble.className = 'flex gap-3 items-start justify-end';
      userBubble.innerHTML = `
        <div class="glass bg-gradient-to-r from-cyan-950/40 to-blue-950/40 p-3.5 rounded-2xl border border-cyan-400/30 max-w-xl text-white text-xs font-mono">
          <div class="text-[9px] text-cyan-400 font-bold uppercase tracking-wider mb-1 flex justify-between">
            <span>YOU (ANALYST)</span>
            <span class="opacity-50">${new Date().toLocaleTimeString()}</span>
          </div>
          <div>${userText.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
        </div>
        <div class="w-8 h-8 rounded-xl bg-violet-500/20 border border-violet-400/40 flex-shrink-0 flex items-center justify-center text-violet-300 text-xs">
          <i class="fa-solid fa-user-shield"></i>
        </div>
      `;
      stream.appendChild(userBubble);
      inputEl.value = '';
      stream.scrollTop = stream.scrollHeight;

      const loadingId = 'copilotLoading_' + Date.now();
      const loadingBubble = document.createElement('div');
      loadingBubble.id = loadingId;
      loadingBubble.className = 'flex gap-3 items-start';
      loadingBubble.innerHTML = `
        <div class="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-400/40 flex-shrink-0 flex items-center justify-center text-cyan-300 text-xs">
          <i class="fa-solid fa-robot animate-spin"></i>
        </div>
        <div class="glass bg-white/5 p-3.5 rounded-2xl border border-white/10 text-xs text-slate-300 flex items-center gap-2 font-mono">
          <span class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
          <span>Dissecting forensic invariants & threat vectors...</span>
        </div>
      `;
      stream.appendChild(loadingBubble);
      stream.scrollTop = stream.scrollHeight;

      if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.classList.add('opacity-50');
      }

      try {
        const payload = {
          message: userText,
          report: currentForensicReport || null,
          history: copilotChatHistory
        };

        const res = await fetch('/api/copilot/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const data = await res.json();
        const loader = document.getElementById(loadingId);
        if (loader) loader.remove();

        const formattedHtml = formatCopilotMarkdown(data.reply || 'No response generated.');

        copilotChatHistory.push({ role: 'user', content: userText });
        copilotChatHistory.push({ role: 'assistant', content: data.reply });
        if (copilotChatHistory.length > 10) copilotChatHistory = copilotChatHistory.slice(-10);

        const botBubble = document.createElement('div');
        botBubble.className = 'flex gap-3 items-start';
        botBubble.innerHTML = `
          <div class="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-400/40 flex-shrink-0 flex items-center justify-center text-cyan-300 text-xs shadow-lg shadow-cyan-500/20">
            <i class="fa-solid fa-brain-circuit"></i>
          </div>
          <div class="glass bg-white/5 p-4 rounded-2xl border border-white/10 max-w-2xl space-y-2 text-slate-200">
            <div class="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider flex items-center justify-between border-b border-white/5 pb-1 mb-2">
              <span class="flex items-center gap-1.5">
                <i class="fa-solid fa-shield-halved"></i>
                <span>FORENSIC COPILOT • ${data.category || 'ANALYSIS'}</span>
              </span>
              <span class="text-[9px] opacity-40">${data.engine === 'ollama' ? 'LOCAL NEURAL OLLAMA' : 'TRACE-MAIL FORENSIC ENGINE'}</span>
            </div>
            <div class="text-xs leading-relaxed space-y-1">${formattedHtml}</div>
          </div>
        `;
        stream.appendChild(botBubble);

        if (data.suggested_prompts && Array.isArray(data.suggested_prompts)) {
          const chipsContainer = document.getElementById('copilotChips');
          if (chipsContainer && data.suggested_prompts.length > 0) {
            chipsContainer.innerHTML = data.suggested_prompts.map(p => `
              <button type="button" onclick="askCopilotPrompt('${p.replace(/'/g, "\\'")}')" class="px-3 py-1.5 rounded-xl bg-black/40 hover:bg-cyan-500/20 border border-white/10 hover:border-cyan-400/50 text-xs font-mono text-cyan-300 transition">
                › ${p}
              </button>
            `).join('');
          }
        }

        stream.scrollTop = stream.scrollHeight;
      } catch (err) {
        console.error('[TraceMail Copilot] Error:', err);
        const loader = document.getElementById(loadingId);
        if (loader) loader.remove();

        const errBubble = document.createElement('div');
        errBubble.className = 'flex gap-3 items-start';
        errBubble.innerHTML = `
          <div class="w-8 h-8 rounded-xl bg-red-500/20 border border-red-400/40 flex-shrink-0 flex items-center justify-center text-red-300 text-xs">
            <i class="fa-solid fa-triangle-exclamation"></i>
          </div>
          <div class="glass bg-red-950/20 p-3.5 rounded-2xl border border-red-500/30 text-xs text-red-300 max-w-xl font-mono">
            Error querying Copilot: ${err.message}. Please check connection or retry.
          </div>
        `;
        stream.appendChild(errBubble);
        stream.scrollTop = stream.scrollHeight;
      } finally {
        if (sendBtn) {
          sendBtn.disabled = false;
          sendBtn.classList.remove('opacity-50');
        }
      }
    }

    // 3. Dropdown selection handler
    function onSampleDropdownChange(val) {
      if (val) {
        loadScenarioIntoConsole(val, false);
      }
    }

    // 4. Import selected sample button handler
    async function importSelectedSample(autoScan = false) {
      const sel = document.getElementById('sampleSelect');
      const filename = sel ? sel.value : '';
      if (!filename) {
        alert('Please select a sample email from the dropdown first.');
        return;
      }
      await loadScenarioIntoConsole(filename, autoScan);
    }

    // 5. Core Ingestion into Console Editor
    async function loadScenarioIntoConsole(filename, autoScan = false) {
      console.log('[TraceMail] Loading scenario:', filename, 'autoScan:', autoScan);
      const notice = document.getElementById('importNotice');
      const noticeText = document.getElementById('importNoticeText');
      const fileLabel = document.getElementById('fileLabel');
      const emailBody = document.getElementById('emailBody');
      const fromInput = document.getElementById('fromInput');
      const fileInput = document.getElementById('fileInput');

      try {
        const res = await fetch('/api/sample/' + encodeURIComponent(filename));
        if (!res.ok) throw new Error('Could not fetch sample ' + filename + ' (' + res.status + ')');
        const data = await res.json();

        // Populate raw RFC 5322 text in console
        if (emailBody) emailBody.value = data.content;
        if (fileInput) fileInput.value = '';
        if (fileLabel) fileLabel.innerText = 'Sample Active: ' + filename;

        const match = data.content.match(/From:[ \t]*([^\r\n]+)/i);
        if (match && fromInput) {
          fromInput.value = match[1].trim();
        }

        // Sync dropdown
        const sel = document.getElementById('sampleSelect');
        if (sel && sel.value !== filename) {
          sel.value = filename;
        }

        // Feedback banner
        if (notice && noticeText) {
          notice.classList.remove('hidden');
          noticeText.innerText = '✓ Successfully loaded ' + filename + ' (' + data.content.length.toLocaleString() + ' bytes into console)';
        }

        // Flash console border
        if (emailBody) {
          emailBody.classList.add('border-cyan-400');
          setTimeout(() => { emailBody.classList.remove('border-cyan-400'); }, 1200);
        }

        // Scroll to console editor
        const scanEl = document.getElementById('scan');
        if (scanEl && !autoScan) {
          scanEl.scrollIntoView({ behavior: 'smooth' });
        }

        if (autoScan) {
          setTimeout(async () => {
            await runForensicScan();
          }, 300);
        }
      } catch (err) {
        console.error('[TraceMail] Scenario load error:', err);
        alert('Scenario Load Error: ' + err.message);
      }
    }

    // 6. Hero demo pill click handler
    async function loadScenario(filename) {
      const scanEl = document.getElementById('scan');
      if (scanEl) scanEl.scrollIntoView({ behavior: 'smooth' });
      await loadScenarioIntoConsole(filename, true);
    }

    // 7. Sync Sample List from Server
    async function initSampleDropdown() {
      try {
        const res = await fetch('/api/samples');
        if (!res.ok) return;
        const data = await res.json();
        const badge = document.getElementById('sampleLoadBadge');
        if (badge && data.samples) {
          badge.innerText = data.samples.length + ' pre-loaded samples ready';
        }
      } catch (e) {
        console.warn('[TraceMail] Could not sync sample list:', e);
      }
    }
    initSampleDropdown();

    // 8. Unified Forensic Deep Scan Executor
    async function runForensicScan() {
      console.log('[TraceMail] Running forensic deep scan...');
      const formEl = document.getElementById('f');
      const scanBtn = document.getElementById('scanBtn');
      const out = document.getElementById('out');
      const scoreEl = document.getElementById('score');
      const statusMsg = document.getElementById('scanStatusMsg');
      const emailBodyEl = document.getElementById('emailBody');
      const fileInputEl = document.getElementById('fileInput');

      const bodyText = emailBodyEl ? emailBodyEl.value.trim() : '';
      const hasFile = fileInputEl && fileInputEl.files && fileInputEl.files.length > 0;

      if (!bodyText && !hasFile) {
        alert('Please select a sample email from the repository, drop a .eml file, or paste raw RFC 5322 headers into the console first.');
        return;
      }

      if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i><span>ANALYZING INVARIANTS...</span>';
      }
      if (scoreEl) scoreEl.textContent = '...';
      if (statusMsg) statusMsg.textContent = 'PIPELINE EXECUTING...';
      if (out) out.textContent = 'Pipeline executing: RFC Header Invariants → Safe Link Inspection → BEC Multi-Signal Model → GeoIP Telemetry...';

      try {
        const fd = formEl ? new FormData(formEl) : new FormData();
        if (!formEl) {
          fd.append('email_body', bodyText);
        }

        const r = await fetch('/scan', { method: 'POST', body: fd });
        const j = await r.json();
        if (!r.ok) {
          throw new Error(j.detail || 'Forensic scan failed (' + r.status + ')');
        }
        currentForensicReport = j;

        renderCompleteForensics(j);

        const resEl = document.getElementById('results');
        if (resEl) {
          resEl.scrollIntoView({ behavior: 'smooth' });
        }
      } catch (err) {
        console.error('[TraceMail] Scan error:', err);
        if (out) out.textContent = 'Scan Error: ' + err.message;
        if (statusMsg) statusMsg.textContent = 'ERROR: ' + err.message;
        alert('Scan Error: ' + err.message);
      } finally {
        if (scanBtn) {
          scanBtn.disabled = false;
          scanBtn.innerHTML = '<i class="fa-solid fa-bolt"></i><span>RUN FORENSIC DEEP SCAN</span>';
        }
      }
    }

    // 9. Render Complete Forensic Results
    function renderCompleteForensics(j) {
      const score = typeof j.fraud_score === 'number' ? j.fraud_score : 0;
      const statusMsg = document.getElementById('scanStatusMsg');
      if (statusMsg) statusMsg.textContent = 'SCAN COMPLETE';

      // Score Metric
      const scoreEl = document.getElementById('score');
      if (scoreEl) {
        scoreEl.textContent = score;
        scoreEl.style.color = score > 70 ? '#ef4444' : score > 40 ? '#f59e0b' : '#22c55e';
      }
      if (typeof gsap !== 'undefined' && gsap.to) {
        try {
          gsap.to('#score', { innerText: score, snap: { innerText: 1 }, duration: 1 });
        } catch (e) {}
      }
      const barEl = document.getElementById('bar');
      if (barEl) barEl.style.width = score + '%';

      const labelEl = document.getElementById('label');
      if (labelEl) {
        const labelText = (j.label || 'ANALYZED').toUpperCase();
        labelEl.innerText = labelText;
        labelEl.style.color = score > 70 ? '#ef4444' : score > 40 ? '#f59e0b' : '#22c55e';
      }

      const becType = (j.ai && j.ai.bec_type) ? j.ai.bec_type : 'none';
      const becEl = document.getElementById('bec');
      if (becEl) becEl.innerText = becType.toUpperCase();
      const confEl = document.getElementById('conf');
      if (confEl) confEl.innerText = (j.confidence || 85) + '% confidence';

      // Update Copilot Status Badge
      const copilotBadge = document.getElementById('copilotReportBadge');
      if (copilotBadge) {
        copilotBadge.innerText = 'Active Scan: ' + (j.label || 'ANALYZED').toUpperCase() + ' (' + score + '/100)';
        copilotBadge.className = 'px-2.5 py-0.5 rounded-full text-[10px] font-mono ' + (score > 70 ? 'bg-red-500/20 text-red-300 border border-red-500/40' : score > 40 ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40');
      }

      // Auth Pills in Top Console
      const h = j.headers || {};
      applyPillStatus('spf', h.spf);
      applyPillStatus('dkim', h.dkim);
      applyPillStatus('dmarc', h.dmarc);
      const ipLabelEl = document.getElementById('ipLabel');
      if (ipLabelEl) ipLabelEl.textContent = h.origin_ip || 'INTERNAL RELAY';

      // Reveal Results Section
      const emptyState = document.getElementById('resEmptyState');
      if (emptyState) emptyState.classList.add('hidden');
      const repState = document.getElementById('resReport');
      if (repState) repState.classList.remove('hidden');

      // Theme logic
      let themeBg = 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300';
      let headline = 'AUTHENTICATED / INTEGRITY VERIFIED';
      let summary = 'The message conforms with SPF, DKIM, and DMARC invariants. No obfuscated redirects or wire transfer anomalies detected.';
      let iconHtml = '<i class="fa-solid fa-shield-check text-emerald-400"></i>';

      if (score >= 70) {
        themeBg = 'bg-red-950/40 border-red-500/40 text-red-300';
        headline = 'CRITICAL THREAT / FRAUD DETECTED';
        summary = 'Severe RFC spoofing detected alongside financial urgency phrases or malicious link redirection.';
        iconHtml = '<i class="fa-solid fa-skull-crossbones text-red-400"></i>';
      } else if (score >= 40) {
        themeBg = 'bg-amber-950/40 border-amber-500/40 text-amber-300';
        headline = 'SUSPICIOUS INVARIANT ANOMALIES';
        summary = 'Authentication check mismatches or intermediate relay anomalies warrant analytical review.';
        iconHtml = '<i class="fa-solid fa-triangle-exclamation text-amber-400"></i>';
      }

      const vBanner = document.getElementById('verdictBanner');
      if (vBanner) vBanner.className = 'glass rounded-2xl p-6 border flex flex-wrap items-center justify-between gap-4 ' + themeBg;
      const vBadge = document.getElementById('verdictBadge');
      if (vBadge) {
        vBadge.innerText = (j.risk_level || 'ANALYZED').toUpperCase();
        vBadge.className = 'text-[10px] uppercase font-bold tracking-widest px-2.5 py-0.5 rounded-full border ' + themeBg;
      }
      const vHead = document.getElementById('verdictHeadline');
      if (vHead) vHead.innerText = headline;
      const vSum = document.getElementById('verdictSummary');
      if (vSum) vSum.innerText = summary;
      const vIcon = document.getElementById('verdictIconBox');
      if (vIcon) {
        vIcon.innerHTML = iconHtml;
        vIcon.className = 'w-14 h-14 rounded-2xl flex items-center justify-center text-2xl bg-black/40 border border-white/10';
      }
      const cNum = document.getElementById('confidenceNum');
      if (cNum) cNum.innerText = (j.confidence || 85) + '%';

      // Reasons List
      const rList = document.getElementById('reasonsList');
      if (rList) {
        rList.innerHTML = '';
        const reasons = (j.ai && j.ai.reasons && j.ai.reasons.length) ? j.ai.reasons : (h.reasons || ['Normal forensic delivery profile']);
        reasons.forEach(r => {
          const li = document.createElement('li');
          li.className = 'flex items-start gap-2 bg-black/30 p-2.5 rounded-xl border border-white/5';
          li.innerHTML = '<i class="fa-solid fa-circle-exclamation text-amber-400 mt-0.5"></i> <span class="opacity-90">' + r + '</span>';
          rList.appendChild(li);
        });
      }

      // BEC Vector
      const bBadge = document.getElementById('becVectorBadge');
      if (bBadge) bBadge.innerText = becType.toUpperCase();
      let becGuide = 'Normal communication. No unauthorized wire diversion or credential phishing hooks.';
      if (becType.includes('diversion') || becType.includes('wire')) {
        becGuide = 'CRITICAL: Out-of-band verification required. Email attempts unauthorized bank account or wire transfer modification with mismatched Reply-To domain. Call the vendor at a verified telephone number before updating banking records.';
      } else if (becType.includes('credential')) {
        becGuide = 'CRITICAL: Phishing lures discovered aiming to harvest enterprise credentials. Block link destination at perimeter gateway.';
      } else if (becType.includes('impersonation')) {
        becGuide = 'WARNING: Executive or VIP impersonation attempted via forged display headers.';
      }
      const bGuide = document.getElementById('becGuidance');
      if (bGuide) bGuide.innerText = becGuide;

      // Evidence Hash & Timestamp
      const hVal = document.getElementById('hashVal');
      if (hVal) hVal.innerText = j.evidence_hash || 'SHA256_UNKNOWN';
      const tVal = document.getElementById('timestampVal');
      if (tVal) tVal.innerText = j.timestamp ? new Date(j.timestamp).toUTCString() : '';

      // TAB 2: RFC Headers Fill
      setAuthBox('spfBox', 'spfStatus', h.spf, 'SPF');
      setAuthBox('dkimBox', 'dkimStatus', h.dkim, 'DKIM');
      setAuthBox('dmarcBox', 'dmarcStatus', h.dmarc, 'DMARC');

      const hdrF = document.getElementById('hdrFrom'); if (hdrF) hdrF.innerText = h.from || 'Not parsed';
      const hdrRP = document.getElementById('hdrReturnPath');
      if (hdrRP) {
        hdrRP.innerText = h.return_path || 'None (Spoofed)';
        if (h.return_path && h.from && !h.return_path.includes((h.from.split('@')[1] || ' '))) {
          hdrRP.innerHTML += ' <span class="text-red-400 font-bold ml-2">[MISMATCH FLAGGED]</span>';
        }
      }
      const hdrRT = document.getElementById('hdrReplyTo'); if (hdrRT) hdrRT.innerText = h.reply_to || 'Matching From';
      const hdrIP = document.getElementById('hdrOriginIp'); if (hdrIP) hdrIP.innerText = h.origin_ip || 'Private / Loopback Relay';
      const hopsCount = typeof h.hops === 'number' ? h.hops : (Array.isArray(h.hops) ? h.hops.length : (h.total_hops || 0));
      const hdrHp = document.getElementById('hdrHops'); if (hdrHp) hdrHp.innerText = hopsCount + ' intermediate hops recorded';
      const hdrSp = document.getElementById('hdrSpoof'); if (hdrSp) hdrSp.innerText = (h.spoof_score || 0) + ' / 100';

      // TAB 3: Links Fill
      const links = j.links || [];
      const lList = document.getElementById('linksList');
      const lSum = document.getElementById('linksSummary');
      if (lSum) lSum.innerText = links.length + ' URLs Discovered';

      if (lList) {
        lList.innerHTML = '';
        if (links.length === 0) {
          lList.innerHTML = '<div class="p-6 bg-black/20 rounded-xl text-center text-xs opacity-50 flex items-center justify-center gap-2"><i class="fa-solid fa-shield-check text-emerald-400"></i> No external hyperlinks discovered in message body.</div>';
        } else {
          links.forEach(l => {
            const isSusp = l.suspicious;
            const card = document.createElement('div');
            card.className = 'p-3.5 rounded-xl border ' + (isSusp ? 'bg-red-950/20 border-red-500/30' : 'bg-black/30 border-white/5') + ' font-mono text-xs space-y-1';
            card.innerHTML = '<div class="flex justify-between items-center gap-2"><span class="text-cyan-300 break-all">' + l.original + '</span><span class="px-2.5 py-0.5 rounded-full text-[9px] font-bold ' + (isSusp ? 'bg-red-500/20 text-red-300 border border-red-500/40' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40') + '">' + (isSusp ? 'SUSPICIOUS' : 'CLEAN') + '</span></div>' +
              (l.final && l.final !== l.original ? '<div class="text-[11px] opacity-70">↳ Resolved: <span class="text-amber-300 break-all">' + l.final + '</span> (' + l.redirects + ' redirects)</div>' : '') +
              (l.punycode ? '<div class="text-red-400 text-[10px]"><i class="fa-solid fa-triangle-exclamation"></i> Punycode Obfuscation (xn--) Detected</div>' : '');
            lList.appendChild(card);
          });
        }
      }

      // TAB 4: Geo & WHOIS Fill
      const tr = j.trace || {};
      const geo = tr.geo || {};
      const gIp = document.getElementById('geoIpVal'); if (gIp) gIp.innerText = geo.ip || h.origin_ip || 'N/A';
      const gLoc = document.getElementById('geoLocVal'); if (gLoc) gLoc.innerText = (geo.city || 'Unknown') + ', ' + (geo.region || '') + ', ' + (geo.country || 'Unknown');
      const gCoord = document.getElementById('geoCoordsVal'); if (gCoord) gCoord.innerText = geo.loc || (geo.lat ? (geo.lat + ', ' + geo.lon) : (geo.latitude ? (geo.latitude + ', ' + geo.longitude) : 'N/A'));
      const gOrg = document.getElementById('geoOrgVal'); if (gOrg) gOrg.innerText = geo.org || geo.organization || 'N/A';

      const whoisData = geo.whois || {};
      const wReg = document.getElementById('whoisReg'); if (wReg) wReg.innerText = whoisData.registrar || 'N/A';
      const wDate = document.getElementById('whoisDate'); if (wDate) wDate.innerText = whoisData.creation || 'N/A';
      
      const hostFlags = tr.hosting_flags || [];
      const hFlag = document.getElementById('hostingFlag');
      if (hFlag) {
        hFlag.innerText = hostFlags.length ? hostFlags.join(', ') : 'Standard ISP / Non-Datacenter';
        hFlag.className = hostFlags.length ? 'text-amber-400 font-bold' : 'text-white';
      }

      const mxBox = document.getElementById('mxRecords');
      if (mxBox) {
        const mxList = Array.isArray(tr.mx) ? tr.mx : (typeof tr.mx === 'string' && tr.mx ? [tr.mx] : []);
        if (mxList.length) {
          mxBox.innerHTML = mxList.map(m => '<div class="text-cyan-300">↳ ' + m + '</div>').join('');
        } else {
          mxBox.innerText = 'No MX exchange records found for sender domain.';
        }
      }

      // 3D Globe Threat Radar Projection
      if (typeof globe !== 'undefined' && globe) {
        let lat = null, lng = null;
        if (geo.loc) {
          const parts = geo.loc.split(',').map(Number);
          lat = parts[0]; lng = parts[1];
        } else if (geo.lat !== undefined && geo.lon !== undefined && geo.lat !== null && geo.lon !== null) {
          lat = Number(geo.lat); lng = Number(geo.lon);
        } else if (geo.latitude !== undefined && geo.longitude !== undefined && geo.latitude !== null && geo.longitude !== null) {
          lat = Number(geo.latitude); lng = Number(geo.longitude);
        }

        const hudCoords = document.getElementById('hudCoords');

        if (lat !== null && lng !== null && !isNaN(lat) && !isNaN(lng)) {
          lastThreatOrigin = {
            lat,
            lng,
            city: geo.city || 'Unknown City',
            country: geo.country || 'Unknown Country',
            ip: geo.ip || h.origin_ip || 'Target IP',
            org: geo.org || geo.organization || 'Registered ISP / Cloud'
          };

          if (hudCoords) {
            hudCoords.innerText = 'Lock: ' + lat.toFixed(2) + '°, ' + lng.toFixed(2) + '° (' + (geo.country || 'EXT') + ')';
            hudCoords.className = 'text-cyan-400 font-bold';
          }

          const targetLabel = '<div style="background: rgba(10,15,29,0.95); border: 1px solid #ef4444; padding: 10px 14px; border-radius: 10px; font-family: monospace; font-size: 11px; color: #fff; box-shadow: 0 8px 25px rgba(0,0,0,0.8); pointer-events: none;">' +
            '<div style="color: #ef4444; font-weight: bold; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">' +
              '<span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#ef4444;"></span>' +
              'ORIGIN THREAT VECTOR' +
            '</div>' +
            '<div style="color: #06b6d4; margin-bottom: 2px;">IP: <span style="color:#fff;">' + lastThreatOrigin.ip + '</span></div>' +
            '<div style="margin-bottom: 2px;">GEO: <span style="color:#cbd5e1;">' + lastThreatOrigin.city + ', ' + lastThreatOrigin.country + '</span></div>' +
            '<div style="margin-bottom: 2px;">ISP: <span style="color:#94a3b8;">' + lastThreatOrigin.org + '</span></div>' +
            '<div style="color: #f59e0b; margin-top: 4px; font-size: 10px;">LAT/LON: ' + lat.toFixed(4) + ', ' + lng.toFixed(4) + '</div>' +
          '</div>';

          const localLabel = '<div style="background: rgba(10,15,29,0.95); border: 1px solid #10b981; padding: 8px 12px; border-radius: 8px; font-family: monospace; font-size: 11px; color: #fff; box-shadow: 0 6px 20px rgba(0,0,0,0.8); pointer-events: none;">' +
            '<div style="color: #10b981; font-weight: bold; margin-bottom: 4px;">🛡️ DEFENDER MAILBOX (TARGET)</div>' +
            '<div>Coordinates: 20.5937° N, 78.9629° E</div>' +
            '<div style="color: #94a3b8; font-size: 10px;">Secure Inbox Gateway</div>' +
          '</div>';

          try {
            globe.arcsData([{
              startLat: lat,
              startLng: lng,
              endLat: 20.5937,
              endLng: 78.9629,
              color: ['#ef4444', '#06b6d4']
            }]);

            globe.pointsData([
              { lat: lat, lng: lng, size: 0.8, color: '#ef4444', label: targetLabel },
              { lat: 20.5937, lng: 78.9629, size: 0.5, color: '#10b981', label: localLabel }
            ]);

            if (typeof globe.ringsData === 'function') {
              globe.ringsData([{ lat: lat, lng: lng }]);
            }

            if (typeof globe.controls === 'function') {
              globe.controls().autoRotate = false;
              globeAutoRotate = false;
              const btn = document.getElementById('orbitBtn');
              if (btn) {
                btn.innerText = '⟳ Orbit: OFF';
                btn.className = 'px-2.5 py-1 bg-black/75 hover:bg-black text-slate-400 border border-white/20 rounded-lg text-[10px] font-mono transition backdrop-blur-md shadow-md cursor-pointer';
              }
            }

            globe.pointOfView({ lat: lat, lng: lng, altitude: 1.6 }, 1200);
          } catch (globeErr) {
            console.warn('[TraceMail] Globe update warning:', globeErr);
          }
        } else {
          lastThreatOrigin = null;
          if (hudCoords) {
            hudCoords.innerText = 'Internal / Non-Routable IP';
            hudCoords.className = 'opacity-40';
          }
          try {
            globe.arcsData([]);
            globe.pointsData([]);
            if (typeof globe.ringsData === 'function') globe.ringsData([]);
          } catch (e) {}
        }
      }

      // TAB 5: IOC Graph Fill
      const ioc = j.ioc_graph || {};
      const nodes = ioc.nodes || [];
      const edges = ioc.edges || [];
      const iocCountEl = document.getElementById('iocCountBadge');
      if (iocCountEl) iocCountEl.innerText = nodes.length + ' Nodes • ' + edges.length + ' Relations';
      const iocBox = document.getElementById('iocGraphContainer');
      if (iocBox) {
        iocBox.innerHTML = '';
        if (nodes.length === 0) {
          iocBox.innerHTML = '<p class="text-xs opacity-40 col-span-full py-8 text-center">No IOC entities isolated.</p>';
        } else {
          nodes.forEach(n => {
            const typeIcons = {
              'EMAIL': 'fa-envelope text-cyan-400',
              'DOMAIN': 'fa-globe text-violet-400',
              'IP': 'fa-server text-emerald-400',
              'URL_DOMAIN': 'fa-link text-amber-400',
              'ATTACHMENT': 'fa-paperclip text-rose-400'
            };
            const icon = typeIcons[n.type] || 'fa-circle-nodes text-slate-400';
            const card = document.createElement('div');
            card.className = 'glass glass-card p-4 rounded-xl border border-white/10 font-mono text-xs space-y-1.5';
            card.innerHTML = '<div class="flex items-center justify-between"><span class="text-[10px] tracking-wider opacity-50 uppercase flex items-center gap-1.5"><i class="fa-solid ' + icon + '"></i> ' + n.type + '</span><span class="text-[9px] bg-white/10 px-2 py-0.5 rounded-full">' + ((n.id || '').split(':')[0]) + '</span></div><div class="text-white font-bold truncate">' + (n.label || n.id) + '</div>';
            iocBox.appendChild(card);
          });
        }
      }

      // TAB 6: Raw Evidence JSON
      const outEl = document.getElementById('out');
      if (outEl) outEl.textContent = JSON.stringify(j, null, 2);
    }

    function applyPillStatus(id, isPass) {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = isPass ? 'PASS' : 'FAIL';
      el.className = 'px-3 py-1 rounded-full font-bold ' + (isPass ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-red-500/20 text-red-300 border border-red-500/40');
    }

    function setAuthBox(boxId, statusId, isPass, label) {
      const b = document.getElementById(boxId);
      const s = document.getElementById(statusId);
      if (!b || !s) return;
      if (isPass) {
        s.innerText = label + ': PASS';
        s.className = 'text-xs font-bold font-mono px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
        b.className = 'glass rounded-2xl p-4 border border-emerald-500/30';
      } else {
        s.innerText = label + ': FAIL / MISSING';
        s.className = 'text-xs font-bold font-mono px-3 py-1 rounded-full bg-red-500/20 text-red-300 border border-red-500/40';
        b.className = 'glass rounded-2xl p-4 border border-red-500/30';
      }
    }

    function copyEvidenceHash() {
      if (currentForensicReport && currentForensicReport.evidence_hash) {
        navigator.clipboard.writeText(currentForensicReport.evidence_hash);
        alert('Evidence SHA-256 Hash copied to clipboard!');
      }
    }

    function copyRawEvidence() {
      if (currentForensicReport) {
        navigator.clipboard.writeText(JSON.stringify(currentForensicReport, null, 2));
        alert('Raw forensic JSON evidence copied to clipboard!');
      }
    }

    // =========================================================================
    // OPTIONAL VISUAL ENHANCEMENTS (SAFE & PROTECTED)
    // =========================================================================
    // 1. Lenis Smooth Scroll
    try {
      if (typeof Lenis !== 'undefined') {
        const lenis = new Lenis({ duration: 1.2 });
        function raf(t) { lenis.raf(t); requestAnimationFrame(raf); }
        requestAnimationFrame(raf);
      }
    } catch (e) {
      console.warn('Lenis disabled:', e);
    }

    // 2. GSAP Animations
    try {
      if (typeof gsap !== 'undefined') {
        if (typeof ScrollTrigger !== 'undefined') gsap.registerPlugin(ScrollTrigger);
        gsap.to('.reveal', { clipPath: 'inset(0 0 0% 0)', duration: 1.2, stagger: 0.15, ease: 'power4.out' });
        gsap.from('.glass', { y: 40, opacity: 0, duration: 1, stagger: 0.08, ease: 'power3.out', scrollTrigger: { trigger: '#scan', start: 'top 85%' } });
      }
    } catch (e) {
      console.warn('GSAP animation disabled:', e);
    }

    // 3. Magnetic Hover
    document.querySelectorAll('.magnet').forEach(b => {
      b.addEventListener('mousemove', e => {
        const r = b.getBoundingClientRect();
        b.style.transform = 'translate(' + ((e.clientX - r.left - r.width / 2) * 0.25) + 'px, ' + ((e.clientY - r.top - r.height / 2) * 0.35) + 'px)';
      });
      b.addEventListener('mouseleave', () => b.style.transform = 'translate(0,0)');
    });

    // 4. Fluid Canvas Background
    try {
      const c = document.getElementById('fluid');
      if (c && c.getContext) {
        const x = c.getContext('2d');
        if (x) {
          let w, h, t = 0, mx = 0, my = 0;
          function rs() { w = c.width = innerWidth; h = c.height = innerHeight; }
          rs();
          window.addEventListener('resize', rs);
          window.addEventListener('mousemove', e => { mx = e.clientX; my = e.clientY; });

          function draw() {
            t += 0.006;
            x.clearRect(0, 0, w, h);
            const g = x.createRadialGradient(mx, my, 0, mx, my, w);
            g.addColorStop(0, 'rgba(6,182,212,0.15)');
            g.addColorStop(0.35, 'rgba(139,92,246,0.08)');
            g.addColorStop(1, 'rgba(0,0,0,0)');
            x.fillStyle = g;
            x.fillRect(0, 0, w, h);

            for (let i = 0; i < 3; i++) {
              x.beginPath();
              for (let a = 0; a < Math.PI * 2; a += 0.02) {
                const r = 280 + Math.sin(a * 3 + t + i) * 90 + Math.cos(a * 2 - t) * 60;
                const px = w * 0.55 + Math.cos(a) * r, py = h * 0.45 + Math.sin(a) * r;
                x.lineTo(px, py);
              }
              x.strokeStyle = 'rgba(6,182,212,' + (0.08 - i * 0.02) + ')';
              x.lineWidth = 1.5;
              x.stroke();
            }
            requestAnimationFrame(draw);
          }
          draw();
        }
      }
    } catch (e) {
      console.warn('Fluid canvas skipped:', e);
    }

    // 5. 3D Globe Telemetry Radar Setup
    try {
      const globeElem = document.getElementById('globe');
      if (typeof Globe === 'function' && globeElem) {
        globe = Globe()(globeElem)
          .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
          .backgroundColor('#000000')
          .width(globeElem.clientWidth || 400)
          .height(320)
          .showAtmosphere(true)
          .atmosphereColor('#06b6d4')
          .atmosphereAltitude(0.18)
          .arcColor('color')
          .arcDashLength(0.4)
          .arcDashGap(0.2)
          .arcDashInitialGap(() => Math.random())
          .arcDashAnimateTime(1800)
          .arcAltitude(0.25)
          .arcStroke(1.5)
          .pointColor('color')
          .pointAltitude(0.04)
          .pointRadius('size')
          .pointLabel('label');

        if (typeof globe.ringColor === 'function') {
          globe
            .ringColor(() => (t) => 'rgba(239,68,68,' + Math.max(0, 1 - t) + ')')
            .ringMaxRadius(8)
            .ringPropagationSpeed(2.5)
            .ringRepeatPeriod(900);
        }

        globe.pointOfView({ lat: 20.5937, lng: 78.9629, altitude: 2.2 });

        if (typeof globe.controls === 'function') {
          globe.controls().autoRotate = true;
          globe.controls().autoRotateSpeed = 0.5;
        }

        window.addEventListener('resize', () => {
          if (globeElem && globe && typeof globe.width === 'function') {
            globe.width(globeElem.clientWidth);
          }
        });
      }
    } catch (e) {
      console.warn('Globe.gl initialization deferred:', e);
    }

    // 6. File Input and Drag-and-Drop Handlers
    const fileInputEl = document.getElementById('fileInput');
    if (fileInputEl) {
      fileInputEl.addEventListener('change', (e) => {
        if (e.target.files && e.target.files[0]) {
          document.getElementById('fileLabel').innerText = 'Attached: ' + e.target.files[0].name;
        }
      });
    }

    const dropZone = document.getElementById('dropZone');
    if (dropZone) {
      ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
          e.preventDefault();
          e.stopPropagation();
          dropZone.classList.add('border-cyan-400', 'bg-white/10');
        }, false);
      });
      ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
          e.preventDefault();
          e.stopPropagation();
          dropZone.classList.remove('border-cyan-400', 'bg-white/10');
        }, false);
      });
      dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        if (dt && dt.files && dt.files.length > 0) {
          const file = dt.files[0];
          const input = document.getElementById('fileInput');
          if (input) input.files = dt.files;
          const lb = document.getElementById('fileLabel');
          if (lb) lb.innerText = 'Attached: ' + file.name;
        }
      });
    }

    // 7. Copilot Input Keyboard Listener
    const copilotInputEl = document.getElementById('copilotInput');
    if (copilotInputEl) {
      copilotInputEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          sendCopilotMessage();
        }
      });
    }
  </script>
</body>
</html>

```


### 📄 File: `tests/test_pipeline.py`
```python
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.evidence_ledger import EvidenceLedger
from engine.geoip_resolver import GeoIPResolver
from engine.parser import EmailParser
from engine.pipeline import ForensicPipeline


ROOT = Path(__file__).resolve().parents[1]


class PipelineTests(unittest.TestCase):
    def sample(self, name):
        return (ROOT / "sample_emails" / name).read_bytes()

    def test_hash_uses_exact_submitted_bytes(self):
        raw = b"\nFrom: sender@example.com\r\nTo: user@example.com\r\n\r\nBody\r\n"
        result = EmailParser(raw).parse()
        self.assertEqual(result["forensic_hash"], hashlib.sha256(raw).hexdigest())

    def test_demo_scenarios_have_expected_risk_order(self):
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            ceo = ForensicPipeline.process_raw_email(self.sample("ceo_bec_fraud.eml"))
            forged = ForensicPipeline.process_raw_email(self.sample("forged_relay_attack.eml"))
            legitimate = ForensicPipeline.process_raw_email(self.sample("legitimate_delivery.eml"))

        self.assertGreaterEqual(ceo["threat_analysis"]["threat_score"], 70)
        self.assertTrue(forged["hops_analysis"]["has_timing_anomalies"])
        self.assertLess(legitimate["threat_analysis"]["threat_score"], 35)
        self.assertEqual(legitimate["authentication"]["overall_status"], "REPORTED_PASS")
        self.assertGreaterEqual(ceo["ml_analysis"]["phishing_probability"], 0.65)

    def test_geoip_failure_is_unavailable_not_simulated(self):
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            result = GeoIPResolver.resolve("8.8.4.4")
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertIsNone(result["latitude"])
        self.assertEqual(result["confidence"], "NONE")

    def test_ioc_graph_is_returned(self):
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            result = ForensicPipeline.process_raw_email(self.sample("ceo_bec_fraud.eml"))
        node_types = {node["type"] for node in result["ioc_graph"]["nodes"]}
        self.assertIn("EMAIL", node_types)
        self.assertIn("IP", node_types)
        self.assertIn("URL_DOMAIN", node_types)

    def test_ledger_records_form_a_hash_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = EvidenceLedger(str(Path(directory) / "ledger.jsonl"))
            first = ledger.append("ANL-ONE", "a" * 64)
            second = ledger.append("ANL-TWO", "b" * 64)
            self.assertEqual(first["previous_record_hash"], "GENESIS")
            self.assertEqual(second["previous_record_hash"], first["record_hash"])

    def test_zero_ssrf_static_url_scanner_flags_threats_without_requests(self):
        from engine.url_scanner import URLScanner
        with patch("requests.get") as mock_get, patch("requests.head") as mock_head:
            test_urls = [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:8080/admin",
                "https://xn--paypl-qqa.com/login",
                "https://legit-site.org/docs"
            ]
            scanned = URLScanner.scan_all(test_urls)
            # Verify NO outbound network requests were made (SSRF immunity)
            mock_get.assert_not_called()
            mock_head.assert_not_called()

            self.assertTrue(scanned[0]["is_internal_or_ssrf"])
            self.assertTrue(scanned[1]["is_internal_or_ssrf"])
            self.assertTrue(scanned[2]["punycode"])
            self.assertFalse(scanned[3]["suspicious"])

    def test_evidence_precedence_suppresses_urgency_false_positives(self):
        raw_email = (
            b"From: \"GitHub Security\" <support@github.com>\r\n"
            b"To: engineer@company.com\r\n"
            b"Subject: Action Required: Personal Access Token Expiring Immediately\r\n"
            b"Date: Thu, 10 Sep 2026 12:00:00 +0000\r\n"
            b"Authentication-Results: mx.company.com;\r\n"
            b" dkim=pass header.i=@github.com header.s=s1;\r\n"
            b" spf=pass smtp.mailfrom=bounces.github.com;\r\n"
            b" dmarc=pass header.from=github.com\r\n"
            b"\r\n"
            b"Urgent action required. Your invoice attached and account verification required immediately.\r\n"
        )
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            report = ForensicPipeline.process_raw_email(raw_email)

        # Authenticated email with urgency words should NOT trigger high risk
        self.assertLess(report["threat_analysis"]["threat_score"], 25)
        self.assertEqual(report["threat_analysis"]["risk_category"], "LOW_OBSERVED_RISK")
        self.assertEqual(report["threat_analysis"]["enforcement_action"], "ALLOW")

    def test_esp_relay_alignment_passes(self):
        raw_email = (
            b"From: \"Stripe Billing\" <invoices@stripe.com>\r\n"
            b"To: finance@startup.io\r\n"
            b"Subject: Monthly Cloud Invoice Paid\r\n"
            b"Return-Path: <bounces@sendgrid.net>\r\n"
            b"Authentication-Results: mx.startup.io;\r\n"
            b" dkim=pass header.i=@stripe.com header.s=st1;\r\n"
            b" spf=pass smtp.mailfrom=bounces@sendgrid.net\r\n"
            b"\r\n"
            b"Here is your monthly invoice receipt for cloud compute services.\r\n"
        )
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            report = ForensicPipeline.process_raw_email(raw_email)

        # ESP relay with SendGrid Return-Path and valid Stripe DKIM alignment must pass DMARC
        self.assertTrue(report["authentication"]["composite_pass"])
        self.assertLess(report["threat_analysis"]["threat_score"], 25)

    def test_unverified_headers_lowers_confidence_not_threat(self):
        raw_email = (
            b"From: colleague@internal.net\r\n"
            b"To: rk@internal.net\r\n"
            b"Subject: Team Lunch Tomorrow\r\n"
            b"\r\n"
            b"Hey RK, let us meet for lunch tomorrow at 12:30.\r\n"
        )
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            report = ForensicPipeline.process_raw_email(raw_email)

        self.assertTrue(report["authentication"]["is_unverified"])
        self.assertLess(report["threat_analysis"]["threat_score"], 35)
        self.assertEqual(report["threat_analysis"]["enforcement_action"], "MONITOR")
        self.assertLessEqual(report["threat_analysis"]["confidence_score"], 65)

    def test_vendor_bank_change_bec_detected(self):
        with open("sample_emails/vendor_bank_change_bec.eml", "rb") as f:
            raw_email = f.read()
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            report = ForensicPipeline.process_raw_email(raw_email)

        # Authenticated vendor with mismatched Reply-To requesting bank change must be flagged
        threat = report["threat_analysis"]
        self.assertGreaterEqual(threat["threat_score"], 60.0)
        self.assertIn("BEC_VENDOR_FINANCIAL_DIVERSION", threat["detections"])
        self.assertIn("REPLY_TO_ORG_MISMATCH", threat["detections"])
        factors = " ".join(f["detail"] for f in threat["explainability_factors"])
        self.assertIn("Out-of-band verification required", factors)

    def test_ui_backend_mappings(self):
        from app import build_ui_compatible_payload
        with open("sample_emails/vendor_bank_change_bec.eml", "rb") as f:
            raw_email = f.read()
        with patch.object(GeoIPResolver, "_query_ip_api", return_value=None):
            GeoIPResolver.CACHE.clear()
            report = ForensicPipeline.process_raw_email(raw_email)
            ui_payload = build_ui_compatible_payload(report)

        # 1. headers.hops must be integer (not an object/list)
        self.assertIsInstance(ui_payload["headers"]["hops"], int)
        # 2. trace.mx must be a list (never raw string) so .map() succeeds
        self.assertIsInstance(ui_payload["trace"]["mx"], list)
        # 3. trace.geo must contain lat, lon, loc, and org
        geo = ui_payload["trace"]["geo"]
        self.assertIn("lat", geo)
        self.assertIn("lon", geo)
        self.assertIn("loc", geo)
        self.assertIn("org", geo)

    def test_copilot_engine_reasoning(self):
        from engine.copilot_engine import ForensicCopilot
        # 1. Standby mode and greeting
        empty_res = ForensicCopilot.query("")
        self.assertEqual(empty_res["category"], "GREETING")
        standby_res = ForensicCopilot.query("Hello")
        self.assertEqual(standby_res["category"], "STANDBY")

        # 2. Domain & Reply-to reasoning
        sample_report = {
            "fraud_score": 85,
            "risk_level": "CRITICAL",
            "label": "fraud",
            "confidence": 90,
            "headers": {
                "from": "billing@vendor.com",
                "reply_to": "attacker@evil.xyz",
                "origin_ip": "198.98.56.12",
                "spf": True,
                "dkim": True,
                "dmarc": False,
                "reasons": ["REPLY_TO_DOMAIN_MISMATCH"]
            },
            "ai": {"bec_type": "wire fraud", "reasons": ["REPLY_TO_DOMAIN_MISMATCH"]},
            "trace": {"geo": {"ip": "198.98.56.12", "city": "Dallas", "country": "US"}}
        }
        domain_res = ForensicCopilot.query("Explain the domain and reply to target", sample_report)
        self.assertEqual(domain_res["category"], "DOMAIN_ANALYSIS")
        self.assertIn("attacker@evil.xyz", domain_res["reply"])

        # 3. Header reasoning
        header_res = ForensicCopilot.query("Explain headers and SPF", sample_report)
        self.assertEqual(header_res["category"], "HEADER_ANALYSIS")
        self.assertIn("SPF", header_res["reply"])

        # 4. Out-of-band remediation
        oob_res = ForensicCopilot.query("What out of band steps should I take?", sample_report)
        self.assertEqual(oob_res["category"], "REMEDIATION")
        self.assertIn("Out-of-Band", oob_res["reply"])


if __name__ == "__main__":
    unittest.main()


```


### 📄 File: `sample_emails/vendor_bank_change_bec.eml`
```email
From: "Apex Lab Supplies - Accounts" <billing@apex-labs.example>
To: procurement@example.edu
Subject: Updated remittance details for invoice AL-20914
Date: Thu, 10 Sep 2026 11:20:00 +0530
Message-ID: <al-20914.20260910@apex-labs.example>
Return-Path: <bounces@apex-labs.example>
Reply-To: payments-update@apex-labs-payments.example
Authentication-Results: mx.example.edu;
 spf=pass smtp.mailfrom=bounces@apex-labs.example;
 dkim=pass header.d=apex-labs.example;
 dmarc=pass header.from=apex-labs.example
Received-SPF: pass (mx.example.edu: domain of apex-labs.example designates 192.0.2.88 as permitted sender)
Received: from mail.apex-labs.example (mail.apex-labs.example [192.0.2.88])
	by mx.example.edu (Postfix) with ESMTPS id 7F6E5D4C
	for <procurement@example.edu>; Thu, 10 Sep 2026 05:50:00 +0000 (UTC)
X-TraceMail-Demo: synthetic-bec-email
Content-Type: text/plain; charset="utf-8"

Hello Procurement Team,

Please treat this as confidential. Our banking details have changed ahead of
today's invoice payment. Please update the vendor record and make the wire
transfer immediately to avoid a delivery delay.

Do not call the usual accounts contact while the finance team is in an audit.
Please reply to this message once the transfer is complete.

Regards,
Accounts Receivable
Apex Lab Supplies

```


### 📄 File: `sample_emails/credential_harvest_ssrf_attack.eml`
```email
From: "AWS Security Center" <security-alerts@aws-verify-notice.com>
To: devops-lead@enterprise.org
Subject: CRITICAL: Immediate IAM Security Token Revocation and Infrastructure Audit
Date: Thu, 10 Sep 2026 14:00:00 +0530
Message-ID: <sec-revocation-20260910@aws-verify-notice.com>
Return-Path: <attacker@bulletproof-relay.xyz>
Reply-To: security-escalation@evil-phish.net
Authentication-Results: mx.enterprise.org;
 spf=fail smtp.mailfrom=attacker@bulletproof-relay.xyz;
 dkim=fail header.d=aws-verify-notice.com;
 dmarc=fail (p=quarantine) header.from=aws-verify-notice.com
Received: from unknown-relay.xyz (unknown-relay.xyz [198.98.56.12])
	by mx.enterprise.org (Postfix) with ESMTPS id 9B4F1A02
	for <devops-lead@enterprise.org>; Thu, 10 Sep 2026 08:30:00 +0000 (UTC)
Content-Type: text/plain; charset="utf-8"

ATTENTION DEVOPS ADMINISTRATOR:

An unauthorized access signature was detected targeting your primary Kubernetes cluster.
To prevent immediate service suspension, you must inspect the exposed metadata credentials:
http://169.254.169.254/latest/meta-data/iam/security-credentials/production-role

Additionally, authenticate your administrative identity through our mirror portal:
https://xn--mcrosoft-g4a.com/iam/verify-identity

Review the attached diagnostic utility to scan your local endpoint for compromised certificates:
Attachment: AWS_Security_Diagnostic_Tool.exe

Regards,
AWS Security Operations

```


### 📄 File: `sample_emails/legitimate_urgent_executive.eml`
```email
From: "Dr. Marcus Vance - Dean of Academic Affairs" <m.vance@central-tech.edu>
To: faculty-all@central-tech.edu
Subject: URGENT ACTION REQUIRED: Annual Faculty Accreditation Dossier Submission Deadline Today
Date: Thu, 10 Sep 2026 09:15:00 +0530
Message-ID: <accreditation-20260910@central-tech.edu>
Return-Path: <bounces@central-tech.edu>
Reply-To: m.vance@central-tech.edu
Authentication-Results: mx.central-tech.edu;
 spf=pass smtp.mailfrom=bounces@central-tech.edu;
 dkim=pass header.d=central-tech.edu;
 dmarc=pass (p=reject) header.from=central-tech.edu
Received-SPF: pass (mx.central-tech.edu: domain of central-tech.edu designates 198.51.100.45 as permitted sender)
Received: from mail.central-tech.edu (mail.central-tech.edu [198.51.100.45])
	by mx.central-tech.edu (Postfix) with ESMTPS id 3A8C7F10
	for <faculty-all@central-tech.edu>; Thu, 10 Sep 2026 03:45:00 +0000 (UTC)
Content-Type: text/plain; charset="utf-8"

Dear Faculty Colleagues,

This is an urgent reminder regarding the accreditation documentation.
Action is required immediately by 5:00 PM today to finalize your departmental dossiers.

Please review your department submission portal:
https://portal.central-tech.edu/faculty/dossier

Failure to complete this ahead of today's deadline will delay our institutional filing.
If you experience any portal synchronization errors, please contact the academic dean's office.

Sincerely,
Dr. Marcus Vance
Dean of Academic Affairs
Central Institute of Technology

```


### 📄 File: `sample_emails/forged_relay_attack.eml`
```email
From: "Internal Security Alert" <support@microsoft-security-alert.xyz>
To: admin@sircrrcoestd.in
Subject: Critical security incident: Immediate password reset required
Date: Mon, 07 Sep 2026 05:00:00 +0000
Message-ID: <992144.forged.relay@microsoft-security-alert.xyz>
Return-Path: <bounce@microsoft-security-alert.xyz>
Authentication-Results: mx.sircrrcoestd.in;
 dkim=none;
 spf=fail (mx.sircrrcoestd.in: 198.98.56.12 is not permitted);
 dmarc=fail (p=reject) header.from=microsoft-security-alert.xyz
Received: from mail.trusted-university-relay.edu (mail.trusted-university-relay.edu [104.244.42.1])
	by intermediary.spoofed-node.com (Postfix) with ESMTPS id A11849102
	for <admin@sircrrcoestd.in>; Mon, 07 Sep 2026 05:00:00 +0000 (UTC)
Received: from fake-hop.forged-mta.com (fake-hop.forged-mta.com [198.98.56.12])
	by trusted-mta.cdn-edge.net (Postfix) with ESMTPS id B8891023
	for <admin@sircrrcoestd.in>; Mon, 07 Sep 2026 04:30:00 +0000 (UTC)
Received: from trusted-mta.cdn-edge.net (trusted-mta.cdn-edge.net [142.250.190.46])
	by mx.sircrrcoestd.in (Postfix) with ESMTP id 99201AA3
	for <admin@sircrrcoestd.in>; Mon, 07 Sep 2026 05:02:15 +0000 (UTC)
Content-Type: text/plain; charset="utf-8"

SECURITY ADVISORY:

Unauthorized login attempts from an unverified IP in Moscow, Russia were detected on your organizational account.
Your account credentials expired and have been placed on temporary hold.

Action required: Verify your account immediately by following the secure portal below:
https://login-verify-account.xyz/auth/reset

Failure to respond within 2 hours will lead to complete suspension of mailbox privileges.

Microsoft Security Operations Team

```
