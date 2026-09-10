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
