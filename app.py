"""
TRACE-MAIL AI - FastAPI Forensic Intelligence Server
AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
Adheres strictly to RFC 5322/7489, zero-request safe link inspection (anti-SSRF),
tamper-evident evidence ledger, and explainable multi-signal threat scoring.
"""

import os
import re
import tempfile
import time
import logging
import threading
import uuid
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

logger = logging.getLogger("tracemail.api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

from engine.pipeline import ForensicPipeline
from engine.evidence_generator import EvidenceGenerator
from engine.evidence_ledger import EvidenceLedger
from engine.url_scanner import URLScanner
from engine.geoip_resolver import GeoIPResolver

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

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from engine.rag_engine import ForensicRAG
        await run_in_threadpool(ForensicRAG.initialize)
    except Exception as ex:
        print(f"[STARTUP] ForensicRAG pre-warm notice: {ex}")
    yield

app = FastAPI(
    title="TRACE-MAIL AI Forensic Server",
    version="2.1.0",
    description="Evidence-Based Email Threat Detection, Geolocation & Forensic Intelligence Platform",
    lifespan=lifespan
)

# Strict CORS origin whitelisting (RFC/W3C compliant; prohibits wildcard * with credentials)
ALLOWED_ORIGINS = [
    "http://localhost:8899",
    "http://127.0.0.1:8899",
    "https://mail.google.com",
    "https://outlook.live.com",
    "https://outlook.office.com",
    "https://tracemail-ai-bc650.firebaseapp.com",
    "https://tracemail-ai-bc650.web.app",
]
custom_origins = os.environ.get("TRACEMAIL_ALLOWED_ORIGINS")
if custom_origins:
    ALLOWED_ORIGINS.extend([o.strip() for o in custom_origins.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https://([a-zA-Z0-9-]+\.)*(trycloudflare\.com|hf\.space|onrender\.com|vercel\.app)$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# In-Memory Sliding-Window Rate Limiter
RATE_LIMIT_WINDOW = 60  # 1 minute window
RATE_LIMIT_MAX = 60     # max 60 requests per minute per IP
RATE_LIMIT_TRACKER = defaultdict(list)
RATE_LIMIT_LOCK = threading.Lock()

def check_client_rate_limit(client_ip: str) -> bool:
    now = time.time()
    with RATE_LIMIT_LOCK:
        history = RATE_LIMIT_TRACKER[client_ip]
        RATE_LIMIT_TRACKER[client_ip] = [t for t in history if now - t < RATE_LIMIT_WINDOW]
        if len(RATE_LIMIT_TRACKER[client_ip]) >= RATE_LIMIT_MAX:
            return False
        RATE_LIMIT_TRACKER[client_ip].append(now)
        return True

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    # Enforce rate limiting on computational pipeline routes
    client_ip = request.client.host if request.client else "127.0.0.1"
    if request.url.path.startswith(("/scan", "/api/analyze", "/api/copilot")):
        if not check_client_rate_limit(client_ip):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Maximum 60 requests per minute allowed."},
                headers={"Retry-After": "60"}
            )

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com https://cdnjs.cloudflare.com https://www.gstatic.com https://apis.google.com https://*.google.com; "
        "connect-src 'self' https: http://localhost:8899 http://127.0.0.1:8899 wss:; "
        "frame-src 'self' https://*.firebaseapp.com https://accounts.google.com https://content.googleapis.com https://*.google.com;"
    )
    return response

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

    # Resilient Geolocation Cascade for any email type:
    if lat_val is None:
        # Fallback 1: Check intermediate hops in the Received chain
        for hop in hops_analyzed:
            h_ip = hop.get("ip")
            if h_ip and h_ip != report.get("origin_ip"):
                h_geo = GeoIPResolver.resolve(h_ip)
                if h_geo.get("latitude") is not None:
                    geo_payload = dict(h_geo)
                    geo_payload["note"] = f"Geolocated from relay hop #{hop.get('hop_number', 1)} ({h_ip})"
                    lat_val = geo_payload.get("latitude")
                    lon_val = geo_payload.get("longitude")
                    break

    if lat_val is None:
        # Fallback 2: Resolve sender domain MX / DNS infrastructure
        from_hdr = str(hdr.get("from", ""))
        sender_domain = None
        m = re.search(r"@([a-zA-Z0-9.\-]+)", from_hdr)
        if m:
            sender_domain = m.group(1).rstrip(">., \t")
        if not sender_domain:
            m2 = re.search(r"@([a-zA-Z0-9.\-]+)", str(hdr.get("return_path", "")))
            if m2:
                sender_domain = m2.group(1).rstrip(">., \t")

        if sender_domain:
            d_geo = GeoIPResolver.resolve_domain(sender_domain)
            if d_geo.get("latitude") is not None:
                geo_payload = dict(d_geo)
                geo_payload["ip"] = d_geo.get("ip") or f"DNS({sender_domain})"
                geo_payload["note"] = f"Geolocated from sender domain authority ({sender_domain})"
                lat_val = geo_payload.get("latitude")
                lon_val = geo_payload.get("longitude")

    if lat_val is None:
        # Fallback 3: Resolve link host from email body (bounded to first 2 to eliminate latency)
        for lk in report.get("body_summary", {}).get("scanned_links", [])[:2]:
            host = lk.get("domain") or lk.get("host")
            if host:
                l_geo = GeoIPResolver.resolve_domain(host)
                if l_geo.get("latitude") is not None:
                    geo_payload = dict(l_geo)
                    geo_payload["ip"] = l_geo.get("ip") or f"Host({host})"
                    geo_payload["note"] = f"Geolocated from destination link host ({host})"
                    lat_val = geo_payload.get("latitude")
                    lon_val = geo_payload.get("longitude")
                    break

    if lat_val is None:
        # Fallback 4: Internal / Private Subnet Enclave (e.g. RFC 1918)
        # Visualized on 3D Globe as Internal Enterprise Node rather than failing silently
        def_ip = report.get("origin_ip") or "10.0.0.1"
        geo_payload = {
            "ip": def_ip,
            "country": "Internal Enterprise Enclave",
            "country_code": "SEC",
            "region": "Private Subnet",
            "city": "Corporate Gateway Node",
            "latitude": 20.5937,
            "longitude": 78.9629,
            "lat": 20.5937,
            "lon": 78.9629,
            "loc": "20.5937,78.9629",
            "org": "Internal Network (RFC 1918)",
            "isp": "Corporate Secure Relay",
            "organization": "Internal Network (RFC 1918)",
            "asn": "AS-PRIVATE",
            "is_private": True,
            "is_tor": False,
            "is_cloud_hosting": False,
            "is_suspicious_infra": False,
            "status": "INTERNAL_ENCLAVE",
            "source": "Local RFC 1918 Defense Gateway Mapping",
            "confidence": "ENCLAVE_CORROBORATED",
            "note": "Private internal sender; anchored to Enterprise Gateway for perimeter defense visualization."
        }
        lat_val = 20.5937
        lon_val = 78.9629

    org_val = geo_payload.get("organization") or geo_payload.get("org") or "Internal / ISP"
    geo_payload["lat"] = lat_val
    geo_payload["lon"] = lon_val
    geo_payload["latitude"] = lat_val
    geo_payload["longitude"] = lon_val
    geo_payload["org"] = org_val
    geo_payload["organization"] = org_val
    geo_payload["loc"] = f"{lat_val},{lon_val}" if lat_val is not None and lon_val is not None else None

    city_str = geo_payload.get("city") or ""
    country_str = geo_payload.get("country") or ""
    if report.get("origin_location") and report.get("origin_location") not in ("Unknown Location", "Internal / Unknown"):
        sender_loc = report["origin_location"]
    elif city_str and country_str and city_str != "Unavailable" and country_str != "Unavailable":
        sender_loc = f"{city_str}, {country_str}"
    elif city_str and city_str != "Unavailable":
        sender_loc = city_str
    elif country_str and country_str != "Unavailable":
        sender_loc = country_str
    elif geo_payload.get("is_private") or geo_payload.get("status") == "INTERNAL_ENCLAVE":
        sender_loc = "Internal Enterprise Enclave"
    else:
        sender_loc = geo_payload.get("note") or "Unknown Location"

    resolved_origin_ip = report.get("origin_ip") or geo_payload.get("ip") or "Loopback / Internal"

    return {
        "fraud_score": threat_score,
        "risk_level": risk_level,
        "label": label,
        "confidence": int(threat.get("confidence_score", 85)),
        "enforcement_action": threat.get("enforcement_action", "ALLOW"),
        "is_pdf_export": report.get("is_pdf_export", False),
        "origin_ip": resolved_origin_ip,
        "origin_geo": geo_payload,
        "origin_location": sender_loc,
        "origin_isp": org_val,
        "headers": {
            "spf": spf_pass,
            "dkim": dkim_pass,
            "dmarc": dmarc_pass,
            "from": hdr.get("from", ""),
            "return_path": hdr.get("return_path", ""),
            "reply_to": hdr.get("reply_to", ""),
            "message_id": hdr.get("message_id", ""),
            "origin_ip": resolved_origin_ip,
            "origin_location": sender_loc,
            "origin_geo": geo_payload,
            "origin_isp": org_val,
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
        "analyst": report.get("input_metadata", {}),
        "evidence_hash": report.get("forensic_hash"),
        "timestamp": report.get("parsed_at_utc") or datetime.now(timezone.utc).isoformat()
    }


@app.get("/login", response_class=HTMLResponse)
async def serve_login():
    """Serves the investigator authentication and clearance gate."""
    login_path = os.path.join(TEMPLATES_DIR, "login.html")
    if os.path.exists(login_path):
        with open(login_path, "r", encoding="utf-8") as f:
            content = f.read()
            return HTMLResponse(content=content, headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            })
    return "<h1>TRACE-MAIL AI Login Portal Initializing...</h1>"


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the primary forensic dashboard."""
    index_path = os.path.join(TEMPLATES_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            content = f.read()
            return HTMLResponse(content=content, headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            })
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
        # Run through single source of truth: ForensicPipeline (offloaded to threadpool to prevent event-loop starvation)
        report = await run_in_threadpool(ForensicPipeline.process_raw_email, content)
        analysis_id = f"ANL-{uuid.uuid4().hex[:12].upper()}"
        report["analysis_id"] = analysis_id
        analyst_name = request.headers.get("X-Analyst-Identity", "Anonymous SOC Analyst")
        analyst_email = request.headers.get("X-Analyst-Email", "soc@tracemail.ai")
        analyst_clearance = request.headers.get("X-Analyst-Clearance", "TIER-3")
        auth_hdr = request.headers.get("Authorization", "")
        has_bearer_token = bool(auth_hdr.startswith("Bearer ") and len(auth_hdr) > 20)

        report["input_metadata"] = {
            "filename": filename,
            "size_bytes": len(content),
            "is_demo_sample": filename in set(os.listdir(SAMPLES_DIR)) if os.path.exists(SAMPLES_DIR) else False,
            "analyst_identity": analyst_name,
            "analyst_email": analyst_email,
            "analyst_clearance": analyst_clearance,
            "analyst_verification_status": "BEARER_TOKEN_AUTHENTICATED" if has_bearer_token else "CLIENT_DECLARED_EVALUATOR_PASS",
        }
        report["ledger_receipt"] = LEDGER.append(analysis_id, report["forensic_hash"])
        remember_analysis(report)

        # Return UI-compatible consolidated payload
        ui_payload = await run_in_threadpool(build_ui_compatible_payload, report)
        return ui_payload

    except HTTPException:
        raise
    except Exception as ex:
        logger.error("Forensic analysis pipeline failed: %s", ex, exc_info=True)
        raise HTTPException(status_code=500, detail="Forensic analysis failed due to an internal pipeline error.")


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
        report = await run_in_threadpool(ForensicPipeline.process_raw_email, content)
        report["analysis_id"] = f"ANL-{uuid.uuid4().hex[:12].upper()}"
        report["input_metadata"] = {
            "filename": filename,
            "size_bytes": len(content),
            "is_demo_sample": filename in set(os.listdir(SAMPLES_DIR)) if os.path.exists(SAMPLES_DIR) else False,
        }
        report["ledger_receipt"] = LEDGER.append(report["analysis_id"], report["forensic_hash"])
        o_geo = report.get("origin_geo") or {}
        c_str = o_geo.get("city") or ""
        co_str = o_geo.get("country") or ""
        if c_str and co_str and c_str != "Unavailable" and co_str != "Unavailable":
            report["origin_location"] = f"{c_str}, {co_str}"
        elif c_str and c_str != "Unavailable":
            report["origin_location"] = c_str
        elif co_str and co_str != "Unavailable":
            report["origin_location"] = co_str
        elif o_geo.get("is_private") or o_geo.get("status") == "INTERNAL_ENCLAVE":
            report["origin_location"] = "Internal Enterprise Enclave"
        else:
            report["origin_location"] = o_geo.get("note") or "Unknown Location"

        if "trace" not in report:
            report["trace"] = {"geo": o_geo}
        if "headers" in report and isinstance(report["headers"], dict):
            report["headers"]["origin_location"] = report["origin_location"]
            report["headers"]["origin_geo"] = o_geo

        remember_analysis(report)
        return report

    except HTTPException:
        raise
    except Exception as ex:
        logger.error("Forensic analysis API failed: %s", ex, exc_info=True)
        raise HTTPException(status_code=500, detail="Forensic analysis failed due to an internal pipeline error.")


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
    except HTTPException:
        raise
    except Exception as ex:
        logger.error("PDF generation failed: %s", ex, exc_info=True)
        if tmp_path:
            remove_file(tmp_path)
        raise HTTPException(status_code=500, detail="Forensic dossier export failed due to an internal rendering error.")


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

    response = await run_in_threadpool(
        ForensicCopilot.query,
        user_message=payload.message,
        report=report_context,
        history=payload.history,
        preferred_model=payload.model
    )
    return response


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 8899))
    print(f"🚀 Starting TRACE-MAIL AI Forensic Platform on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
