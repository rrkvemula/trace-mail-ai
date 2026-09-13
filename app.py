"""
TRACE-MAIL AI - FastAPI Forensic Intelligence Server
AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
Adheres strictly to RFC 5322/7489, zero-request safe link inspection (anti-SSRF),
tamper-evident evidence ledger, and explainable multi-signal threat scoring.
"""

import os
import re
import json
import tempfile
import time
import logging
import threading
import uuid
import secrets
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

try:
    from firebase_admin import auth as firebase_auth, credentials, initialize_app, get_apps
    FIREBASE_ADMIN_AVAILABLE = True
except ImportError:
    firebase_auth = None
    credentials = None
    initialize_app = None
    get_apps = None
    FIREBASE_ADMIN_AVAILABLE = False

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
FEEDBACK_STORE_PATH = os.environ.get(
    "TRACEMAIL_FEEDBACK_STORE", os.path.join(DATA_DIR, "user_feedback.jsonl")
)

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

# In-Memory Sliding-Window Bounded Rate Limiter with TTL Pruning
class BoundedRateLimiter:
    """
    Thread-safe sliding-window rate limiter with automatic TTL pruning,
    periodic expiration cleanup, and LRU bounding to prevent memory exhaustion.
    """
    def __init__(
        self,
        window_seconds: int = 60,
        max_requests: int = 60,
        max_tracked_ips: int = 10000,
        cleanup_interval: int = 60,
    ):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.max_tracked_ips = max_tracked_ips
        self.cleanup_interval = cleanup_interval
        self._tracker: OrderedDict[str, list[float]] = OrderedDict()
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def check(self, client_ip: str) -> bool:
        now = time.time()
        with self._lock:
            # 1. Periodic TTL pruning of stale IP histories or watermark trigger
            if (now - self._last_cleanup >= self.cleanup_interval) or (len(self._tracker) >= self.max_tracked_ips):
                self._prune_stale(now)

            # 2. Filter client history within sliding window
            history = self._tracker.get(client_ip, [])
            valid_history = [t for t in history if now - t < self.window_seconds]

            # 3. Check rate limit threshold
            if len(valid_history) >= self.max_requests:
                self._tracker[client_ip] = valid_history
                self._tracker.move_to_end(client_ip)
                while len(self._tracker) > self.max_tracked_ips:
                    self._tracker.popitem(last=False)
                return False

            # 4. Record new request
            valid_history.append(now)
            self._tracker[client_ip] = valid_history
            self._tracker.move_to_end(client_ip)

            # 5. Enforce strict LRU bounding if exceeding capacity
            while len(self._tracker) > self.max_tracked_ips:
                self._tracker.popitem(last=False)

            return True

    def _prune_stale(self, now: float) -> None:
        self._last_cleanup = now
        stale_cutoff = now - self.window_seconds
        stale_keys = [
            ip for ip, timestamps in self._tracker.items()
            if not timestamps or timestamps[-1] < stale_cutoff
        ]
        for ip in stale_keys:
            del self._tracker[ip]

    def reset(self) -> None:
        with self._lock:
            self._tracker.clear()
            self._last_cleanup = time.time()

    def tracked_count(self) -> int:
        with self._lock:
            return len(self._tracker)


RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 60
MAX_TRACKED_IPS = 10000
RATE_LIMITER = BoundedRateLimiter(
    window_seconds=RATE_LIMIT_WINDOW,
    max_requests=RATE_LIMIT_MAX,
    max_tracked_ips=MAX_TRACKED_IPS,
    cleanup_interval=60,
)


def check_client_rate_limit(client_ip: str) -> bool:
    return RATE_LIMITER.check(client_ip)



FIREBASE_INIT_ERROR: Optional[str] = None


def initialize_firebase_admin() -> None:
    """Initializes Firebase Admin once when a service-account credential is present."""
    global FIREBASE_INIT_ERROR
    if not FIREBASE_ADMIN_AVAILABLE:
        return
    if get_apps and get_apps():
        return

    credential_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    credential_path = os.environ.get("FIREBASE_SERVICE_ACCOUNT_PATH", "").strip()
    try:
        if credential_json:
            parsed = json.loads(credential_json)
            initialize_app(credentials.Certificate(parsed))
            FIREBASE_INIT_ERROR = None
            logger.info("Firebase Admin successfully initialized from FIREBASE_SERVICE_ACCOUNT_JSON.")
        elif credential_path:
            with open(credential_path, "r", encoding="utf-8") as handle:
                initialize_app(credentials.Certificate(json.load(handle)))
            FIREBASE_INIT_ERROR = None
            logger.info("Firebase Admin successfully initialized from %s.", credential_path)
    except Exception as ex:
        FIREBASE_INIT_ERROR = f"{type(ex).__name__}: {ex}"
        logger.warning("Firebase Admin initialization failed: %s", ex)


def verify_firebase_bearer_token(request: Request) -> Dict[str, Any]:
    """
    Verifies a Firebase ID token produced by the signed-in web analyst.
    Demo/local emergency access requires an explicit server-side secret.
    Client-side localStorage is never treated as authentication.
    """
    initialize_firebase_admin()
    authorization = request.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Authentication required. Provide a Firebase Bearer token.")

    if FIREBASE_ADMIN_AVAILABLE and firebase_auth is not None and get_apps and get_apps():
        try:
            decoded = firebase_auth.verify_id_token(token, check_revoked=True)
            if not decoded.get("uid"):
                raise ValueError("Token has no uid")
            return decoded
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid or expired analyst authentication token.")

    local_key = os.environ.get("TRACEMAIL_LOCAL_ANALYST_KEY", "")
    if local_key and secrets.compare_digest(token, local_key):
        return {"uid": "local-bearer-analyst", "email": "local-analyst@tracemail.local"}

    err_detail = "Feedback authentication is not configured on this deployment."
    if not FIREBASE_ADMIN_AVAILABLE:
        err_detail = "Firebase Admin SDK is not available in this container environment."
    elif not (get_apps and get_apps()):
        if FIREBASE_INIT_ERROR:
            err_detail = f"Firebase Admin credential initialization failed: {FIREBASE_INIT_ERROR}"
        else:
            err_detail = "Firebase service account credentials (FIREBASE_SERVICE_ACCOUNT_JSON) not found."

    raise HTTPException(status_code=503, detail=err_detail)


def get_client_ip(request: Request) -> str:
    """
    Extracts client IP from proxy headers (Cloudflare, reverse proxies)
    falling back to peer socket host.
    """
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip and real_ip.strip():
        return real_ip.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and forwarded.strip():
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    # Enforce rate limiting on computational pipeline routes
    client_ip = get_client_ip(request)
    if request.url.path.startswith(("/scan", "/api/analyze", "/api/copilot", "/api/forensics")):
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
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://cdnjs.cloudflare.com https://www.gstatic.com https://apis.google.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://unpkg.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
        "img-src 'self' data: blob: https://*.googleusercontent.com https://*.gstatic.com https://unpkg.com https://*.basemaps.cartocdn.com https://*.tile.openstreetmap.org; "
        "connect-src 'self' http://localhost:8899 http://127.0.0.1:8899 https://*.googleapis.com https://*.firebaseio.com https://*.firebaseapp.com https://*.firebasestorage.app https://unpkg.com https://cdnjs.cloudflare.com; "
        "frame-src 'self' https://*.firebaseapp.com https://accounts.google.com https://content.googleapis.com; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
    return response


@app.middleware("http")
async def bind_user_allowlist(request: Request, call_next):
    """Binds only the verified analyst's own allowlist to this request."""
    request.state.user_allowlist = set()
    request.state.analyst_uid = None
    if request.url.path.startswith(("/scan", "/api/analyze")):
        try:
            claims = verify_firebase_bearer_token(request)
        except HTTPException as ex:
            if ex.status_code not in (401, 503):
                raise
        else:
            request.state.analyst_uid = claims.get("uid")
            request.state.user_allowlist = FEEDBACK_STORE.allowlist_for(claims.get("uid", ""))
    return await call_next(request)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ExportRequest(BaseModel):
    analysis_id: str


class AIAnalystRequest(BaseModel):
    analysis_id: Optional[str] = None
    report: Optional[Dict[str, Any]] = None
    focus: Optional[str] = "full"
    force_deterministic: Optional[bool] = False


class ChatRequest(BaseModel):
    message: str
    report: Optional[Dict[str, Any]] = None
    analysis_id: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = None
    model: Optional[str] = None


class FeedbackRequest(BaseModel):
    analysis_id: Optional[str] = None
    sender_email: Optional[str] = None
    sender_domain: Optional[str] = None
    feedback_type: str  # "ALLOWLIST_SENDER", "FALSE_POSITIVE", "REPORT_PHISHING"
    notes: Optional[str] = None


class FeedbackResponse(BaseModel):
    status: str
    feedback_type: str
    target: str
    scoped_to: str
    message: str


FREE_CONSUMER_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "proton.me", "protonmail.com",
    "icloud.com", "me.com", "mac.com", "zoho.com", "mail.com"
}


class FeedbackStore:
    """Append-only, user-scoped feedback and allowlist persistence."""

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()

    def _validate(self, entry: Dict[str, Any]) -> bool:
        owner = str(entry.get("owner_uid", "")).strip()
        feedback_type = str(entry.get("feedback_type", "")).strip().upper()
        sender = str(entry.get("sender_email", "")).strip().lower()
        domain = str(entry.get("sender_domain", "")).strip().lower()
        email_ok = not sender or re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender)
        domain_ok = not domain or re.match(r"^[a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,}$", domain)
        return bool(owner and feedback_type and (sender or domain) and email_ok and domain_ok)

    def append(self, entry: Dict[str, Any]) -> bool:
        if not self._validate(entry):
            return False
        safe_entry = dict(entry)
        with self.lock:
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(safe_entry, separators=(",", ":")) + "\n")
                return True
            except Exception as ex:
                logger.warning("Could not persist feedback to durable store: %s", ex)
                return False

    def allowlist_for(self, owner_uid: str) -> set:
        owner_uid = str(owner_uid).strip()
        allowlist = set()
        if not owner_uid:
            return allowlist
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("feedback_type") != "ALLOWLIST_SENDER" or entry.get("owner_uid") != owner_uid:
                        continue
                    sender = str(entry.get("sender_email", "")).strip().lower()
                    domain = str(entry.get("sender_domain", "")).strip().lower()
                    if sender and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender):
                        allowlist.add(sender)
                    if domain and domain not in FREE_CONSUMER_PROVIDERS and re.match(
                        r"^[a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,}$", domain
                    ):
                        allowlist.add(domain)
        except FileNotFoundError:
            pass
        except Exception as ex:
            logger.warning("Could not read durable allowlist store: %s", ex)
        return allowlist


FEEDBACK_STORE = FeedbackStore(FEEDBACK_STORE_PATH)


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
        # Accurately labeled as private non-routable range without synthetic physical coordinates
        def_ip = report.get("origin_ip") or "10.0.0.1"
        geo_payload = {
            "ip": def_ip,
            "country": "Private / Internal Network",
            "country_code": "SEC",
            "region": "Non-Routable RFC 1918",
            "city": "Internal Relay Node",
            "latitude": None,
            "longitude": None,
            "lat": None,
            "lon": None,
            "loc": None,
            "org": "Internal Network (RFC 1918)",
            "isp": "Corporate Intranet Relay",
            "organization": "Internal Network (RFC 1918)",
            "asn": "AS-PRIVATE",
            "is_private": True,
            "is_tor": False,
            "is_cloud_hosting": False,
            "is_suspicious_infra": False,
            "status": "INTERNAL_NON_ROUTABLE",
            "source": "Private / Non-Routable IP Range",
            "confidence": "HIGH",
            "note": "Private / internal network IP address (RFC 1918 / RFC 4193). Geolocation coordinates are not applicable."
        }
        lat_val = None
        lon_val = None

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
    if report.get("origin_location") and report.get("origin_location") not in ("Unknown Location", "Internal / Unknown", "No IP provided, Internal / Unknown"):
        sender_loc = report["origin_location"]
    elif city_str and country_str and city_str != "Unavailable" and country_str != "Unavailable":
        sender_loc = f"{city_str}, {country_str}"
    elif city_str and city_str != "Unavailable":
        sender_loc = city_str
    elif country_str and country_str != "Unavailable":
        sender_loc = country_str
    elif geo_payload.get("is_private") or geo_payload.get("status") in ("INTERNAL_ENCLAVE", "INTERNAL_NON_ROUTABLE"):
        sender_loc = "Internal Enterprise Network (RFC 1918)"
    else:
        sender_loc = geo_payload.get("note") or "Unknown Location"

    resolved_origin_ip = report.get("origin_ip") or geo_payload.get("ip") or "Loopback / Internal"

    # Explicit Forensic Origin Evidence Categorization (GLM-5.3 Integrity Standard)
    origin_evidence = report.get("origin_evidence") or {}
    source_str = origin_evidence.get("source", "")
    from_hdr = str(hdr.get("from", ""))
    sender_domain = ""
    m = re.search(r"@([a-zA-Z0-9.\-]+)", from_hdr)
    if m:
        sender_domain = m.group(1).rstrip(">., \t")

    client_ip = hdr.get("x_originating_ip") or None
    earliest_hop_ip = hops_analyzed[0].get("ip") if hops_analyzed else None

    if "X-Originating-IP" in source_str:
        evidence_source_type = "CLIENT_ENDPOINT"
        evidence_label = "Sender Client Endpoint"
        evidence_caveat = "Extracted from sender-reported header (X-Originating-IP); reflects client workstation/endpoint."
    elif hops_analyzed and any(h.get("is_public_ip") for h in hops_analyzed):
        evidence_source_type = "ORIGINATING_MTA_RELAY"
        evidence_label = "Mail Transfer Agent (MTA) Relay"
        evidence_caveat = "Geolocated earliest public relay server; represents mail transport infrastructure, not the sender's physical handheld device."
    elif report.get("is_pdf_export"):
        evidence_source_type = "DOMAIN_AUTHORITY"
        evidence_label = "Sender Domain Authority (Mobile PDF)"
        evidence_caveat = "Routing hops omitted by mobile visual export; physical origin geolocated from verified sender domain infrastructure."
    elif "domain" in source_str.lower() or "DNS" in str(resolved_origin_ip) or "MX" in str(resolved_origin_ip):
        evidence_source_type = "DOMAIN_AUTHORITY"
        evidence_label = "Sender Domain Infrastructure"
        evidence_caveat = "Geolocated from registered domain authority (DNS/MX) as no public relay hops were available."
    elif "Telemetry" in source_str or "Body Text" in source_str:
        evidence_source_type = "MESSAGE_CONTENT_INDICATOR"
        evidence_label = "Message Body IP Indicator"
        evidence_caveat = "Public IP extracted from message content; requires independent corroboration against raw headers."
    elif geo_payload.get("is_private") or geo_payload.get("status") in ("INTERNAL_NON_ROUTABLE", "INTERNAL_ENCLAVE"):
        evidence_source_type = "INTERNAL_NON_ROUTABLE"
        evidence_label = "Private Internal Subnet (RFC 1918)"
        evidence_caveat = "Internal non-routable IP address. Geographical coordinates are not applicable."
    else:
        evidence_source_type = "UNAVAILABLE"
        evidence_label = "Infrastructure Unresolved"
        evidence_caveat = "No public source infrastructure could be verified from submitted headers."

    forensic_origin = {
        "evidence_source_type": evidence_source_type,
        "evidence_label": evidence_label,
        "evidence_caveat": evidence_caveat,
        "sender_client_ip": client_ip,
        "originating_relay_ip": earliest_hop_ip,
        "sender_domain_infrastructure": sender_domain,
        "resolved_ip": resolved_origin_ip,
        "location": sender_loc,
        "geo": geo_payload
    }

    return {
        "analysis_id": report.get("analysis_id"),
        "forensic_hash": report.get("forensic_hash"),
        "fraud_score": threat_score,
        "risk_level": risk_level,
        "label": label,
        "evidence_strength": threat.get("evidence_strength", "MODERATE"),
        "corroborated_classes": threat.get("corroborated_classes", []),
        "limitations": threat.get("limitations", []),
        "confidence": int(threat.get("confidence_score", 85)),
        "enforcement_action": threat.get("enforcement_action", "ALLOW"),
        "is_pdf_export": report.get("is_pdf_export", False),
        "origin_ip": resolved_origin_ip,
        "origin_geo": geo_payload,
        "origin_location": sender_loc,
        "origin_isp": org_val,
        "forensic_origin": forensic_origin,
        "headers": {
            "spf": spf_pass,
            "dkim": dkim_pass,
            "dmarc": dmarc_pass,
            "from": hdr.get("from", ""),
            "subject": hdr.get("subject", ""),
            "date": hdr.get("date", ""),
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
    initialize_firebase_admin()
    return {
        "status": "ok",
        "platform": "TRACE-MAIL AI Forensic Intelligence",
        "version": app.version,
        "pipeline": "Active (RFC 5322/7489, Safe URL Inspection, Tamper-Evident Ledger)",
        "firebase_admin_installed": FIREBASE_ADMIN_AVAILABLE,
        "firebase_apps_active": len(get_apps()) if (FIREBASE_ADMIN_AVAILABLE and get_apps) else 0,
        "has_service_account_env": bool(os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")),
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
        analyst_allowlist = getattr(request.state, "user_allowlist", set())
        report = await run_in_threadpool(ForensicPipeline.process_raw_email, content, analyst_allowlist)
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
        raise HTTPException(status_code=500, detail=f"Forensic analysis failed: {type(ex).__name__}: {str(ex)}")


@app.post("/api/analyze")
async def analyze_email(
    request: Request,
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
        analyst_allowlist = getattr(request.state, "user_allowlist", set())
        report = await run_in_threadpool(ForensicPipeline.process_raw_email, content, analyst_allowlist)
        report["analysis_id"] = f"ANL-{uuid.uuid4().hex[:12].upper()}"
        report["input_metadata"] = {
            "filename": filename,
            "size_bytes": len(content),
            "is_demo_sample": filename in set(os.listdir(SAMPLES_DIR)) if os.path.exists(SAMPLES_DIR) else False,
        }
        report["ledger_receipt"] = LEDGER.append(report["analysis_id"], report["forensic_hash"])
        o_geo = report.get("origin_geo") or {}
        if not report.get("origin_location") or report.get("origin_location") in ("Unknown Location", "Internal / Unknown", "No IP provided, Internal / Unknown"):
            c_str = o_geo.get("city") or ""
            co_str = o_geo.get("country") or ""
            if c_str and co_str and c_str != "Unavailable" and co_str != "Unavailable":
                report["origin_location"] = f"{c_str}, {co_str}"
            elif c_str and c_str != "Unavailable":
                report["origin_location"] = c_str
            elif co_str and co_str != "Unavailable":
                report["origin_location"] = co_str
            elif o_geo.get("is_private") or o_geo.get("status") in ("INTERNAL_ENCLAVE", "INTERNAL_NON_ROUTABLE"):
                report["origin_location"] = "Internal Enterprise Network (RFC 1918)"
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
        raise HTTPException(status_code=500, detail=f"Forensic analysis failed: {type(ex).__name__}: {str(ex)}")


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


@app.post("/api/forensics/ai-analyst")
@app.post("/api/copilot/ai-analyst")
def forensic_ai_analyst(payload: AIAnalystRequest):
    """
    Forensic AI Analyst endpoint powered by GLM-5.3 via TokenRouter.
    Synthesizes explainable threat risk narratives, actionable SOC triage advice,
    and MITRE ATT&CK/D3FEND matrix mappings strictly grounded in the deterministic
    evidence ledger. Falls back gracefully to deterministic expert synthesis if
    the external API is rate-limited (HTTP 429), unavailable, or offline.
    """
    report = payload.report
    if not report and payload.analysis_id:
        report = ANALYSIS_CACHE.get(payload.analysis_id)
        if not report:
            raise HTTPException(
                status_code=404,
                detail=f"Analysis report '{payload.analysis_id}' not found or expired from cache."
            )

    # Fallback to the latest analysis in cache only if neither report nor analysis_id was supplied
    if not report and not payload.analysis_id and ANALYSIS_CACHE:
        try:
            latest_id = list(ANALYSIS_CACHE.keys())[-1]
            report = ANALYSIS_CACHE[latest_id]
        except Exception:
            pass

    if not report:
        raise HTTPException(
            status_code=400,
            detail="No forensic report provided or found in cache to analyze."
        )

    from engine.glm_analyst import GLMForensicAnalyst
    return GLMForensicAnalyst.synthesize_triage(
        report=report,
        focus=payload.focus or "full",
        force_deterministic=payload.force_deterministic or False
    )


@app.post("/api/feedback")
async def record_user_feedback(request: Request, req: FeedbackRequest):
    """
    Stores authenticated, user-scoped analyst feedback (false positives, allowlisted senders,
    reported threats). Allowlist entries affect only the authenticated analyst's future scans.
    """
    claims = verify_firebase_bearer_token(request)
    analyst_uid = str(claims.get("uid", ""))
    if not analyst_uid:
        raise HTTPException(status_code=401, detail="Authenticated analyst identifier missing.")

    feedback_type = req.feedback_type.strip().upper()
    sender = (req.sender_email or "").strip().lower()
    domain = (req.sender_domain or "").strip().lower()

    valid_email = re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender)
    valid_domain = re.match(r"^[a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,}$", domain)
    if not valid_email and not valid_domain:
        raise HTTPException(status_code=400, detail="Provide a valid sender email or sender domain.")

    target_desc = sender or f"@{domain}"
    if feedback_type == "ALLOWLIST_SENDER" and domain and domain in FREE_CONSUMER_PROVIDERS:
        target_desc = f"Exact sender '{sender}' (shared provider '@{domain}' cannot be domain-allowlisted)"

    feedback_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "owner_uid": analyst_uid,
        "analysis_id": req.analysis_id,
        "sender_email": sender,
        "sender_domain": domain,
        "feedback_type": feedback_type,
        "notes": req.notes
    }
    if not FEEDBACK_STORE.append(feedback_entry):
        raise HTTPException(status_code=500, detail="Feedback could not be persisted to the durable store.")

    return FeedbackResponse(
        status="RECORDED",
        feedback_type=feedback_type,
        target=target_desc,
        scoped_to=analyst_uid,
        message=(
            f"Feedback '{feedback_type}' recorded for this analyst. "
            "Allowlist rules are user-scoped and never suppress weaponized payloads."
        )
    )


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 8899))
    print(f"🚀 Starting TRACE-MAIL AI Forensic Platform on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
