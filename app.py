"""
TRACE-MAIL AI - FastAPI Server
AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
PS ID: SIH26106 (AICTE)
"""

import os
import tempfile
import uuid
from collections import OrderedDict
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.background import BackgroundTask
from engine.pipeline import ForensicPipeline
from engine.evidence_generator import EvidenceGenerator
from engine.evidence_ledger import EvidenceLedger

app = FastAPI(title="TRACE-MAIL AI Forensic Server", version="1.1.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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


class ExportRequest(BaseModel):
    analysis_id: str


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

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>TRACE-MAIL AI Dashboard Loading...</h1>"

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


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": app.version, "cached_analyses": len(ANALYSIS_CACHE)}

@app.post("/api/analyze")
async def analyze_email(
    file: UploadFile = File(None),
    raw_text: str = Form(None),
    source_name: str = Form(None),
):
    """Analyzes uploaded .eml file or raw email text."""
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
            "is_demo_sample": filename in set(os.listdir(SAMPLES_DIR)),
        }
        report["ledger_receipt"] = LEDGER.append(report["analysis_id"], report["forensic_hash"])
        remember_analysis(report)
        return report
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Forensic analysis failed: {str(ex)}")

@app.post("/api/export-pdf")
async def export_forensic_pdf(payload: ExportRequest):
    """Generates a report only from a server-cached analysis result."""
    report = ANALYSIS_CACHE.get(payload.analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Analysis expired or was not found; run it again")
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

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting TRACE-MAIL AI Forensic Platform on http://127.0.0.1:8899")
    uvicorn.run(app, host="127.0.0.1", port=8899)
