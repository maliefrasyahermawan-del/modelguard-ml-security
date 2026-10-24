import sys
import uuid
import shutil
from pathlib import Path

# Ensure project root is on path when run via uvicorn
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, File, UploadFile, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="ModelGuard", version="1.0")

UPLOADS_DIR = _ROOT / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

app.mount(
    "/static",
    StaticFiles(directory=str(_ROOT / "web" / "static")),
    name="static",
)
templates = Jinja2Templates(directory=str(_ROOT / "web" / "templates"))

ALLOWED_EXT = {".pkl", ".pt", ".h5", ".safetensors", ".joblib", ".npy"}


@app.on_event("startup")
async def startup():
    from src.database import init_db
    init_db()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    from src.database import get_recent_scans
    scans = get_recent_scans(10)
    return templates.TemplateResponse(
        "index.html", {"request": request, "scans": scans}
    )


@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXT))}")

    dest = UPLOADS_DIR / f"{uuid.uuid4()}{ext}"
    try:
        with open(dest, "wb") as f:
            shutil.copyfileobj(file.file, f)
    finally:
        await file.close()

    try:
        from src.scanner import ModelScanner
        from src.database import save_scan
        result = ModelScanner().scan(str(dest))
        scan_id = save_scan(result)
        return JSONResponse({
            "scan_id": scan_id,
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "findings_count": len(result.findings),
        })
    except Exception as e:
        dest.unlink(missing_ok=True)
        raise HTTPException(500, str(e))


@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def report_page(request: Request, scan_id: int):
    from src.database import get_scan
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return templates.TemplateResponse(
        "report.html", {"request": request, "scan": scan}
    )


@app.get("/report/{scan_id}/json")
async def report_json(scan_id: int):
    from src.database import get_scan
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return JSONResponse(scan)
