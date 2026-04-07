import hashlib
import json
import os
import shutil
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

INPUT_DIR = Path("/app/input")
OUTPUT_DIR = Path("/app/output")
QUEUE_PENDING = Path("/app/queue/pending")
SCRIPT_DIR = Path("/ghidra-scripts")
GHIDRA_HOME = Path(os.environ.get("GHIDRA_HOME", "/opt/ghidra"))

ANALYSIS_SUFFIX = "_analysis.json"

jobs: dict[str, dict[str, Any]] = {}


def compute_hashes(filepath: Path) -> dict[str, Any]:
    data = filepath.read_bytes()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def analyze_headless_exists() -> bool:
    return (GHIDRA_HOME / "support" / "analyzeHeadless").is_file()


def status_path(job_id: str) -> Path:
    return OUTPUT_DIR / f"{job_id}.status.json"


def write_status_atomic(job_id: str, data: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = status_path(job_id)
    tmp = OUTPUT_DIR / f"{job_id}.status.json.tmp"
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def read_status_file(job_id: str) -> dict[str, Any] | None:
    path = status_path(job_id)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def load_jobs_from_disk() -> None:
    for f in OUTPUT_DIR.glob("*.status.json"):
        jid = f.name[: -len(".status.json")]
        if not jid:
            continue
        data = read_status_file(jid)
        if data is not None:
            jobs[jid] = data


def write_job_queue_atomic(job_id: str, payload: dict[str, Any]) -> None:
    QUEUE_PENDING.mkdir(parents=True, exist_ok=True)
    path = QUEUE_PENDING / f"{job_id}.json"
    tmp = QUEUE_PENDING / f"{job_id}.json.tmp"
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    QUEUE_PENDING.mkdir(parents=True, exist_ok=True)
    load_jobs_from_disk()
    yield


app = FastAPI(title="Cyber Ghidra API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"status": "online", "message": "Cyber Ghidra Backend System Active"}


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "ghidra_cli": analyze_headless_exists(),
        "ghidra_home": str(GHIDRA_HOME),
        "queue_pending": QUEUE_PENDING.is_dir(),
    }


@app.post("/api/upload")
async def upload_binary(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = f"{timestamp}_{Path(file.filename).name}"
    filepath = INPUT_DIR / safe_name

    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    hashes = compute_hashes(filepath)
    project_name = f"p_{hashes['sha256'][:16]}"
    job_id = str(uuid.uuid4())
    created = datetime.now().isoformat()

    record: dict[str, Any] = {
        "job_id": job_id,
        "status": "queued",
        "filename": safe_name,
        "sha256": hashes["sha256"],
        "created": created,
        "updated": created,
    }
    jobs[job_id] = record
    write_status_atomic(job_id, record)

    job_payload = {
        "job_id": job_id,
        "filepath": str(filepath),
        "project_name": project_name,
        "filename": safe_name,
        "sha256": hashes["sha256"],
        "created": created,
    }
    try:
        write_job_queue_atomic(job_id, job_payload)
    except OSError as exc:
        record["status"] = "failed"
        record["error"] = f"queue write failed: {exc}"
        record["updated"] = datetime.now().isoformat()
        jobs[job_id] = record
        write_status_atomic(job_id, record)
        raise HTTPException(status_code=503, detail="Could not enqueue analysis job") from exc

    return {
        "status": "accepted",
        "job_id": job_id,
        "filename": safe_name,
        "hashes": hashes,
        "message": "Job queued for ghidra-worker",
    }


@app.get("/api/jobs")
async def list_jobs():
    load_jobs_from_disk()
    rows = []
    for f in sorted(OUTPUT_DIR.glob("*.status.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        jid = f.name[: -len(".status.json")]
        data = read_status_file(jid)
        if data is not None:
            rows.append(data)
    return {"jobs": rows}


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    data = read_status_file(job_id)
    if data is None:
        data = jobs.get(job_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Job not found")
    jobs[job_id] = data
    return data


@app.get("/api/results")
async def list_results():
    results = []
    for f in sorted(OUTPUT_DIR.glob(f"*{ANALYSIS_SUFFIX}"), key=lambda p: p.stat().st_mtime, reverse=True):
        st = f.stat()
        results.append(
            {
                "filename": f.name,
                "size": st.st_size,
                "created": datetime.fromtimestamp(st.st_ctime).isoformat(),
            }
        )
    return {"results": results}


@app.get("/api/results/{filename}")
async def get_result(filename: str):
    safe = Path(filename).name
    if safe != filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    if safe.endswith(".status.json"):
        raise HTTPException(
            status_code=404,
            detail="Not a result artifact; use GET /api/jobs/{job_id} for job status",
        )
    filepath = (OUTPUT_DIR / safe).resolve()
    try:
        filepath.relative_to(OUTPUT_DIR.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid path") from exc
    if not filepath.is_file():
        raise HTTPException(status_code=404, detail="Result not found")
    with open(filepath, encoding="utf-8") as fh:
        return json.load(fh)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
