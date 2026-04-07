import hashlib
import json
import os
import shutil
import subprocess
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

INPUT_DIR = Path("/app/input")
OUTPUT_DIR = Path("/app/output")
SCRIPT_DIR = Path("/ghidra-scripts")
GHIDRA_HOME = Path(os.environ.get("GHIDRA_HOME", "/opt/ghidra"))
PROJECT_ROOT = Path("/tmp/ghidra_projects")

ANALYSIS_SUFFIX = "_analysis.json"
GHIDRA_TIMEOUT_SEC = int(os.environ.get("GHIDRA_TIMEOUT_SEC", "600"))

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


def run_headless_analysis(filepath: Path, project_name: str, job_id: str) -> None:
    job = jobs.get(job_id)
    if job is not None:
        job["status"] = "running"
    analyze = GHIDRA_HOME / "support" / "analyzeHeadless"
    cmd = [
        str(analyze),
        str(PROJECT_ROOT),
        project_name,
        "-import",
        str(filepath),
        "-postScript",
        "auto_analyze.py",
        "-scriptPath",
        str(SCRIPT_DIR),
        "-deleteProject",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=GHIDRA_TIMEOUT_SEC,
        )
        if job is not None:
            job["returncode"] = result.returncode
            out = result.stdout or ""
            err = result.stderr or ""
            job["stdout_tail"] = out[-8000:]
            job["stderr_tail"] = err[-8000:]
            if result.returncode != 0:
                job["status"] = "failed"
                job["error"] = "analyzeHeadless exited with a non-zero status"
            else:
                job["status"] = "completed"
    except subprocess.TimeoutExpired:
        if job is not None:
            job["status"] = "failed"
            job["error"] = f"analyzeHeadless exceeded {GHIDRA_TIMEOUT_SEC}s"
    except Exception as exc:
        if job is not None:
            job["status"] = "failed"
            job["error"] = str(exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PROJECT_ROOT.mkdir(parents=True, exist_ok=True)
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
        "ghidra": analyze_headless_exists(),
        "ghidra_home": str(GHIDRA_HOME),
    }


@app.post("/api/upload")
async def upload_binary(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    if not analyze_headless_exists():
        raise HTTPException(
            status_code=503,
            detail="Ghidra analyzeHeadless is not available in this container",
        )
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
    jobs[job_id] = {
        "status": "queued",
        "filename": safe_name,
        "sha256": hashes["sha256"],
        "created": datetime.now().isoformat(),
    }
    background_tasks.add_task(run_headless_analysis, filepath, project_name, job_id)

    return {
        "status": "accepted",
        "job_id": job_id,
        "filename": safe_name,
        "hashes": hashes,
        "message": "Analysis started in background",
    }


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


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
