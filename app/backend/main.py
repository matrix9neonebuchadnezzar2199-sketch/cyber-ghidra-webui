import hashlib
import json
import os
import shutil
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from annotator import annotate_function, select_target_functions

INPUT_DIR = Path("/app/input")
OUTPUT_DIR = Path("/app/output")
QUEUE_PENDING = Path("/app/queue/pending")
GHIDRA_HOME = Path(os.environ.get("GHIDRA_HOME", "/opt/ghidra"))

ANALYSIS_SUFFIX = "_analysis.json"
ANNOTATED_SUFFIX = "_annotated.json"
# Reject strategy=all when more than this many functions (sync LLM loop; avoid client timeouts)
ANNOTATE_ALL_MAX_FUNCTIONS = int(os.environ.get("ANNOTATE_ALL_MAX_FUNCTIONS", "100"))


class AnnotateBody(BaseModel):
    strategy: str = "suspicious_only"
    top_n: int = Field(default=50, ge=1, le=2000)
    model: str | None = None
    prompt_template: str | None = None


def cors_origins() -> list[str]:
    raw = os.environ.get("CORS_ORIGINS", "").strip()
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return ["http://localhost:3001"]

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


def resolve_analysis_json_path(job_id: str) -> Path:
    st = read_status_file(job_id)
    if not st or st.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Job not completed or not found")
    name = st.get("analysis_json")
    if name:
        p = OUTPUT_DIR / Path(str(name)).name
        if p.is_file():
            return p
    candidates = sorted(
        OUTPUT_DIR.glob(f"*{ANALYSIS_SUFFIX}"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise HTTPException(status_code=404, detail="No analysis JSON in output")

    input_fn = (st.get("filename") or "").strip()
    if input_fn:
        parts = input_fn.split("_", 2)
        needles: list[str] = []
        if len(parts) >= 3:
            tail = parts[2]
            needles.append(Path(tail).stem)
            needles.append(tail)
        needles.append(Path(input_fn).stem)
        needles.append(input_fn)
        ordered: list[str] = []
        seen: set[str] = set()
        for n in needles:
            if n and n not in seen:
                seen.add(n)
                ordered.append(n)
        for c in candidates:
            cn = c.name
            for n in ordered:
                if n in cn:
                    return c

    return candidates[0]


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
    allow_origins=cors_origins(),
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
    if safe.endswith(ANNOTATED_SUFFIX):
        raise HTTPException(
            status_code=404,
            detail=f"Use GET /api/annotate/result/{{id}} for files ending with {ANNOTATED_SUFFIX}",
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


@app.post("/api/annotate/{job_id}")
async def start_annotation(job_id: str, body: AnnotateBody = AnnotateBody()):
    if body.strategy not in ("suspicious_only", "all", "top_n"):
        raise HTTPException(status_code=400, detail="strategy must be suspicious_only, all, or top_n")

    path = resolve_analysis_json_path(job_id)
    analysis = json.loads(path.read_text(encoding="utf-8"))

    targets = select_target_functions(analysis, body.strategy, body.top_n)
    if not targets:
        raise HTTPException(status_code=400, detail="No matching functions to annotate for this strategy")

    if body.strategy == "all" and len(targets) > ANNOTATE_ALL_MAX_FUNCTIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"strategy=all would annotate {len(targets)} functions; maximum is {ANNOTATE_ALL_MAX_FUNCTIONS} "
                f"for synchronous processing (increase ANNOTATE_ALL_MAX_FUNCTIONS if needed, or use "
                f"strategy=top_n / suspicious_only). Large async batches are planned for Phase 2c."
            ),
        )

    model = body.model or os.environ.get("LLM_MODEL", "llama3")
    annotate_id = str(uuid.uuid4())
    annotations: list[dict[str, Any]] = []

    async with httpx.AsyncClient() as client:
        for func in targets:
            try:
                ann = await annotate_function(client, func, model)
                annotations.append(ann)
            except Exception as exc:
                annotations.append(
                    {
                        "function_name": func.get("name", ""),
                        "address": func.get("address", ""),
                        "summary": f"LLM error: {exc}",
                        "risk_level": "unknown",
                        "risk_reasons": [],
                        "ioc_candidates": [],
                        "decompiled_c_hash": "",
                    }
                )

    high = sum(1 for a in annotations if a.get("risk_level") == "high")
    med = sum(1 for a in annotations if a.get("risk_level") == "medium")
    low = sum(1 for a in annotations if a.get("risk_level") == "low")
    ioc_count = sum(len(a.get("ioc_candidates") or []) for a in annotations)

    result: dict[str, Any] = {
        "source_job_id": job_id,
        "annotate_id": annotate_id,
        "model": model,
        "strategy": body.strategy,
        "created": datetime.now().isoformat(),
        "annotations": annotations,
        "summary": {
            "total_annotated": len(annotations),
            "high_risk": high,
            "medium_risk": med,
            "low_risk": low,
            "ioc_count": ioc_count,
        },
    }

    out_name = f"{annotate_id}{ANNOTATED_SUFFIX}"
    out_path = OUTPUT_DIR / out_name
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "status": "completed",
        "job_id": job_id,
        "annotate_id": annotate_id,
        "strategy": body.strategy,
        "target_functions": len(targets),
        "summary": result["summary"],
        "output_file": out_name,
        "message": f"Saved to {out_name}; GET /api/annotate/result/{annotate_id}",
    }


@app.get("/api/annotate/result/{annotate_id}")
async def get_annotation(annotate_id: str):
    safe = Path(annotate_id).name
    if safe != annotate_id or ".." in annotate_id:
        raise HTTPException(status_code=400, detail="Invalid annotate_id")
    path = (OUTPUT_DIR / f"{safe}{ANNOTATED_SUFFIX}").resolve()
    try:
        path.relative_to(OUTPUT_DIR.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid path") from exc
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Annotation not found")
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
