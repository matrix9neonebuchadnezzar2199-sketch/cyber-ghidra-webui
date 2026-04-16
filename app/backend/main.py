import asyncio
import hashlib
import json
import os
import shutil
import tempfile as _tempfile
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import py7zr
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
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
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_SIZE_MB", "200")) * 1024 * 1024
MAX_EXTRACT_SIZE_MB = int(os.environ.get("MAX_EXTRACT_SIZE_MB", "500"))
MAX_EXTRACT_BYTES = MAX_EXTRACT_SIZE_MB * 1024 * 1024
DEFAULT_ARCHIVE_PASSWORD = "infected"
EXTRACT_TMPDIR = Path("/tmp/extract")


class AnnotateBody(BaseModel):
    strategy: str = "suspicious_only"
    top_n: int = Field(default=50, ge=1, le=2000)
    model: str | None = None
    prompt_template: str | None = None


def cors_origins() -> list[str]:
    raw = os.environ.get("CORS_ORIGINS", "").strip()
    if raw:
        origins = [o.strip() for o in raw.split(",") if o.strip()]
    else:
        origins = ["http://localhost:3001"]
    # localhost と 127.0.0.1 の両方を自動的にカバーする
    expanded: list[str] = []
    for o in origins:
        expanded.append(o)
        if "://localhost:" in o:
            expanded.append(o.replace("://localhost:", "://127.0.0.1:"))
        elif "://127.0.0.1:" in o:
            expanded.append(o.replace("://127.0.0.1:", "://localhost:"))
    # 重複除去して返す
    seen: set[str] = set()
    result: list[str] = []
    for o in expanded:
        if o not in seen:
            seen.add(o)
            result.append(o)
    return result

jobs: dict[str, dict[str, Any]] = {}
_jobs_loaded_mtimes: dict[str, float] = {}
_annotate_tasks: dict[str, asyncio.Task] = {}


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
    """status.json を差分スキャンして jobs 辞書を更新する（mtime 比較）"""
    for f in OUTPUT_DIR.glob("*.status.json"):
        jid = f.name[: -len(".status.json")]
        if not jid:
            continue
        try:
            mt = f.stat().st_mtime
        except OSError:
            continue
        if jid in _jobs_loaded_mtimes and _jobs_loaded_mtimes[jid] >= mt:
            continue
        data = read_status_file(jid)
        if data is not None:
            jobs[jid] = data
            _jobs_loaded_mtimes[jid] = mt


def resolve_analysis_json_path(job_id: str) -> Path:
    st = read_status_file(job_id)
    if not st or st.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Job not completed or not found")
    name = st.get("analysis_json")
    if not name:
        raise HTTPException(
            status_code=404,
            detail="analysis_json not recorded for this job. Re-run analysis.",
        )
    p = OUTPUT_DIR / Path(str(name)).name
    if not p.is_file():
        raise HTTPException(
            status_code=404,
            detail="Analysis JSON file not found on disk: %s" % Path(str(name)).name,
        )
    return p


def write_job_queue_atomic(job_id: str, payload: dict[str, Any]) -> None:
    QUEUE_PENDING.mkdir(parents=True, exist_ok=True)
    path = QUEUE_PENDING / f"{job_id}.json"
    tmp = QUEUE_PENDING / f"{job_id}.json.tmp"
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _is_archive(filepath: Path) -> str | None:
    """アーカイブ種別を返す。非アーカイブなら None。7z はヘッダマジックで判定（パスワード不要）。"""
    try:
        if zipfile.is_zipfile(str(filepath)):
            return "zip"
    except Exception:
        pass
    try:
        with open(str(filepath), "rb") as fh:
            header = fh.read(6)
        if header == b"7z\xbc\xaf\x27\x1c":
            return "7z"
    except Exception:
        pass
    return None


def _safe_extract_name(name: str) -> str:
    """パストラバーサル対策。ファイル名部分のみ返す。"""
    return Path(name).name


def _extract_archive(
    filepath: Path,
    password: str,
    extract_dir: Path,
    archive_type: str,
) -> list[Path]:
    """
    アーカイブを展開し、展開されたファイルのパスリストを返す。
    ZIP爆弾対策: 展開合計が MAX_EXTRACT_BYTES を超えたら中断。
    ディレクトリ・隠しファイル・空ファイルはスキップ。
    """
    extracted: list[Path] = []
    total_size = 0

    if archive_type == "zip":
        with zipfile.ZipFile(str(filepath), "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                safe_name = _safe_extract_name(info.filename)
                if not safe_name or safe_name.startswith("."):
                    continue
                if info.file_size == 0:
                    continue
                total_size += info.file_size
                if total_size > MAX_EXTRACT_BYTES:
                    raise ValueError(
                        "Archive exceeds max extract size (%d MB)" % MAX_EXTRACT_SIZE_MB
                    )
                pwd_bytes = password.encode("utf-8") if password else None
                data = zf.read(info.filename, pwd=pwd_bytes)
                out_path = extract_dir / safe_name
                counter = 1
                while out_path.exists():
                    stem = Path(safe_name).stem
                    suffix = Path(safe_name).suffix
                    out_path = extract_dir / ("%s_%d%s" % (stem, counter, suffix))
                    counter += 1
                out_path.write_bytes(data)
                extracted.append(out_path)

    elif archive_type == "7z":
        tmp_extract = extract_dir / "_7z_tmp"
        with py7zr.SevenZipFile(str(filepath), mode="r", password=password or None) as sz:
            for entry in sz.list():
                if entry.is_directory:
                    continue
                uc = int(entry.uncompressed or 0)
                total_size += uc
                if total_size > MAX_EXTRACT_BYTES:
                    raise ValueError(
                        "Archive exceeds max extract size (%d MB)" % MAX_EXTRACT_SIZE_MB
                    )
            tmp_extract.mkdir(exist_ok=True)
            sz.extractall(path=str(tmp_extract))
        try:
            for f in tmp_extract.rglob("*"):
                if f.is_dir():
                    continue
                safe_name = _safe_extract_name(f.name)
                if not safe_name or safe_name.startswith("."):
                    continue
                if f.stat().st_size == 0:
                    continue
                out_path = extract_dir / safe_name
                counter = 1
                while out_path.exists():
                    stem = Path(safe_name).stem
                    suffix = Path(safe_name).suffix
                    out_path = extract_dir / ("%s_%d%s" % (stem, counter, suffix))
                    counter += 1
                shutil.move(str(f), str(out_path))
                extracted.append(out_path)
        finally:
            shutil.rmtree(str(tmp_extract), ignore_errors=True)

    return extracted


def _enqueue_binary_from_path(src: Path) -> dict[str, Any]:
    """
    単一バイナリからジョブを作成しキューに登録する。
    upload_binary の非アーカイブ経路と同一のペイロード・ステータス更新。
    """
    hashes = compute_hashes(src)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = f"{timestamp}_{src.name}"
    dest = INPUT_DIR / safe_name
    counter = 1
    while dest.exists():
        dest = INPUT_DIR / ("%s_%d%s" % (Path(safe_name).stem, counter, Path(safe_name).suffix))
        counter += 1
    # tmpfs → input はクロスデバイスのため shutil.move（rename 不可の場合がある）
    shutil.move(str(src), str(dest))

    project_name = f"p_{hashes['sha256'][:16]}"
    job_id = str(uuid.uuid4())
    created = datetime.now().isoformat()

    record: dict[str, Any] = {
        "job_id": job_id,
        "status": "queued",
        "filename": dest.name,
        "sha256": hashes["sha256"],
        "created": created,
        "updated": created,
    }
    jobs[job_id] = record
    write_status_atomic(job_id, record)

    job_payload = {
        "job_id": job_id,
        "filepath": str(dest),
        "project_name": project_name,
        "filename": dest.name,
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
        "job_id": job_id,
        "filename": dest.name,
        "sha256": hashes["sha256"],
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    QUEUE_PENDING.mkdir(parents=True, exist_ok=True)
    EXTRACT_TMPDIR.mkdir(parents=True, exist_ok=True)
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
async def upload_binary(
    file: UploadFile = File(...),
    archive_password: str = Form(default=DEFAULT_ARCHIVE_PASSWORD),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = f"{timestamp}_{Path(file.filename).name}"
    filepath = INPUT_DIR / safe_name

    total = 0
    try:
        with open(filepath, "wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    buffer.close()
                    filepath.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail="File too large. Maximum size: %d MB"
                        % (MAX_UPLOAD_BYTES // (1024 * 1024)),
                    )
                buffer.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        filepath.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Upload failed: %s" % exc) from exc

    archive_type = _is_archive(filepath)
    if archive_type is not None:
        extract_dir = Path(_tempfile.mkdtemp(dir=str(EXTRACT_TMPDIR)))
        try:
            files = _extract_archive(filepath, archive_password, extract_dir, archive_type)
            if not files:
                raise HTTPException(status_code=400, detail="No files found in archive")

            jobs_out: list[dict[str, Any]] = []
            for f in files:
                jobs_out.append(_enqueue_binary_from_path(f))

            return {
                "archive": True,
                "archive_type": archive_type,
                "jobs": [
                    {
                        "job_id": j["job_id"],
                        "filename": j["filename"],
                        "sha256": j["sha256"],
                    }
                    for j in jobs_out
                ],
                "count": len(jobs_out),
            }
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail="Archive extraction failed: %s" % str(exc),
            ) from exc
        finally:
            filepath.unlink(missing_ok=True)
            shutil.rmtree(str(extract_dir), ignore_errors=True)

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
    rows = sorted(
        jobs.values(),
        key=lambda d: d.get("updated", d.get("created", "")),
        reverse=True,
    )
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
    if not filename or Path(filename).name != filename:
        raise HTTPException(status_code=400, detail="invalid filename")
    safe = Path(filename).name
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


@app.get("/api/results/{filename}/decompiled")
async def download_decompiled(filename: str):
    """全デコンパイル済み関数を結合した .c テキストを返す"""
    if not filename or Path(filename).name != filename:
        raise HTTPException(status_code=400, detail="invalid filename")
    safe = Path(filename).name

    filepath = (OUTPUT_DIR / safe).resolve()
    try:
        filepath.relative_to(OUTPUT_DIR.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid path") from exc
    if not filepath.is_file():
        raise HTTPException(status_code=404, detail="Result not found")

    analysis = json.loads(filepath.read_text(encoding="utf-8"))
    functions = analysis.get("functions") or []

    lines: list[str] = []
    lines.append("// File: %s" % analysis.get("file_name", "unknown"))
    lines.append("// Architecture: %s" % analysis.get("architecture", "unknown"))
    lines.append("// Compiler: %s" % analysis.get("compiler", "unknown"))

    decompiled_count = sum(1 for f in functions if f.get("decompiled_c"))
    lines.append("// Decompiled functions: %d / %d" % (decompiled_count, len(functions)))

    if analysis.get("truncated"):
        lines.append(
            "// WARNING: truncated=true (MAX_FUNCTIONS limit reached)"
            " — not all functions are included"
        )
    lines.append("")

    count = 0
    for f in functions:
        code = f.get("decompiled_c")
        if not code:
            continue
        count += 1
        lines.append(
            "// === [%d] %s @ %s (%s bytes) ==="
            % (count, f.get("name", "?"), f.get("address", "?"), f.get("size", 0))
        )
        lines.append(code)
        lines.append("")

    if count == 0:
        raise HTTPException(
            status_code=404,
            detail="No decompiled functions in this analysis",
        )

    stem = Path(analysis.get("file_name", "output")).stem
    out_filename = "%s_all_decompiled.c" % stem
    content = "\n".join(lines)

    return PlainTextResponse(
        content=content,
        media_type="text/x-csrc; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="%s"' % out_filename,
        },
    )


def _write_annotate_status(annotate_id: str, data: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / ("%s.annotate_status.json" % annotate_id)
    tmp_fd, tmp_path = _tempfile.mkstemp(dir=str(OUTPUT_DIR), suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, str(path))
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _read_annotate_status(annotate_id: str) -> dict[str, Any] | None:
    path = OUTPUT_DIR / ("%s.annotate_status.json" % annotate_id)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


@app.post("/api/annotate/{job_id}", status_code=202)
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
                "strategy=all would annotate %d functions; maximum is %d. "
                "Use strategy=top_n / suspicious_only, or increase ANNOTATE_ALL_MAX_FUNCTIONS."
            ) % (len(targets), ANNOTATE_ALL_MAX_FUNCTIONS),
        )

    model = body.model or os.environ.get("LLM_MODEL", "llama3")
    annotate_id = str(uuid.uuid4())

    # 進捗追跡用のステータスファイルを先に作成
    status_data: dict[str, Any] = {
        "annotate_id": annotate_id,
        "source_job_id": job_id,
        "status": "running",
        "model": model,
        "strategy": body.strategy,
        "total_functions": len(targets),
        "completed_functions": 0,
        "created": datetime.now().isoformat(),
        "updated": datetime.now().isoformat(),
    }
    _write_annotate_status(annotate_id, status_data)

    async def _run_annotation() -> None:
        try:
            annotations: list[dict[str, Any]] = []
            try:
                async with httpx.AsyncClient() as client:
                    for i, func in enumerate(targets):
                        try:
                            ann = await annotate_function(client, func, model)
                            annotations.append(ann)
                        except Exception as exc:
                            annotations.append(
                                {
                                    "function_name": func.get("name", ""),
                                    "address": func.get("address", ""),
                                    "summary": "LLM error: %s" % exc,
                                    "risk_level": "unknown",
                                    "risk_reasons": [],
                                    "ioc_candidates": [],
                                    "decompiled_c_hash": "",
                                }
                            )
                        # 進捗更新（5関数ごと、または最後）
                        if (i + 1) % 5 == 0 or i + 1 == len(targets):
                            status_data["completed_functions"] = i + 1
                            status_data["updated"] = datetime.now().isoformat()
                            _write_annotate_status(annotate_id, status_data)
            except Exception as exc:
                status_data["status"] = "failed"
                status_data["error"] = str(exc)
                status_data["updated"] = datetime.now().isoformat()
                _write_annotate_status(annotate_id, status_data)
                return

            high = sum(1 for a in annotations if a.get("risk_level") == "high")
            med = sum(1 for a in annotations if a.get("risk_level") == "medium")
            low = sum(1 for a in annotations if a.get("risk_level") == "low")
            ioc_count = sum(len(a.get("ioc_candidates") or []) for a in annotations)

            result: dict[str, Any] = {
                "source_job_id": job_id,
                "annotate_id": annotate_id,
                "model": model,
                "strategy": body.strategy,
                "created": status_data["created"],
                "annotations": annotations,
                "summary": {
                    "total_annotated": len(annotations),
                    "high_risk": high,
                    "medium_risk": med,
                    "low_risk": low,
                    "ioc_count": ioc_count,
                },
            }

            out_name = "%s%s" % (annotate_id, ANNOTATED_SUFFIX)
            out_path = OUTPUT_DIR / out_name
            out_path.write_text(
                json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
            )

            status_data["status"] = "completed"
            status_data["completed_functions"] = len(targets)
            status_data["output_file"] = out_name
            status_data["summary"] = result["summary"]
            status_data["updated"] = datetime.now().isoformat()
            _write_annotate_status(annotate_id, status_data)
        finally:
            _annotate_tasks.pop(annotate_id, None)

    task = asyncio.create_task(_run_annotation())
    _annotate_tasks[annotate_id] = task

    return {
        "status": "accepted",
        "annotate_id": annotate_id,
        "job_id": job_id,
        "strategy": body.strategy,
        "target_functions": len(targets),
        "message": "Annotation started. Poll GET /api/annotate/status/%s" % annotate_id,
    }


@app.get("/api/annotate/status/{annotate_id}")
async def get_annotate_status(annotate_id: str):
    safe = Path(annotate_id).name
    if safe != annotate_id or ".." in annotate_id:
        raise HTTPException(status_code=400, detail="Invalid annotate_id")
    data = _read_annotate_status(safe)
    if data is None:
        raise HTTPException(status_code=404, detail="Annotation task not found")
    return data


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
