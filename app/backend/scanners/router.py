"""
/api/scan/* エンドポイント定義。
既存の main.py に `app.include_router(scan_router)` の 1行を追加するだけで有効化される。
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Body, HTTPException

from .models import (
    FindingResponse,
    ScannerInfoResponse,
    ScannerResultResponse,
    ScanRequest,
    ScanResponse,
)
from .registry import get_all_scanners
from .runner import determine_overall_risk, run_scan

router = APIRouter(prefix="/api/scan", tags=["scan"])

# main.py / worker.py と同じアプリ上のパス（cyber-ghidra-webui）
INPUT_DIR = Path("/app/input")
OUTPUT_DIR = Path("/app/output")
QUEUE_PENDING = Path("/app/queue/pending")
QUEUE_PROCESSING = Path("/app/queue/processing")
QUEUE_DONE = Path("/app/queue/done")


def _resolve_file_path(job_id: str) -> Path:
    """
    job_id からアップロード済みファイルのパスを返す。
    1) キュー JSON (pending / processing / done) の filepath
    2) output の {job_id}.status.json の filename → INPUT_DIR
    """
    if not job_id or Path(job_id).name != job_id or ".." in job_id:
        raise FileNotFoundError("invalid job_id")
    job_id = Path(job_id).name

    for qdir in (QUEUE_PENDING, QUEUE_PROCESSING, QUEUE_DONE):
        jp = qdir / f"{job_id}.json"
        if not jp.is_file():
            continue
        try:
            payload = json.loads(jp.read_text(encoding="utf-8"))
            raw = payload.get("filepath", "")
            fp = Path(str(raw)) if raw else None
        except (OSError, TypeError, json.JSONDecodeError, ValueError):
            continue
        if fp is not None and fp.is_file():
            return fp

    stpath = OUTPUT_DIR / f"{job_id}.status.json"
    if stpath.is_file():
        try:
            st = json.loads(stpath.read_text(encoding="utf-8"))
            name = st.get("filename")
            if name:
                p = (INPUT_DIR / Path(str(name)).name).resolve()
                try:
                    p.relative_to(INPUT_DIR.resolve())
                except ValueError:
                    p = None
                if p is not None and p.is_file():
                    return p
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass

    raise FileNotFoundError(f"File for job_id={job_id} not found")


@router.post("/{job_id}", response_model=ScanResponse)
def scan_file(
    job_id: str,
    body: ScanRequest | None = Body(default=None),
):
    """
    指定ジョブのファイルに対してマルウェア静的解析スキャンを実行する。
    body.scanners が null の場合、ファイル種別に応じて自動選択。
    """
    try:
        file_path = _resolve_file_path(job_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Job {job_id} の検体ファイルが見つかりません",
        ) from None

    scanner_names = body.scanners if body else None
    file_type, hashes, results = run_scan(file_path, scanner_names)
    overall_risk = determine_overall_risk(results)

    return ScanResponse(
        job_id=job_id,
        file_name=file_path.name,
        file_type=file_type,
        file_size=file_path.stat().st_size,
        hashes=hashes,
        overall_risk=overall_risk.value,
        scanners_run=len(results),
        results=[
            ScannerResultResponse(
                scanner_name=r.scanner_name,
                success=r.success,
                risk=r.risk.value,
                findings=[
                    FindingResponse(
                        rule=f.rule,
                        description=f.description,
                        risk=f.risk.value,
                        details=f.details,
                    )
                    for f in r.findings
                ],
                metadata=r.metadata,
                error=r.error,
                elapsed_sec=r.elapsed_sec,
            )
            for r in results
        ],
    )


@router.get("/scanners", response_model=list[ScannerInfoResponse])
def list_scanners():
    """登録済みスキャナー一覧を返す"""
    scanners = get_all_scanners()
    return [
        ScannerInfoResponse(
            name=s.SCANNER_NAME,
            supported_types=sorted(s.SUPPORTED_TYPES),
            match_all=s.MATCH_ALL,
        )
        for s in scanners.values()
    ]
