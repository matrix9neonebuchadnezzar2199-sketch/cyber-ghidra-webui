"""
Ghidra headless queue worker: polls /app/queue/pending, runs analyzeHeadless, writes status to output.
Intended for network-isolated containers (network_mode: none).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

OUTPUT_DIR = Path("/app/output")
QUEUE_PENDING = Path("/app/queue/pending")
QUEUE_PROCESSING = Path("/app/queue/processing")
QUEUE_DONE = Path("/app/queue/done")
SCRIPT_DIR = Path("/ghidra-scripts")
GHIDRA_HOME = Path(os.environ.get("GHIDRA_HOME", "/opt/ghidra"))
PROJECT_ROOT = Path(os.environ.get("GHIDRA_PROJECT_ROOT", "/workspace/ghidra_projects"))
GHIDRA_TIMEOUT_SEC = int(os.environ.get("GHIDRA_TIMEOUT_SEC", "600"))
POLL_SEC = float(os.environ.get("WORKER_POLL_SEC", "2"))


def write_status(job_id: str, data: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / f"{job_id}.status.json"
    tmp = OUTPUT_DIR / f"{job_id}.status.json.tmp"
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def process_job(job_path: Path) -> None:
    job_id = job_path.stem
    proc_path = QUEUE_PROCESSING / job_path.name
    QUEUE_PROCESSING.mkdir(parents=True, exist_ok=True)
    try:
        job_path.rename(proc_path)
    except OSError:
        return

    try:
        payload = json.loads(proc_path.read_text(encoding="utf-8"))
    except Exception as exc:
        write_status(
            job_id,
            {
                "job_id": job_id,
                "status": "failed",
                "error": f"invalid job file: {exc}",
                "updated": datetime.now().isoformat(),
            },
        )
        _finish(proc_path)
        return

    filepath = Path(payload["filepath"])
    project_name = payload["project_name"]
    if not filepath.is_file():
        write_status(
            job_id,
            {
                **{k: v for k, v in payload.items() if k in ("filename", "sha256", "created")},
                "job_id": job_id,
                "status": "failed",
                "error": "input file missing",
                "updated": datetime.now().isoformat(),
            },
        )
        _finish(proc_path)
        return

    base = {**payload, "job_id": job_id, "status": "running", "updated": datetime.now().isoformat()}
    write_status(job_id, base)

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
    PROJECT_ROOT.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=GHIDRA_TIMEOUT_SEC,
        )
        out = {
            **base,
            "status": "completed" if result.returncode == 0 else "failed",
            "returncode": result.returncode,
            "stdout_tail": (result.stdout or "")[-8000:],
            "stderr_tail": (result.stderr or "")[-8000:],
            "updated": datetime.now().isoformat(),
        }
        if result.returncode != 0:
            out["error"] = "analyzeHeadless exited with a non-zero status"
        else:
            combined = (result.stdout or "") + "\n" + (result.stderr or "")
            m = re.search(r"Analysis complete:\s+(\S+\.json)", combined)
            if m:
                out["analysis_json"] = Path(m.group(1)).name
            else:
                input_mtime = filepath.stat().st_mtime
                candidates = sorted(
                    OUTPUT_DIR.glob("*_analysis.json"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                for c in candidates:
                    if c.stat().st_mtime >= input_mtime - 5.0:
                        out["analysis_json"] = c.name
                        break
        write_status(job_id, out)
    except subprocess.TimeoutExpired:
        write_status(
            job_id,
            {
                **base,
                "status": "failed",
                "error": f"analyzeHeadless exceeded {GHIDRA_TIMEOUT_SEC}s",
                "updated": datetime.now().isoformat(),
            },
        )
    except Exception as exc:
        write_status(
            job_id,
            {
                **base,
                "status": "failed",
                "error": str(exc),
                "updated": datetime.now().isoformat(),
            },
        )
    finally:
        _finish(proc_path)


def _finish(proc_path: Path) -> None:
    QUEUE_DONE.mkdir(parents=True, exist_ok=True)
    dest = QUEUE_DONE / proc_path.name
    if proc_path.exists():
        proc_path.rename(dest)


def main() -> None:
    for d in (QUEUE_PENDING, QUEUE_PROCESSING, QUEUE_DONE, OUTPUT_DIR, PROJECT_ROOT):
        d.mkdir(parents=True, exist_ok=True)
    print("[ghidra-worker] queue worker started", flush=True)
    while True:
        for f in sorted(QUEUE_PENDING.glob("*.json")):
            process_job(f)
        time.sleep(POLL_SEC)


if __name__ == "__main__":
    main()
