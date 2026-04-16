"""
Ghidra headless queue worker: polls /app/queue/pending, runs analyzeHeadless, writes status to output.
Intended for network-isolated containers (network_mode: none).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
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

# auto_analyze.py prints: [CyberGhidra] PROGRESS N
PROGRESS_RE = re.compile(r"\[CyberGhidra\]\s*PROGRESS\s+(\d+)", re.IGNORECASE)


def _extract_analysis_json(tail: str) -> str | None:
    m = re.search(r"Analysis complete:\s+(\S+\.json)", tail)
    if not m:
        return None
    return Path(m.group(1)).name


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

    base = {
        **payload,
        "job_id": job_id,
        "status": "running",
        "progress_message": "analyzeHeadless を起動しています…",
        "progress_percent": None,
        "updated": datetime.now().isoformat(),
    }
    write_status(job_id, base)

    analyze = GHIDRA_HOME / "support" / "analyzeHeadless"
    cmd = [
        str(analyze),
        str(PROJECT_ROOT),
        project_name,
        "-import",
        str(filepath),
        "-scriptPath",
        str(SCRIPT_DIR),
        "-postScript",
        "auto_analyze.py",
        job_id,
        "-deleteProject",
    ]
    PROJECT_ROOT.mkdir(parents=True, exist_ok=True)

    try:
        child_env = os.environ.copy()
        child_env["CYBERGHIDRA_JOB_ID"] = job_id

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=child_env,
        )
        full_lines: list[str] = []
        last_line: list[str] = [""]
        last_progress = [None]
        analysis_json_from_line: list[str | None] = [None]

        def drain_stdout() -> None:
            if proc.stdout is None:
                return
            try:
                for line in proc.stdout:
                    full_lines.append(line)
                    s = line.strip()
                    if s:
                        last_line[0] = s[:500]
                    m = PROGRESS_RE.search(line)
                    if m:
                        try:
                            v = int(m.group(1))
                            last_progress[0] = max(0, min(100, v))
                        except ValueError:
                            pass
                    m_ac = re.search(
                        r"\[CyberGhidra\]\s*Analysis complete:\s+(\S+\.json)",
                        line,
                        re.IGNORECASE,
                    )
                    if m_ac:
                        analysis_json_from_line[0] = Path(m_ac.group(1)).name
            except Exception:
                pass

        reader = threading.Thread(target=drain_stdout, daemon=True)
        reader.start()

        deadline = time.monotonic() + float(GHIDRA_TIMEOUT_SEC)
        while reader.is_alive():
            if time.monotonic() > deadline:
                proc.kill()
                reader.join(timeout=30)
                write_status(
                    job_id,
                    {
                        **base,
                        "status": "failed",
                        "error": f"analyzeHeadless exceeded {GHIDRA_TIMEOUT_SEC}s",
                        "progress_message": last_line[0] or "",
                        "progress_percent": last_progress[0],
                        "updated": datetime.now().isoformat(),
                    },
                )
                return
            write_status(
                job_id,
                {
                    **base,
                    "progress_message": last_line[0] or "Ghidra を実行中です…",
                    "progress_percent": last_progress[0],
                    "updated": datetime.now().isoformat(),
                },
            )
            time.sleep(2.0)

        reader.join(timeout=5)
        rc = proc.wait()
        combined = "".join(full_lines)

        out = {
            **base,
            "status": "completed" if rc == 0 else "failed",
            "returncode": rc,
            "stdout_tail": combined[-8000:],
            "stderr_tail": "",
            "progress_percent": 100 if rc == 0 else last_progress[0],
            "updated": datetime.now().isoformat(),
        }
        out.pop("progress_message", None)
        if rc != 0:
            out["error"] = "analyzeHeadless exited with a non-zero status"
            out["progress_message"] = last_line[0] or ""
        else:
            picked = analysis_json_from_line[0] or _extract_analysis_json(combined)
            if picked:
                old_name = picked
                if job_id and job_id not in old_name:
                    old_path = OUTPUT_DIR / old_name
                    dest_name = "%s_%s" % (job_id, old_name)
                    dest_path = OUTPUT_DIR / dest_name
                    if old_path.is_file():
                        try:
                            dest_path.unlink(missing_ok=True)
                            old_path.rename(dest_path)
                            out["analysis_json"] = dest_name
                        except OSError as exc:
                            print(
                                "[ghidra-worker] WARNING: failed to rename analysis JSON %s: %s"
                                % (old_path, exc),
                                flush=True,
                            )
                            out["analysis_json"] = old_name
                    else:
                        out["analysis_json"] = old_name
                else:
                    out["analysis_json"] = old_name
            else:
                candidates = sorted(
                    OUTPUT_DIR.glob("*_analysis.json"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                for c in candidates:
                    if job_id in c.name:
                        out["analysis_json"] = c.name
                        break
        write_status(job_id, out)
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
    try:
        if proc_path.exists():
            proc_path.rename(dest)
    except OSError as exc:
        print("[ghidra-worker] WARNING: failed to move %s to done: %s" % (proc_path, exc), flush=True)


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
