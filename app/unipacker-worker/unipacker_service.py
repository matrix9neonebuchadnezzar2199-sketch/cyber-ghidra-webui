"""
Unipacker HTTP microservice.
Receives a packed PE, runs emulation-based unpacking, returns the unpacked PE.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any

import pefile
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, Response

UNPACK_TIMEOUT = int(os.environ.get("UNPACK_TIMEOUT_SEC", "300"))
UNPACK_MAX_SIZE_MB = int(os.environ.get("UNPACK_MAX_SIZE_MB", "200"))
WORK_DIR = Path("/tmp/unipacker_work")

app = FastAPI(title="Unipacker Worker")


def _detect_packer_simple(pe_path: Path) -> dict[str, Any]:
    """
    Quick packer heuristics using pefile section analysis.
    Returns dict with 'packed' bool, 'packer_name' str, 'details' str.
    """
    result: dict[str, Any] = {
        "packed": False,
        "packer_name": "none",
        "details": "",
        "sections": [],
    }
    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
    except Exception as exc:
        result["details"] = f"pefile parse error: {exc}"
        return result

    section_info = []
    suspicious_count = 0
    for s in pe.sections:
        try:
            name = s.Name.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            name = "???"
        raw = s.SizeOfRawData
        virtual = s.Misc_VirtualSize
        entropy = s.get_entropy()
        info = {
            "name": name,
            "raw_size": raw,
            "virtual_size": virtual,
            "entropy": round(entropy, 3),
        }
        section_info.append(info)
        if entropy > 6.8:
            suspicious_count += 1
        if raw > 0 and virtual / raw > 10:
            suspicious_count += 1

    result["sections"] = section_info

    known_packer_sections = {
        "UPX0": "UPX",
        "UPX1": "UPX",
        "UPX2": "UPX",
        ".aspack": "ASPack",
        ".adata": "ASPack",
        ".nsp0": "NsPack",
        ".nsp1": "NsPack",
        ".nsp2": "NsPack",
        "pec1": "PECompact",
        "pec2": "PECompact",
        "PEC2": "PECompact",
        ".petite": "PEtite",
        ".MPRESS1": "MPRESS",
        ".MPRESS2": "MPRESS",
        "FSG!": "FSG",
        ".yP": "YZPack",
        ".themida": "Themida",
        ".vmp0": "VMProtect",
        ".vmp1": "VMProtect",
    }

    section_names = [s["name"] for s in section_info]
    for sn in section_names:
        sn_clean = sn.strip()
        if sn_clean in known_packer_sections:
            result["packed"] = True
            result["packer_name"] = known_packer_sections[sn_clean]
            result["details"] = f"Known packer section: {sn_clean}"
            break

    if not result["packed"] and suspicious_count >= 2:
        result["packed"] = True
        result["packer_name"] = "unknown"
        result["details"] = (
            f"Heuristic: {suspicious_count} suspicious section(s) "
            f"(high entropy / large virtual-to-raw ratio)"
        )

    try:
        pe.close()
    except Exception:
        pass
    return result


def _run_unipacker(input_path: Path, output_dir: Path) -> Path | None:
    """Run unipacker on the input PE. Returns path to unpacked file or None."""
    script = Path(__file__).resolve().parent / "run_unpack.py"
    try:
        subprocess.run(
            [sys.executable, str(script), str(input_path), str(output_dir)],
            check=False,
            timeout=UNPACK_TIMEOUT,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired:
        traceback.print_exc()
        return None
    except Exception:
        traceback.print_exc()
        return None

    dest = output_dir / f"unpacked_{input_path.name}"
    if dest.is_file() and dest.stat().st_size > 0:
        return dest
    return None


@app.get("/health")
async def health():
    return {"status": "ok", "service": "unipacker-worker"}


@app.post("/detect")
async def detect_packer(file: UploadFile = File(...)):
    """Detect whether the uploaded PE is packed."""
    if not file.filename:
        raise HTTPException(400, "missing filename")

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(WORK_DIR), suffix=".bin")
    tmp = Path(tmp_name)
    try:
        os.close(fd)
        data = await file.read()
        if len(data) > UNPACK_MAX_SIZE_MB * 1024 * 1024:
            raise HTTPException(413, "file too large")
        tmp.write_bytes(data)
        result = _detect_packer_simple(tmp)
        result["filename"] = file.filename
        result["sha256"] = hashlib.sha256(data).hexdigest()
        result["size_bytes"] = len(data)
        return result
    finally:
        tmp.unlink(missing_ok=True)


@app.post("/unpack")
async def unpack_binary(file: UploadFile = File(...)):
    """
    Unpack a packed PE binary using unipacker emulation.
    Returns the unpacked PE file as download, or JSON error.
    """
    if not file.filename:
        raise HTTPException(400, "missing filename")

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(dir=str(WORK_DIR)))
    input_path = work / file.filename
    try:
        data = await file.read()
        if len(data) > UNPACK_MAX_SIZE_MB * 1024 * 1024:
            raise HTTPException(413, "file too large")
        input_path.write_bytes(data)

        detection = _detect_packer_simple(input_path)
        if not detection["packed"]:
            return JSONResponse(
                status_code=200,
                content={
                    "unpacked": False,
                    "reason": "not_packed",
                    "detection": detection,
                    "message": "File does not appear to be packed",
                },
            )

        unpacked_path = _run_unipacker(input_path, work)
        if unpacked_path is None or not unpacked_path.is_file():
            return JSONResponse(
                status_code=200,
                content={
                    "unpacked": False,
                    "reason": "unpack_failed",
                    "detection": detection,
                    "message": "Unipacker could not extract the original binary",
                },
            )

        file_data = unpacked_path.read_bytes()
        unpacked_hash = hashlib.sha256(file_data).hexdigest()
        orig_hash = hashlib.sha256(data).hexdigest()
        return Response(
            content=file_data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="unpacked_{file.filename}"',
                "X-Unpacked": "true",
                "X-Packer-Name": str(detection.get("packer_name", "unknown")),
                "X-Unpacked-SHA256": unpacked_hash,
                "X-Original-SHA256": orig_hash,
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={
                "unpacked": False,
                "reason": "internal_error",
                "message": str(exc),
            },
        )
    finally:
        shutil.rmtree(str(work), ignore_errors=True)
