"""
Unipacker HTTP microservice.
Receives a packed PE, runs emulation-based unpacking, returns the unpacked PE.
Supports multi-layer unpacking (re-detect after each pass).
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
UNPACK_MAX_LAYERS = int(os.environ.get("UNPACK_MAX_LAYERS", "3"))
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
        result["details"] = "pefile parse error: %s" % exc
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
            result["details"] = "Known packer section: %s" % sn_clean
            break

    if not result["packed"] and suspicious_count >= 2:
        result["packed"] = True
        result["packer_name"] = "unknown"
        result["details"] = (
            "Heuristic: %d suspicious section(s) "
            "(high entropy / large virtual-to-raw ratio)" % suspicious_count
        )

    try:
        pe.close()
    except Exception:
        pass
    return result


def _run_unipacker_once(input_path: Path, output_dir: Path) -> Path | None:
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

    dest = output_dir / ("unpacked_%s" % input_path.name)
    if dest.is_file() and dest.stat().st_size > 0:
        return dest
    return None


def _run_unipacker_multilayer(
    input_path: Path,
    work_dir: Path,
    max_layers: int,
) -> dict[str, Any]:
    """
    Repeatedly detect → unpack until the output is no longer packed
    or max_layers is reached.
    """
    original_sha256 = hashlib.sha256(input_path.read_bytes()).hexdigest()
    layers: list[dict[str, Any]] = []
    current_path = input_path
    seen_hashes: set[str] = {original_sha256}

    for i in range(1, max_layers + 1):
        detection = _detect_packer_simple(current_path)
        if not detection["packed"]:
            reason = "completed" if layers else "not_packed"
            return {
                "unpacked": bool(layers),
                "layers": layers,
                "total_layers": len(layers),
                "final_path": current_path if layers else None,
                "final_sha256": hashlib.sha256(current_path.read_bytes()).hexdigest(),
                "original_sha256": original_sha256,
                "reason": reason,
            }

        layer_dir = work_dir / ("layer_%d" % i)
        layer_dir.mkdir(parents=True, exist_ok=True)

        unpacked = _run_unipacker_once(current_path, layer_dir)
        if unpacked is None or not unpacked.is_file():
            return {
                "unpacked": bool(layers),
                "layers": layers,
                "total_layers": len(layers),
                "final_path": current_path if layers else None,
                "final_sha256": hashlib.sha256(current_path.read_bytes()).hexdigest(),
                "original_sha256": original_sha256,
                "reason": "unpack_failed_at_layer_%d" % i,
            }

        unpacked_sha = hashlib.sha256(unpacked.read_bytes()).hexdigest()

        if unpacked_sha in seen_hashes:
            return {
                "unpacked": bool(layers),
                "layers": layers,
                "total_layers": len(layers),
                "final_path": current_path if layers else None,
                "final_sha256": hashlib.sha256(current_path.read_bytes()).hexdigest(),
                "original_sha256": original_sha256,
                "reason": "hash_cycle_at_layer_%d" % i,
            }
        seen_hashes.add(unpacked_sha)

        input_sha = hashlib.sha256(current_path.read_bytes()).hexdigest()
        layers.append(
            {
                "layer": i,
                "packer_name": detection.get("packer_name", "unknown"),
                "input_sha256": input_sha,
                "output_sha256": unpacked_sha,
            }
        )

        current_path = unpacked

    final_detection = _detect_packer_simple(current_path)
    return {
        "unpacked": True,
        "layers": layers,
        "total_layers": len(layers),
        "final_path": current_path,
        "final_sha256": hashlib.sha256(current_path.read_bytes()).hexdigest(),
        "original_sha256": original_sha256,
        "reason": "max_layers" if final_detection["packed"] else "completed",
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "unipacker-worker",
        "max_layers": UNPACK_MAX_LAYERS,
    }


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
    Unpack a packed PE binary using multi-layer emulation.
    Returns the unpacked PE file as download + layer metadata in headers,
    or JSON if not packed / failed.
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

        result = _run_unipacker_multilayer(input_path, work, UNPACK_MAX_LAYERS)

        if not result["unpacked"] or result["final_path"] is None:
            return JSONResponse(
                status_code=200,
                content={
                    "unpacked": False,
                    "reason": result["reason"],
                    "layers": result["layers"],
                    "total_layers": result["total_layers"],
                    "message": "Unpacking did not produce a result",
                },
            )

        final_path: Path = result["final_path"]
        file_data = final_path.read_bytes()

        packer_chain = " → ".join(layer["packer_name"] for layer in result["layers"])

        return Response(
            content=file_data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": 'attachment; filename="unpacked_%s"' % file.filename,
                "X-Unpacked": "true",
                "X-Packer-Chain": packer_chain,
                "X-Total-Layers": str(result["total_layers"]),
                "X-Unpacked-SHA256": result["final_sha256"],
                "X-Original-SHA256": result["original_sha256"],
                "X-Unpack-Reason": result["reason"],
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
