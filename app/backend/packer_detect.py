"""
Lightweight packer detection for the backend.
Used to decide whether to route through unipacker-worker before Ghidra analysis.
Works on raw bytes / file path — no PE execution.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


def is_pe_file(filepath: Path) -> bool:
    """Check MZ + PE signature."""
    try:
        with open(filepath, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            if len(pe_offset_bytes) < 4:
                return False
            pe_offset = struct.unpack_from("<I", pe_offset_bytes)[0]
            f.seek(pe_offset)
            return f.read(4) == b"PE\x00\x00"
    except Exception:
        return False


def quick_packer_heuristic(filepath: Path) -> dict[str, Any]:
    """
    Fast heuristic check using section names only (no pefile dependency in backend).
    Returns: {"likely_packed": bool, "hint": str}
    """
    result: dict[str, Any] = {"likely_packed": False, "hint": "", "is_pe": False}
    if not is_pe_file(filepath):
        return result
    result["is_pe"] = True

    known_names = (
        b"UPX0",
        b"UPX1",
        b"UPX2",
        b".aspack",
        b".adata",
        b".nsp0",
        b".nsp1",
        b"pec1",
        b"pec2",
        b"PEC2",
        b".petite",
        b".MPRESS1",
        b".MPRESS2",
        b"FSG!",
        b".yP",
        b".themida",
        b".vmp0",
        b".vmp1",
    )

    try:
        with open(filepath, "rb") as f:
            f.seek(0x3C)
            pe_offset = struct.unpack_from("<I", f.read(4))[0]
            # COFF header: pe_offset+4 = machine, +6 = num_sections
            f.seek(pe_offset + 6)
            num_sections = struct.unpack_from("<H", f.read(2))[0]
            # Optional header size at pe_offset + 20
            f.seek(pe_offset + 20)
            opt_header_size = struct.unpack_from("<H", f.read(2))[0]
            # Section table starts at pe_offset + 24 + opt_header_size
            section_table_offset = pe_offset + 24 + opt_header_size

            for i in range(min(num_sections, 96)):
                f.seek(section_table_offset + i * 40)
                name_bytes = f.read(8)
                for known in known_names:
                    if name_bytes.startswith(known):
                        result["likely_packed"] = True
                        result["hint"] = name_bytes.split(b"\x00")[0].decode(
                            "ascii", errors="replace"
                        )
                        return result

            # Entropy-like heuristic: check if first non-header section is mostly high bytes
            # (simplified — full entropy calc delegated to unipacker-worker)
            if num_sections >= 1:
                f.seek(section_table_offset + 20)  # PointerToRawData of first section
                raw_ptr = struct.unpack_from("<I", f.read(4))[0]
                f.seek(section_table_offset + 16)  # SizeOfRawData
                raw_size = struct.unpack_from("<I", f.read(4))[0]
                if raw_ptr > 0 and raw_size > 256:
                    f.seek(raw_ptr)
                    sample = f.read(min(raw_size, 4096))
                    if sample:
                        high_bytes = sum(1 for b in sample if b > 0x7F)
                        ratio = high_bytes / len(sample)
                        if ratio > 0.55:
                            result["likely_packed"] = True
                            result["hint"] = f"high-byte ratio {ratio:.2f}"
    except Exception:
        pass

    return result
