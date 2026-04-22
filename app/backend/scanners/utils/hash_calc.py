"""ファイルのハッシュ値を計算"""
from __future__ import annotations

import hashlib
from pathlib import Path

# ssdeep は任意依存。なければスキップ
try:
    import ppdeep as _ppdeep  # type: ignore[import-untyped]

    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False


def compute_hashes(file_path: Path) -> dict[str, str]:
    data = file_path.read_bytes()
    result: dict[str, str] = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if HAS_SSDEEP:
        result["ssdeep"] = _ppdeep.hash(data)  # type: ignore[union-attr]
    return result
