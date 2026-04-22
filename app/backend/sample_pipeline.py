"""
アップロード後の解析パス分岐: Ghidra ワーカー or 静的分析のみ。
判別は libmagic 優先＋拡張子＋PE/ELF 直読み（フォールバック）。
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Literal, TypedDict

from packer_detect import is_pe_file
from scanners.base import ScanResult
from scanners.runner import determine_overall_risk, run_scan
from scanners.utils.file_type import detect_file_type

# ワーカー（analyzeHeadless）に載せる候補（主にネイティブ COFF/ELF 系）
_GHIDRA_MIMES: frozenset[str] = frozenset(
    {
        "application/x-dosexec",
        "application/x-executable",
        "application/x-elf",
        "application/x-pie-executable",
        "application/x-sharedlib",
        "application/x-mach-binary",
        "application/vnd.microsoft.portable-executable",
        "application/x-msdownload",
    }
)

# PDF / ドキュメント / Android 等（Ghidra では不適切が多い → 静的分析のみ）
_STATIC_MIMES: frozenset[str] = frozenset(
    {
        "application/pdf",
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        "application/vnd.ms-word.document.macroEnabled.12",
        "application/x-msi",
        "text/rtf",
        "application/rtf",
        "application/vnd.android.package-archive",
    }
)

# application/zip だが中身判別用の拡張子（OOXML / JAR / APK 等）
_ZIP_INNER_OFFICE_OR_PKG = frozenset(
    {".docx", ".xlsx", ".pptx", ".xlsm", ".docm", ".pptm", ".apk", ".jar", ".kdbx"}
)


def _is_elf_path(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _is_pdf_magic(path: Path) -> bool:
    """拡張子の取り違い（全角 .pdf 等）があっても、先頭 %PDF なら静的分析へ。"""
    try:
        return path.read_bytes()[:4] == b"%PDF"
    except OSError:
        return False


def classify_sample_pipeline(path: Path) -> Literal["ghidra", "static_only"]:
    """
    検体の解析パスを 1 件分決定する。

    * static_only: PDF/Office 等。Ghidra キューに乗せない。
    * ghidra: PE/ELF 等。従来どおり analyzeHeadless。
    * 判定不能（octet-stream 等）は PE/ELF ヘッダがあれば ghidra、それ以外は static
      （Ghidra で毎回失敗する挙動を避けるためデフォルトは static）。
    """
    if not path.is_file():
        return "static_only"

    if _is_pdf_magic(path):
        return "static_only"

    ext = path.suffix.lower()
    mime = detect_file_type(path)

    if ext == ".ipa":
        return "static_only"  # Mach-O 等混在; Ghidra 1 本は不自然
    if mime in ("application/zip", "application/x-zip-compressed"):
        if ext in _ZIP_INNER_OFFICE_OR_PKG or ext in (".odt", ".ods", ".odp", ".epub"):
            return "static_only"
    if ext in (".apk", ".pdf") or mime in _STATIC_MIMES or mime in ("text/rtf", "application/rtf", "application/pdf"):
        return "static_only"
    if mime in _GHIDRA_MIMES:
        return "ghidra"
    if mime in ("application/octet-stream", "text/plain"):
        if is_pe_file(path) or _is_elf_path(path):
            return "ghidra"
    if is_pe_file(path) or _is_elf_path(path):
        return "ghidra"
    return "static_only"


def static_scan_to_json_dict(
    file_type: str,
    hashes: dict[str, str],
    results: list[ScanResult],
) -> dict[str, Any]:
    """ジョブ status や API 用に、ScanResult 列を JSON 化する。"""
    overall = determine_overall_risk(results)
    out_results: list[dict[str, Any]] = []
    for r in results:
        out_results.append(
            {
                "scanner_name": r.scanner_name,
                "success": r.success,
                "risk": r.risk.value,
                "findings": [
                    {
                        "rule": f.rule,
                        "description": f.description,
                        "risk": f.risk.value,
                        "details": f.details,
                    }
                    for f in r.findings
                ],
                "metadata": r.metadata,
                "error": r.error,
                "elapsed_sec": r.elapsed_sec,
            }
        )
    return {
        "file_type": file_type,
        "hashes": hashes,
        "overall_risk": overall.value,
        "scanners_run": len(results),
        "results": out_results,
    }


class StaticJobOutcome(TypedDict, total=False):
    file_type: str
    static_scan: dict[str, Any]
    error: str


async def run_static_scan_on_disk(path: Path) -> StaticJobOutcome:
    """同プロセス内で run_scan（ブロッキングは別スレッド）。"""
    if not path.is_file():
        return {"error": "file missing"}

    def work() -> tuple[str, dict[str, str], list[ScanResult]]:
        return run_scan(path, None)

    try:
        file_type, hashes, results = await asyncio.to_thread(work)
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}

    return {
        "file_type": file_type,
        "static_scan": static_scan_to_json_dict(file_type, hashes, results),
    }
