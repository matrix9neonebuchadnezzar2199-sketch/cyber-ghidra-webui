"""
LIEF を使った ELF / Mach-O / PE のクロスプラットフォーム解析。
PE は pefile_scanner と補完関係にあり、ELF / Mach-O のカバーが主目的。
"""
from __future__ import annotations

import logging
from pathlib import Path

import lief

from ..base import BaseScanner, Finding, RiskLevel, ScanResult
from ..registry import register

logger = logging.getLogger(__name__)

_SUPPORTED = {
    # ELF
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-elf",
    "application/x-pie-executable",
    # Mach-O
    "application/x-mach-binary",
    # PE (補助)
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
}

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@register
class LiefScanner(BaseScanner):
    SCANNER_NAME = "lief"
    SUPPORTED_TYPES = _SUPPORTED

    def scan(self, file_path: Path, file_type: str) -> ScanResult:
        findings: list[Finding] = []
        metadata: dict = {}

        binary = lief.parse(str(file_path))
        if binary is None:
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error="LIEF could not parse the file",
            )

        # 共通メタデータ
        _fmt = getattr(binary, "format", None)
        if _fmt is not None and hasattr(_fmt, "name"):
            metadata["format"] = _fmt.name
        else:
            metadata["format"] = str(_fmt)
        metadata["is_pie"] = bool(binary.is_pie) if hasattr(binary, "is_pie") else None
        metadata["has_nx"] = bool(binary.has_nx) if hasattr(binary, "has_nx") else None
        try:
            ep = int(binary.entrypoint) if binary.entrypoint is not None else 0
            metadata["entrypoint"] = hex(ep) if ep else None
        except Exception:
            metadata["entrypoint"] = None

        # ELF 固有
        if isinstance(binary, lief.ELF.Binary):
            try:
                metadata["elf_type"] = binary.header.file_type.name
            except Exception:
                metadata["elf_type"] = str(binary.header.file_type)
            try:
                metadata["machine"] = binary.header.machine_type.name
            except Exception:
                metadata["machine"] = str(getattr(binary.header, "machine_type", ""))
            static_syms = list(binary.static_symbols) if hasattr(binary, "static_symbols") else []
            metadata["is_stripped"] = len(static_syms) == 0

            if metadata.get("is_stripped"):
                findings.append(
                    Finding(
                        rule="elf_stripped",
                        description="ELF binary is stripped (no symbols) — common in malware",
                        risk=RiskLevel.LOW,
                        details={},
                    )
                )

            # NX (No-Execute) 無効チェック
            if hasattr(binary, "has_nx") and not bool(binary.has_nx):
                findings.append(
                    Finding(
                        rule="elf_no_nx",
                        description="NX bit is disabled — executable stack is allowed",
                        risk=RiskLevel.MEDIUM,
                        details={},
                    )
                )

        # Mach-O 固有
        elif isinstance(binary, lief.MachO.Binary):
            try:
                metadata["macho_type"] = binary.header.file_type.name
            except Exception:
                metadata["macho_type"] = str(binary.header.file_type)
            try:
                metadata["cpu_type"] = binary.header.cpu_type.name
            except Exception:
                metadata["cpu_type"] = str(getattr(binary.header, "cpu_type", ""))

        # セクション一覧
        sections: list[dict] = []
        for sec in binary.sections:
            ent = float(sec.entropy) if sec.entropy is not None else 0.0
            sections.append(
                {
                    "name": str(sec.name) if sec.name is not None else "",
                    "size": int(sec.size) if sec.size is not None else 0,
                    "entropy": round(ent, 3),
                }
            )
            if ent > 7.0:
                findings.append(
                    Finding(
                        rule="lief_high_entropy_section",
                        description=f"Section '{sec.name}' entropy={ent:.2f} — possible packed/encrypted content",
                        risk=RiskLevel.HIGH,
                        details={"section": str(sec.name), "entropy": round(ent, 3)},
                    )
                )
        metadata["sections"] = sections

        if not findings:
            max_risk = RiskLevel.SAFE
        else:
            max_risk = max(
                (f.risk for f in findings),
                key=lambda r: _RISK_ORD.get(r.value, 0),
            )

        return ScanResult(
            scanner_name=self.SCANNER_NAME,
            success=True,
            risk=max_risk,
            findings=findings,
            metadata=metadata,
        )
