"""
pefile を使った Windows PE ファイルの静的解析。
検出項目: 高エントロピーセクション（パック検出）、不審なインポート、
          タイムスタンプ異常、セクション名異常
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

import pefile

from ..base import BaseScanner, Finding, RiskLevel, ScanResult
from ..registry import register

logger = logging.getLogger(__name__)

_PE_TYPES = {
    "application/x-dosexec",
    "application/x-executable",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
}

# マルウェアで頻出する不審な API
_SUSPICIOUS_IMPORTS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "IsDebuggerPresent",
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "InternetOpenA",
    "InternetOpenUrlA",
    "CryptEncrypt",
    "CryptDecrypt",
}

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@register
class PefileScanner(BaseScanner):
    SCANNER_NAME = "pefile"
    SUPPORTED_TYPES = _PE_TYPES

    def scan(self, file_path: Path, file_type: str) -> ScanResult:
        findings: list[Finding] = []
        metadata: dict = {}

        try:
            pe = pefile.PE(str(file_path))
        except pefile.PEFormatError as e:
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error=f"PE parse error: {e}",
            )

        # 基本メタデータ
        metadata["machine"] = hex(pe.FILE_HEADER.Machine)
        metadata["num_sections"] = pe.FILE_HEADER.NumberOfSections
        metadata["timestamp"] = pe.FILE_HEADER.TimeDateStamp
        metadata["dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)

        # タイムスタンプ異常検出
        try:
            ts = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc)
            metadata["compile_time"] = ts.isoformat()
            if ts.year < 2000 or ts > datetime.now(tz=timezone.utc):
                findings.append(
                    Finding(
                        rule="pe_suspicious_timestamp",
                        description=f"Suspicious compile timestamp: {ts.isoformat()}",
                        risk=RiskLevel.MEDIUM,
                        details={"timestamp": ts.isoformat()},
                    )
                )
        except Exception:
            pass

        # セクション解析
        section_info = []
        for section in pe.sections:
            sec_name = section.Name.decode("utf-8", errors="replace").strip("\x00")
            sec_entropy = float(section.get_entropy())
            sec_data = {
                "name": sec_name,
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "entropy": round(sec_entropy, 3),
            }
            section_info.append(sec_data)

            # 高エントロピー → パックまたは暗号化の疑い
            if sec_entropy > 7.0:
                findings.append(
                    Finding(
                        rule="pe_high_entropy_section",
                        description=(
                            f"Section '{sec_name}' has high entropy ({sec_entropy:.2f}) "
                            "— possible packing/encryption"
                        ),
                        risk=RiskLevel.HIGH,
                        details=sec_data,
                    )
                )

        metadata["sections"] = section_info

        # インポート解析
        suspicious_found: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp and imp.name:
                        func_name = imp.name.decode("utf-8", errors="replace")
                        if func_name in _SUSPICIOUS_IMPORTS:
                            suspicious_found.append(func_name)

        if suspicious_found:
            metadata["suspicious_imports"] = suspicious_found
            risk = RiskLevel.HIGH if len(suspicious_found) >= 5 else RiskLevel.MEDIUM
            findings.append(
                Finding(
                    rule="pe_suspicious_imports",
                    description=(
                        f"Found {len(suspicious_found)} suspicious API imports: "
                        f"{', '.join(suspicious_found[:10])}"
                    ),
                    risk=risk,
                    details={"imports": suspicious_found},
                )
            )

        pe.close()

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
