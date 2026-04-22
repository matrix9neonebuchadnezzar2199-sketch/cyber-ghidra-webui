"""
binwalk を使ったファームウェア/バイナリ内の埋め込みファイル検出。
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from ..base import BaseScanner, Finding, RiskLevel, ScanResult
from ..registry import register

logger = logging.getLogger(__name__)

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@register
class BinwalkScanner(BaseScanner):
    SCANNER_NAME = "binwalk"
    # ファイル種別を問わずスキャン可能
    MATCH_ALL = True

    def scan(self, file_path: Path, file_type: str) -> ScanResult:
        findings: list[Finding] = []
        metadata: dict = {}

        try:
            proc = subprocess.run(
                ["binwalk", "--quiet", str(file_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error="binwalk not found in PATH",
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error="binwalk timed out (>120s)",
            )

        # binwalk 出力をパース（テキスト出力: "DECIMAL|HEX   type   description"）
        embedded_items: list[dict[str, str]] = []
        for line in (proc.stdout or "").strip().splitlines():
            line = line.strip()
            if not line:
                continue
            u = line.upper()
            if u.startswith("DECIMAL") or ("DECIMAL" in u and "DESCRIPTION" in u):
                continue
            parts = line.split(None, 2)
            if len(parts) >= 3:
                embedded_items.append(
                    {
                        "offset": parts[0],
                        "type": parts[1] if len(parts) > 1 else "",
                        "description": parts[2] if len(parts) > 2 else "",
                    }
                )

        metadata["embedded_count"] = len(embedded_items)
        metadata["embedded_items"] = embedded_items[:50]  # 上限 50

        if len(embedded_items) > 0:
            risk = RiskLevel.MEDIUM if len(embedded_items) > 5 else RiskLevel.LOW
            findings.append(
                Finding(
                    rule="binwalk_embedded_files",
                    description=f"Found {len(embedded_items)} embedded file(s)/data segment(s)",
                    risk=risk,
                    details={"count": len(embedded_items)},
                )
            )

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
