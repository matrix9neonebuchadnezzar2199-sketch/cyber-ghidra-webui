"""
oletools を使った Office ドキュメントのマルウェア検査。
検出項目: VBA マクロ、AutoOpen/AutoExec、DDE リンク、
          疑わしい API (Shell, WScript.Shell 等)、OLE 埋め込みオブジェクト
"""
from __future__ import annotations

import logging
from pathlib import Path

from oletools import oleid
from oletools.olevba import VBA_Parser

from ..base import BaseScanner, Finding, RiskLevel, ScanResult
from ..registry import register

logger = logging.getLogger(__name__)

_OFFICE_TYPES = {
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
}

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@register
class OletoolsScanner(BaseScanner):
    SCANNER_NAME = "oletools"
    SUPPORTED_TYPES = _OFFICE_TYPES

    def scan(self, file_path: Path, file_type: str) -> ScanResult:
        findings: list[Finding] = []
        metadata: dict = {}

        # --- oleid: 指標収集 ---
        try:
            oid = oleid.OleID(str(file_path))
            indicators = oid.check()
            for ind in indicators:
                metadata[ind.name] = {"value": str(ind.value), "risk": ind.risk}
                rsk = (str(ind.risk) if ind.risk is not None else "").lower()
                if rsk in ("high", "medium"):
                    findings.append(
                        Finding(
                            rule=f"oleid_{ind.name}",
                            description=f"{ind.name}: {ind.value}",
                            risk=RiskLevel.HIGH if rsk == "high" else RiskLevel.MEDIUM,
                            details={"indicator": ind.name, "value": str(ind.value)},
                        )
                    )
        except Exception as e:
            logger.warning("oleid failed: %s", e)

        # --- olevba: VBA マクロ解析 ---
        try:
            vba_parser = VBA_Parser(str(file_path))
            if vba_parser.detect_vba_macros():
                metadata["has_vba_macros"] = True
                for kw_type, keyword, description in vba_parser.analyze_macros():
                    risk = RiskLevel.LOW
                    if kw_type in ("AutoExec", "Suspicious"):
                        risk = RiskLevel.HIGH
                    elif kw_type == "IOC":
                        risk = RiskLevel.MEDIUM

                    findings.append(
                        Finding(
                            rule=f"olevba_{kw_type}_{keyword}",
                            description=description,
                            risk=risk,
                            details={"type": kw_type, "keyword": keyword},
                        )
                    )
            else:
                metadata["has_vba_macros"] = False
            vba_parser.close()
        except Exception as e:
            logger.warning("olevba failed: %s", e)

        # 総合リスク判定
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
