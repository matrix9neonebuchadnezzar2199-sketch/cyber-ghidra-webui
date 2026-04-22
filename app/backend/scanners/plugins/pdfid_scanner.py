"""
pdfid を使った PDF ドキュメントの悪性コード検査。
検出項目: /JS, /JavaScript, /OpenAction, /AA, /Launch, /RichMedia, /XFA, /JBIG2Decode
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pdfid import pdfid

from ..base import BaseScanner, Finding, RiskLevel, ScanResult
from ..registry import register

logger = logging.getLogger(__name__)

# 危険度の高いキーワード定義
_HIGH_RISK_KEYWORDS = {"/JS", "/JavaScript", "/Launch"}
_MEDIUM_RISK_KEYWORDS = {"/OpenAction", "/AA", "/RichMedia", "/XFA"}
_LOW_RISK_KEYWORDS = {"/JBIG2Decode", "/ObjStm", "/Encrypt"}

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _iter_pdfid_keywords(file_path: Path) -> list[dict[str, int | str]]:
    """pdfid (PyPI) の JSON 文字列から keyword 行を展開"""
    xmldoc = pdfid.PDFiD(str(file_path))
    raw = pdfid.PDFiD2JSON(xmldoc, force=True)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    data = json.loads(raw) if raw else []
    if not isinstance(data, list):
        return []
    out: list[dict[str, int | str]] = []
    for top in data:
        if not isinstance(top, dict):
            continue
        pdfi = top.get("pdfid")
        if not isinstance(pdfi, dict):
            continue
        kwrap = pdfi.get("keywords")
        if not isinstance(kwrap, dict):
            continue
        klist = kwrap.get("keyword")
        if klist is None:
            continue
        if isinstance(klist, dict):
            klist = [klist]
        if not isinstance(klist, list):
            continue
        for kw in klist:
            if not isinstance(kw, dict):
                continue
            name = str(kw.get("name", ""))
            try:
                count = int(kw.get("count", 0))
            except (TypeError, ValueError):
                count = 0
            if name and count > 0:
                out.append({"name": name, "count": count})
    return out


@register
class PdfidScanner(BaseScanner):
    SCANNER_NAME = "pdfid"
    SUPPORTED_TYPES = {"application/pdf"}

    def scan(self, file_path: Path, file_type: str) -> ScanResult:
        findings: list[Finding] = []
        metadata: dict = {}

        try:
            for row in _iter_pdfid_keywords(file_path):
                kw_name = str(row.get("name", ""))
                count = int(row.get("count", 0))
                if count <= 0:
                    continue
                metadata[kw_name] = count
                if kw_name in _HIGH_RISK_KEYWORDS:
                    findings.append(
                        Finding(
                            rule=f"pdfid{kw_name.replace('/', '_')}",
                            description=f"PDF contains {kw_name} (count: {count})",
                            risk=RiskLevel.HIGH,
                            details={"keyword": kw_name, "count": count},
                        )
                    )
                elif kw_name in _MEDIUM_RISK_KEYWORDS:
                    findings.append(
                        Finding(
                            rule=f"pdfid{kw_name.replace('/', '_')}",
                            description=f"PDF contains {kw_name} (count: {count})",
                            risk=RiskLevel.MEDIUM,
                            details={"keyword": kw_name, "count": count},
                        )
                    )
                elif kw_name in _LOW_RISK_KEYWORDS:
                    findings.append(
                        Finding(
                            rule=f"pdfid{kw_name.replace('/', '_')}",
                            description=f"PDF contains {kw_name} (count: {count})",
                            risk=RiskLevel.LOW,
                            details={"keyword": kw_name, "count": count},
                        )
                    )
        except Exception as e:
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error=str(e),
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
