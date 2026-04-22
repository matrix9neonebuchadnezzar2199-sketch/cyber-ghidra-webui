"""
アップロードされたファイルに対して該当するスキャナーを実行し、
結果を統合して返すオーケストレーター。
"""

from __future__ import annotations

import logging
from pathlib import Path

from .base import RiskLevel, ScanResult
from .registry import get_scanner, get_scanners_for_type
from .utils.file_type import detect_file_type
from .utils.hash_calc import compute_hashes

logger = logging.getLogger(__name__)

# リスクレベルの優先度（高いほど深刻）
_RISK_PRIORITY = {
    RiskLevel.SAFE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def determine_overall_risk(results: list[ScanResult]) -> RiskLevel:
    """全スキャナー結果のうち最も高いリスクを返す"""
    if not results:
        return RiskLevel.SAFE
    risks = [r.risk for r in results if r.success]
    if not risks:
        return RiskLevel.SAFE
    return max(risks, key=lambda x: _RISK_PRIORITY.get(x, 0), default=RiskLevel.SAFE)


def run_scan(
    file_path: Path,
    scanner_names: list[str] | None = None,
) -> tuple[str, dict[str, str], list[ScanResult]]:
    """
    Parameters
    ----------
    file_path : Path
        検査対象ファイルのパス（Docker Volume 内）
    scanner_names : list[str] | None
        実行するスキャナー名リスト。None ならファイル種別で自動選択。

    Returns
    -------
    (file_type, hashes, results)
    """
    file_type = detect_file_type(file_path)
    hashes = compute_hashes(file_path)

    if scanner_names:
        # 明示指定: 指定名のスキャナーのみ実行
        scanners = []
        for name in scanner_names:
            s = get_scanner(name)
            if s is None:
                logger.warning("Unknown scanner requested: %s", name)
                continue
            scanners.append(s)
    else:
        # 自動選択: ファイル種別に対応するスキャナー全て
        scanners = get_scanners_for_type(file_type)

    logger.info(
        "Running %d scanners on %s (type=%s)",
        len(scanners),
        file_path.name,
        file_type,
    )

    results: list[ScanResult] = []
    for scanner in scanners:
        logger.info("  → %s", scanner.SCANNER_NAME)
        result = scanner._timed_scan(file_path, file_type)
        results.append(result)

    return file_type, hashes, results
