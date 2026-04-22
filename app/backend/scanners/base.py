"""
全スキャナープラグインが継承する抽象基底クラス。
新しいスキャナーを追加する際はこのクラスを継承し、
SCANNER_NAME / SUPPORTED_TYPES / scan() を実装するだけで良い。
"""
from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """個別の検出結果"""

    rule: str  # 検出ルール名 (例: "VBA_Macro_AutoOpen")
    description: str  # 日本語 or 英語の説明
    risk: RiskLevel = RiskLevel.LOW
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """1スキャナーの実行結果"""

    scanner_name: str
    success: bool
    risk: RiskLevel = RiskLevel.SAFE
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    elapsed_sec: float = 0.0


class BaseScanner(abc.ABC):
    """
    プラグインスキャナーの抽象基底クラス。
    サブクラスは以下を実装すること:
      - SCANNER_NAME: str          (例: "oletools")
      - SUPPORTED_TYPES: set[str]  (例: {"application/msword", ...})
      - scan(file_path, file_type) -> ScanResult

    対応外のファイルは registry / runner 側でスキップされるため、
    各プラグイン内部でファイル種別チェックは不要。
    """

    SCANNER_NAME: str = ""
    SUPPORTED_TYPES: set[str] = set()
    # ワイルドカード: 全ファイル形式に対応する場合は True
    MATCH_ALL: bool = False

    @abc.abstractmethod
    def scan(self, file_path: Path, file_type: str) -> ScanResult:
        """
        ファイルを検査して ScanResult を返す。
        例外は内部で catch し、ScanResult(success=False, error=...) として返すこと。
        """
        ...

    def _timed_scan(self, file_path: Path, file_type: str) -> ScanResult:
        """runner から呼ばれるラッパー。実行時間を自動計測する。"""
        start = time.monotonic()
        try:
            result = self.scan(file_path, file_type)
        except Exception as e:
            result = ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error=f"{type(e).__name__}: {e}",
            )
        result.elapsed_sec = round(time.monotonic() - start, 3)
        result.scanner_name = self.SCANNER_NAME
        return result

    def accepts(self, file_type: str) -> bool:
        """このスキャナーが指定 MIME タイプを処理可能か判定"""
        if self.MATCH_ALL:
            return True
        return file_type in self.SUPPORTED_TYPES
