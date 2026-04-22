"""
YARA スキャナー: 後日実装予定のスタブ。
実装時は yara-python をインストールし、以下の TODO を埋めること。
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..base import BaseScanner, ScanResult

# ★ 注意: @register を付けていないため、現時点では無効
# from ..registry import register

logger = logging.getLogger(__name__)


# @register   # ← YARA 実装時にコメント解除
class YaraScanner(BaseScanner):
    SCANNER_NAME = "yara"
    MATCH_ALL = True  # 全ファイル形式に対応

    def scan(self, file_path: Path, file_type: str) -> ScanResult:
        # TODO: yara-python を使ったルールマッチング実装
        # 1. YARA_RULES_DIR 環境変数からルールディレクトリを取得
        # 2. ルールをコンパイル (yara.compile)
        # 3. file_path に対してマッチング
        # 4. マッチしたルールを Finding に変換
        return ScanResult(
            scanner_name=self.SCANNER_NAME,
            success=False,
            error="YARA scanner is not yet implemented",
        )
