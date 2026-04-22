"""API リクエスト/レスポンスの Pydantic モデル"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """POST /api/scan/{job_id} のリクエストボディ"""

    scanners: list[str] | None = Field(
        default=None,
        description="実行するスキャナー名リスト。null の場合はファイル種別に応じて自動選択",
    )


class FindingResponse(BaseModel):
    rule: str
    description: str
    risk: str
    details: dict[str, Any] = Field(default_factory=dict)


class ScannerResultResponse(BaseModel):
    scanner_name: str
    success: bool
    risk: str
    findings: list[FindingResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    elapsed_sec: float = 0.0


class ScanResponse(BaseModel):
    """スキャン結果の統合レスポンス"""

    job_id: str
    file_name: str
    file_type: str
    file_size: int
    hashes: dict[str, str]
    overall_risk: str
    scanners_run: int
    results: list[ScannerResultResponse]


class ScannerInfoResponse(BaseModel):
    """GET /api/scan/scanners のレスポンス要素"""

    name: str
    supported_types: list[str]
    match_all: bool
