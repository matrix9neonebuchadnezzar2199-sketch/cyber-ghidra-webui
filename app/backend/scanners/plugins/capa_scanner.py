"""
Mandiant capa を使った実行ファイルの機能/振る舞い自動検出。
※ capa は CLI ラッパーとして呼び出す（Python API が安定していないため）。
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from ..base import BaseScanner, Finding, RiskLevel, ScanResult
from ..registry import register

logger = logging.getLogger(__name__)

_PE_ELF_TYPES = {
    "application/x-dosexec",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-elf",
    "application/x-pie-executable",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
}

# capa の ATT&CK タクティクスからリスクレベルへのマッピング
_TACTIC_RISK = {
    "defense-evasion": RiskLevel.HIGH,
    "credential-access": RiskLevel.CRITICAL,
    "exfiltration": RiskLevel.CRITICAL,
    "impact": RiskLevel.CRITICAL,
    "command-and-control": RiskLevel.HIGH,
    "execution": RiskLevel.HIGH,
    "persistence": RiskLevel.HIGH,
    "privilege-escalation": RiskLevel.HIGH,
    "lateral-movement": RiskLevel.HIGH,
    "discovery": RiskLevel.MEDIUM,
    "collection": RiskLevel.MEDIUM,
}

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@register
class CapaScanner(BaseScanner):
    SCANNER_NAME = "capa"
    SUPPORTED_TYPES = _PE_ELF_TYPES

    def scan(self, file_path: Path, file_type: str) -> ScanResult:
        findings: list[Finding] = []
        metadata: dict = {}

        try:
            proc = subprocess.run(
                ["capa", "--json", str(file_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError:
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error="capa binary not found in PATH. Install: pip install flare-capa",
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error="capa timed out (>300s)",
            )

        if proc.returncode != 0:
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error=f"capa exited with code {proc.returncode}: {proc.stderr[:500]}",
            )

        try:
            capa_result = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error=f"Failed to parse capa JSON: {e}",
            )

        rules = capa_result.get("rules", {})
        metadata["capabilities_count"] = len(rules) if isinstance(rules, dict) else 0

        if not isinstance(rules, dict):
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=True,
                risk=RiskLevel.SAFE,
                findings=findings,
                metadata=metadata,
            )

        for rule_name, rule_data in rules.items():
            if not isinstance(rule_data, dict):
                continue
            rule_meta = rule_data.get("meta", {})
            if not isinstance(rule_meta, dict):
                rule_meta = {}
            attack = rule_meta.get("att&ck", [])

            # タクティクスからリスク判定
            risk = RiskLevel.LOW
            tactics: list[str] = []
            for entry in attack or []:
                if isinstance(entry, dict):
                    tactic = str(entry.get("tactic", "")).lower()
                elif isinstance(entry, str):
                    tactic = entry.split("::", 1)[0].lower() if "::" in entry else entry.lower()
                else:
                    continue
                if tactic:
                    tactics.append(tactic)
                mapped = _TACTIC_RISK.get(tactic, RiskLevel.LOW)
                if _RISK_ORD.get(mapped.value, 0) > _RISK_ORD.get(risk.value, 0):
                    risk = mapped

            details_scopes = rule_meta.get("scopes", {})
            if not isinstance(details_scopes, dict):
                details_scopes = {}

            findings.append(
                Finding(
                    rule=f"capa_{rule_name}",
                    description=str(rule_meta.get("description", rule_name)),
                    risk=risk,
                    details={
                        "namespace": str(rule_meta.get("namespace", "")),
                        "tactics": tactics,
                        "scopes": details_scopes,
                    },
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
