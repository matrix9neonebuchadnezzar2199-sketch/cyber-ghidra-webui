"""runner.determine_overall_risk の境界テスト。"""

from scanners.base import RiskLevel, ScanResult
from scanners.runner import determine_overall_risk


def test_determine_overall_risk_empty() -> None:
    assert determine_overall_risk([]) == RiskLevel.SAFE


def test_determine_overall_risk_takes_highest() -> None:
    results = [
        ScanResult("a", success=True, risk=RiskLevel.LOW),
        ScanResult("b", success=True, risk=RiskLevel.HIGH),
    ]
    assert determine_overall_risk(results) == RiskLevel.HIGH


def test_determine_overall_risk_ignores_failed() -> None:
    results = [
        ScanResult("a", success=False, risk=RiskLevel.CRITICAL, error="x"),
        ScanResult("b", success=True, risk=RiskLevel.LOW),
    ]
    assert determine_overall_risk(results) == RiskLevel.LOW
