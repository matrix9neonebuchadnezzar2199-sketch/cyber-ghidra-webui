"""
Androguard を使った Android APK の静的解析。
検出項目: 危険な権限、コンポーネント一覧、署名検証
"""

from __future__ import annotations

from pathlib import Path

from ..base import BaseScanner, Finding, RiskLevel, ScanResult
from ..registry import register

_APK_TYPES = {
    "application/vnd.android.package-archive",
    "application/zip",  # APK は ZIP ベース（file_type だけでは判定困難な場合あり）
}

# 悪意のある APK で頻出する危険な権限
_DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": RiskLevel.HIGH,
    "android.permission.READ_SMS": RiskLevel.HIGH,
    "android.permission.RECEIVE_SMS": RiskLevel.HIGH,
    "android.permission.CALL_PHONE": RiskLevel.HIGH,
    "android.permission.READ_CONTACTS": RiskLevel.MEDIUM,
    "android.permission.CAMERA": RiskLevel.MEDIUM,
    "android.permission.RECORD_AUDIO": RiskLevel.HIGH,
    "android.permission.ACCESS_FINE_LOCATION": RiskLevel.MEDIUM,
    "android.permission.READ_PHONE_STATE": RiskLevel.MEDIUM,
    "android.permission.RECEIVE_BOOT_COMPLETED": RiskLevel.LOW,
    "android.permission.SYSTEM_ALERT_WINDOW": RiskLevel.HIGH,
    "android.permission.REQUEST_INSTALL_PACKAGES": RiskLevel.HIGH,
    "android.permission.WRITE_SETTINGS": RiskLevel.MEDIUM,
}

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@register
class AndroguardScanner(BaseScanner):
    SCANNER_NAME = "androguard"
    SUPPORTED_TYPES = _APK_TYPES

    def scan(self, file_path: Path, file_type: str) -> ScanResult:
        # APK かどうかの追加判定（ZIP の場合は拡張子で確認）
        if file_type == "application/zip" and not file_path.suffix.lower() == ".apk":
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=True,
                risk=RiskLevel.SAFE,
                metadata={"skipped": "Not an APK file"},
            )

        findings: list[Finding] = []
        metadata: dict = {}

        try:
            from androguard.core.apk import APK  # type: ignore[import-untyped]

            apk = APK(str(file_path))
        except Exception as e:
            return ScanResult(
                scanner_name=self.SCANNER_NAME,
                success=False,
                error=f"APK parse error: {e}",
            )

        metadata["package_name"] = apk.get_package()
        metadata["app_name"] = apk.get_app_name()
        try:
            metadata["target_sdk"] = apk.get_target_sdk_version()
        except Exception:
            metadata["target_sdk"] = None
        try:
            metadata["min_sdk"] = apk.get_min_sdk_version()
        except Exception:
            metadata["min_sdk"] = None
        try:
            metadata["is_signed"] = apk.is_signed()
        except Exception:
            metadata["is_signed"] = None

        # 権限チェック
        permissions: list = []
        try:
            permissions = list(apk.get_permissions() or [])
        except Exception:
            pass
        metadata["permissions_count"] = len(permissions)
        metadata["permissions"] = permissions

        for perm in permissions:
            if perm in _DANGEROUS_PERMISSIONS:
                findings.append(
                    Finding(
                        rule=f"apk_dangerous_perm_{str(perm).split('.')[-1]}",
                        description=f"Dangerous permission: {perm}",
                        risk=_DANGEROUS_PERMISSIONS[perm],
                        details={"permission": perm},
                    )
                )

        # 複合判定: SMS + INTERNET + BOOT_COMPLETED → 非常に怪しい
        perm_set = set(permissions)
        sms_combo = {
            "android.permission.SEND_SMS",
            "android.permission.INTERNET",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        }
        if sms_combo.issubset(perm_set):
            findings.append(
                Finding(
                    rule="apk_sms_bot_combo",
                    description=(
                        "Suspicious combo: SEND_SMS + INTERNET + "
                        "RECEIVE_BOOT_COMPLETED (potential SMS bot)"
                    ),
                    risk=RiskLevel.CRITICAL,
                    details={"permissions": list(sms_combo)},
                )
            )

        # コンポーネント
        try:
            metadata["activities"] = (apk.get_activities() or [])[:20]
        except Exception:
            metadata["activities"] = []
        try:
            metadata["services"] = (apk.get_services() or [])[:20]
        except Exception:
            metadata["services"] = []
        try:
            metadata["receivers"] = (apk.get_receivers() or [])[:20]
        except Exception:
            metadata["receivers"] = []

        # 署名チェック
        try:
            if not apk.is_signed():
                findings.append(
                    Finding(
                        rule="apk_unsigned",
                        description="APK is not signed",
                        risk=RiskLevel.HIGH,
                        details={},
                    )
                )
        except Exception:
            pass

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
