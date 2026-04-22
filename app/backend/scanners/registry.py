"""
scanners/plugins/ 配下の全モジュールを自動インポートし、
BaseScanner のサブクラスを自動登録するレジストリ。
新しいプラグインは plugins/ にファイルを置くだけで認識される。
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import BaseScanner

logger = logging.getLogger(__name__)

_registry: dict[str, BaseScanner] = {}
_plugins_discovered: bool = False


def _discover_plugins() -> None:
    """plugins パッケージ内の全モジュールを動的にインポート"""
    plugins_pkg = importlib.import_module(".plugins", package=__package__)
    plugins_path = Path(plugins_pkg.__file__ or ".").parent

    for _finder, name, _ in pkgutil.iter_modules([str(plugins_path)]):
        try:
            importlib.import_module(f".plugins.{name}", package=__package__)
            logger.info("Loaded scanner plugin: %s", name)
        except Exception:
            logger.exception("Failed to load scanner plugin: %s", name)


def register(scanner_cls: type[BaseScanner]) -> type[BaseScanner]:
    """
    クラスデコレータ。プラグインのクラス定義に @register を付けると自動登録される。

    使用例:
        @register
        class OletoolsScanner(BaseScanner):
            ...
    """
    instance = scanner_cls()
    name = instance.SCANNER_NAME
    if not name:
        raise ValueError(f"{scanner_cls.__name__} に SCANNER_NAME が未設定")
    if name in _registry:
        logger.warning("Scanner '%s' is already registered, overwriting.", name)
    _registry[name] = instance
    logger.info("Registered scanner: %s", name)
    return scanner_cls


def _ensure_plugins_discovered() -> None:
    global _plugins_discovered
    if not _plugins_discovered:
        _discover_plugins()
        _plugins_discovered = True


def get_all_scanners() -> dict[str, BaseScanner]:
    """登録済み全スキャナーを返す"""
    _ensure_plugins_discovered()
    return dict(_registry)


def get_scanners_for_type(file_type: str) -> list[BaseScanner]:
    """指定 MIME タイプに対応するスキャナー一覧を返す"""
    _ensure_plugins_discovered()
    return [s for s in _registry.values() if s.accepts(file_type)]


def get_scanner(name: str) -> BaseScanner | None:
    """名前指定でスキャナーを取得"""
    _ensure_plugins_discovered()
    return _registry.get(name)
