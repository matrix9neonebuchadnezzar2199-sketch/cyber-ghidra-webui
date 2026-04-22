"""ファイルの MIME タイプを判定。

python-magic (libmagic) を優先し、利用不可時は mimetypes にフォールバックする。
"""

import mimetypes
from pathlib import Path


def detect_file_type(file_path: Path) -> str:
    """ファイルの MIME タイプを返す (例: 'application/pdf')"""
    try:
        import magic  # type: ignore[import-untyped]

        return magic.Magic(mime=True).from_file(str(file_path))
    except Exception:
        t, _ = mimetypes.guess_type(str(file_path))
        return t or "application/octet-stream"
