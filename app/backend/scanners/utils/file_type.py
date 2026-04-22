"""python-magic でファイルの MIME タイプを判定（libmagic 非利用環境は mimetypes にフォールバック）"""
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
