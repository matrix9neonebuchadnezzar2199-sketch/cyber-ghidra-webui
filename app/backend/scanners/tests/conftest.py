import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_pe(tmp_path: Path) -> Path:
    """最小限の MZ ヘッダを持つダミー PE（解析失敗想定可）"""
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(
        b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00" + b"\x00" * 200
    )
    return pe_file


@pytest.fixture
def sample_pdf(tmp_path: Path) -> Path:
    """pdfid が検出可能なキーワードを含むダミー PDF"""
    pdf_file = tmp_path / "test.pdf"
    pdf_file.write_text(
        "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
        "3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert\\('test'\\)) >>\nendobj\n"
        "xref\n0 4\ntrailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF",
        encoding="utf-8",
    )
    return pdf_file


@pytest.fixture
def sample_office(tmp_path: Path) -> Path:
    """空の DOCX（最小 ZIP）"""
    docx = tmp_path / "test.docx"
    with zipfile.ZipFile(docx, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>',
        )
    return docx
