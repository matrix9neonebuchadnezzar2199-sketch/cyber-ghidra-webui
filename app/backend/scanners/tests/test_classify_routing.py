"""upload 分岐: classify_sample_pipeline が PDF/Office 等を Ghidra へ出さないこと。"""

from __future__ import annotations

from pathlib import Path

from sample_pipeline import classify_sample_pipeline


def test_pdf_magic_routes_static_even_without_extension(tmp_path: Path) -> None:
    p = tmp_path / "blob"
    p.write_bytes(b"%PDF-1.4\n%xref")
    assert classify_sample_pipeline(p) == "static_only"


def test_pdf_extension_routes_static(tmp_path: Path) -> None:
    p = tmp_path / "doc.PDF"
    p.write_bytes(b"not a real pdf for magic but ext ok")
    assert classify_sample_pipeline(p) == "static_only"
