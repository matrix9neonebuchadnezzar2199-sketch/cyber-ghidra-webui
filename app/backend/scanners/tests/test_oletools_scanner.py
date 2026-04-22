from scanners.plugins.oletools_scanner import OletoolsScanner


def test_oletools_docx_runs(sample_office):
    s = OletoolsScanner()
    r = s.scan(
        sample_office,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    assert r.success
    assert r.scanner_name == "oletools"
    assert "has_vba_macros" in (r.metadata or {})
