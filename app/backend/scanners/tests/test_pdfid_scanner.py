from scanners.plugins.pdfid_scanner import PdfidScanner


def test_pdfid_finds_suspicious_keywords(sample_pdf):
    s = PdfidScanner()
    r = s.scan(sample_pdf, "application/pdf")
    assert r.success
    # OpenAction または JavaScript 等が出る想定
    assert r.findings, "expected pdfid to emit findings for the crafted PDF"
    assert any("OpenAction" in f.description or "JavaScript" in f.description for f in r.findings)
