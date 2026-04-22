from scanners.runner import run_scan


def test_run_scan_pdf(sample_pdf):
    file_type, hashes, results = run_scan(sample_pdf)
    assert "sha256" in hashes
    assert len(results) >= 1
    assert any(r.scanner_name == "pdfid" for r in results)
    assert any(r.scanner_name == "binwalk" for r in results)
