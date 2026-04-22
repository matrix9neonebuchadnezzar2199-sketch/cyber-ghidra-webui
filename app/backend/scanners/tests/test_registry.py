from scanners.registry import get_all_scanners, get_scanners_for_type


def test_all_scanners_loaded():
    """プラグインが 1 つ以上登録されていること"""
    scanners = get_all_scanners()
    assert len(scanners) >= 6  # yara はスタブなので除外


def test_pdf_scanners():
    scanners = get_scanners_for_type("application/pdf")
    names = {s.SCANNER_NAME for s in scanners}
    assert "pdfid" in names
    assert "binwalk" in names


def test_pe_scanners():
    scanners = get_scanners_for_type("application/x-dosexec")
    names = {s.SCANNER_NAME for s in scanners}
    assert "pefile" in names
    assert "lief" in names
    assert "capa" in names
    assert "binwalk" in names
