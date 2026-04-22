"""
ユーザーフロー: ジョブが queue/pending にある想定で /api/scan を叩く。
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> TestClient:
    from main import app

    return TestClient(app, raise_server_exceptions=True)


def test_get_scan_scanners_lists_plugins(client: TestClient) -> None:
    r = client.get("/api/scan/scanners")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list) and data
    names = {x["name"] for x in data}
    for n in ("pdfid", "binwalk", "oletools"):
        assert n in names
    for x in data:
        assert "supported_types" in x
        assert "match_all" in x


def test_post_scan_happy_path(
    client: TestClient,
    sample_pdf: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """queue/pending/{job_id}.json の filepath を参照してスキャンが走る。"""
    job_id = str(uuid.uuid4())
    qdir = tmp_path / "pending"
    qdir.mkdir(parents=True, exist_ok=True)
    (qdir / f"{job_id}.json").write_text(
        json.dumps(
            {
                "job_id": job_id,
                "filepath": str(sample_pdf),
                "project_name": "p_test",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "empty_proc").mkdir()
    (tmp_path / "empty_done").mkdir()
    out = tmp_path / "output"
    out.mkdir()
    in_dir = tmp_path / "input"
    in_dir.mkdir()

    monkeypatch.setattr("scanners.router.QUEUE_PENDING", qdir)
    monkeypatch.setattr("scanners.router.QUEUE_PROCESSING", tmp_path / "empty_proc")
    monkeypatch.setattr("scanners.router.QUEUE_DONE", tmp_path / "empty_done")
    monkeypatch.setattr("scanners.router.OUTPUT_DIR", out)
    monkeypatch.setattr("scanners.router.INPUT_DIR", in_dir)

    r = client.post(f"/api/scan/{job_id}", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["job_id"] == job_id
    assert "sha256" in body["hashes"]
    assert "results" in body
    assert any(x["scanner_name"] == "pdfid" for x in body["results"])


def test_post_scan_not_found(client: TestClient) -> None:
    jid = "00000000-0000-0000-0000-00000000beef"
    r = client.post(f"/api/scan/{jid}", json={})
    assert r.status_code == 404
    d = r.json().get("detail", "")
    assert d and jid in d and "/app/input" in d
