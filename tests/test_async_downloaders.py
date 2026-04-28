"""Unit tests for vulnradar.async_downloaders — parallel download orchestrator."""

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnradar.async_downloaders import (
    DownloadResults,
    _auth_headers,
    _download_epss,
    _download_kev,
    _download_patchthis,
    _resolve_cvelist_url,
    download_all_parallel,
    download_and_extract_zip,
)

# ── _auth_headers ────────────────────────────────────────────────────────────


class TestAuthHeaders:
    def test_default_headers(self):
        with patch.dict(os.environ, {}, clear=True):
            headers = _auth_headers()
            assert "VulnRadar" in headers["User-Agent"]
            assert headers["Accept"] == "application/json"
            assert "Authorization" not in headers

    @patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_test"})
    def test_github_token(self):
        headers = _auth_headers()
        assert headers["Authorization"] == "Bearer ghp_test"

    @patch.dict(os.environ, {"GH_TOKEN": "ghp_gh"}, clear=False)
    def test_gh_token_fallback(self):
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
        with patch.dict(os.environ, env, clear=True):
            headers = _auth_headers()
            assert headers["Authorization"] == "Bearer ghp_gh"


# ── DownloadResults ──────────────────────────────────────────────────────────


class TestDownloadResults:
    def test_defaults(self):
        r = DownloadResults()
        assert r.kev_by_cve == {}
        assert r.epss_by_cve == {}
        assert r.patchthis_cves == set()
        assert r.nvd_by_cve == {}
        assert r.zip_bytes == b""
        assert r.errors == []

    def test_populated(self):
        r = DownloadResults(
            kev_by_cve={"CVE-2024-001": {}},
            epss_by_cve={"CVE-2024-001": 0.85},
            patchthis_cves={"CVE-2024-001"},
            zip_bytes=b"pk",
            errors=["test error"],
        )
        assert len(r.kev_by_cve) == 1
        assert len(r.errors) == 1


# ── Async download functions (via mock sessions) ────────────────────────────


class TestAsyncKev:
    def test_parses_kev(self):
        mock_resp = AsyncMock()
        mock_resp.json = AsyncMock(
            return_value={
                "vulnerabilities": [
                    {"cveID": "CVE-2024-12345", "vendorProject": "Apache"},
                    {"cveID": "not-valid"},
                ]
            }
        )
        mock_resp.raise_for_status = MagicMock()

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncContextManager(mock_resp))

        result = asyncio.run(_download_kev(mock_session))
        assert "CVE-2024-12345" in result
        assert len(result) == 1


class TestAsyncEpss:
    def test_parses_epss(self):
        import csv
        import gzip
        import io

        buf = io.StringIO()
        buf.write("# comment\n")
        writer = csv.writer(buf)
        writer.writerow(["cve", "epss", "percentile"])
        writer.writerow(["CVE-2024-001", "0.85", "0.95"])
        raw = buf.getvalue().encode()
        gz_buf = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buf, mode="wb") as gz:
            gz.write(raw)
        gz_bytes = gz_buf.getvalue()

        mock_resp = AsyncMock()
        mock_resp.read = AsyncMock(return_value=gz_bytes)
        mock_resp.raise_for_status = MagicMock()

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncContextManager(mock_resp))

        result = asyncio.run(_download_epss(mock_session))
        assert result["CVE-2024-001"] == pytest.approx(0.85)


class TestAsyncPatchthis:
    def test_parses_cves(self):
        import csv
        import io

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["cveID", "desc"])
        writer.writeheader()
        writer.writerow({"cveID": "CVE-2024-11111", "desc": "test"})
        raw = buf.getvalue().encode()

        mock_resp = AsyncMock()
        mock_resp.read = AsyncMock(return_value=raw)
        mock_resp.raise_for_status = MagicMock()

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncContextManager(mock_resp))

        result = asyncio.run(_download_patchthis(mock_session))
        assert "CVE-2024-11111" in result


class TestAsyncCvelistUrl:
    def test_resolves_url(self):
        mock_resp = AsyncMock()
        mock_resp.json = AsyncMock(
            return_value={
                "assets": [
                    {
                        "name": "2024-06-15_all_CVEs_at_midnight.zip",
                        "browser_download_url": "https://example.com/cves.zip",
                    }
                ]
            }
        )
        mock_resp.raise_for_status = MagicMock()

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncContextManager(mock_resp))

        url = asyncio.run(_resolve_cvelist_url(mock_session))
        assert url == "https://example.com/cves.zip"


# ── Helper for async context manager mocking ────────────────────────────────


class AsyncContextManager:
    """Wraps an async mock to support `async with session.get(url) as resp:`."""

    def __init__(self, mock_resp):
        self.mock_resp = mock_resp

    async def __aenter__(self):
        return self.mock_resp

    async def __aexit__(self, *args):
        pass


# ── download_and_extract_zip (re-exported) ──────────────────────────────────


class TestDownloadAndExtractZip:
    def test_basic_zip(self):
        import io
        import shutil
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("test.txt", "hello")
        out = download_and_extract_zip(buf.getvalue())
        try:
            assert (out / "test.txt").read_text() == "hello"
        finally:
            shutil.rmtree(out, ignore_errors=True)
