"""Unit tests for vulnradar.downloaders — HTTP download helpers."""

import csv
import gzip
import io
import json
import os
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulnradar.downloaders import (
    download_and_extract_zip,
    download_cisa_kev,
    download_epss,
    download_patchthis,
    get_latest_cvelist_zip_url,
    requests_session,
)

# ── requests_session ─────────────────────────────────────────────────────────


class TestRequestsSession:
    def test_user_agent(self):
        s = requests_session()
        assert "VulnRadar" in s.headers["User-Agent"]

    def test_accept_json(self):
        s = requests_session()
        assert s.headers["Accept"] == "application/json"

    @patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_test123"})
    def test_github_token(self):
        s = requests_session()
        assert s.headers["Authorization"] == "Bearer ghp_test123"

    @patch.dict(os.environ, {"GH_TOKEN": "ghp_gh456"}, clear=False)
    def test_gh_token_fallback(self):
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
        with patch.dict(os.environ, env, clear=True):
            s = requests_session()
            assert s.headers["Authorization"] == "Bearer ghp_gh456"

    @patch.dict(os.environ, {}, clear=True)
    def test_no_token(self):
        s = requests_session()
        assert "Authorization" not in s.headers


# ── get_latest_cvelist_zip_url ───────────────────────────────────────────────


class TestGetLatestCvelistZipUrl:
    def test_resolves_url(self):
        mock_session = MagicMock()
        mock_session.get.return_value.json.return_value = {
            "assets": [
                {
                    "name": "2024-06-15_all_CVEs_at_midnight.zip",
                    "browser_download_url": "https://example.com/cves.zip",
                }
            ]
        }
        mock_session.get.return_value.raise_for_status = MagicMock()
        url = get_latest_cvelist_zip_url(mock_session)
        assert url == "https://example.com/cves.zip"

    def test_no_matching_asset_raises(self):
        """Raises when neither latest nor recent releases have a midnight zip."""
        no_midnight = MagicMock()
        no_midnight.json.return_value = {
            "assets": [{"name": "random.txt", "browser_download_url": "https://x.com/r.txt"}]
        }
        no_midnight.raise_for_status = MagicMock()

        # Second call returns a list of releases, also without midnight zips
        releases_resp = MagicMock()
        releases_resp.json.return_value = [
            {"assets": [{"name": "delta.zip", "browser_download_url": "https://x.com/d.zip"}]},
        ]
        releases_resp.raise_for_status = MagicMock()

        mock_session = MagicMock()
        mock_session.get.side_effect = [no_midnight, releases_resp]
        with pytest.raises(RuntimeError, match="Could not find"):
            get_latest_cvelist_zip_url(mock_session)

    def test_double_zip_suffix(self):
        mock_session = MagicMock()
        mock_session.get.return_value.json.return_value = {
            "assets": [
                {
                    "name": "2024_all_CVEs_at_midnight.zip.zip",
                    "browser_download_url": "https://example.com/double.zip",
                }
            ]
        }
        mock_session.get.return_value.raise_for_status = MagicMock()
        url = get_latest_cvelist_zip_url(mock_session)
        assert url == "https://example.com/double.zip"

    def test_fallback_to_recent_releases(self):
        """When 'latest' is an at_end_of_day release (no midnight zip),
        fall back to searching recent releases."""
        # First call: /releases/latest returns the at_end_of_day release
        latest_resp = MagicMock()
        latest_resp.json.return_value = {
            "assets": [
                {
                    "name": "2026-02-26_delta_CVEs_at_end_of_day.zip",
                    "browser_download_url": "https://example.com/eod.zip",
                },
                {
                    "name": "release_notes.md",
                    "browser_download_url": "https://example.com/notes.md",
                },
            ]
        }
        latest_resp.raise_for_status = MagicMock()

        # Second call: /releases?per_page=5 returns several releases
        releases_resp = MagicMock()
        releases_resp.json.return_value = [
            {
                "assets": [
                    {
                        "name": "2026-02-26_delta_CVEs_at_end_of_day.zip",
                        "browser_download_url": "https://example.com/eod.zip",
                    },
                ]
            },
            {
                "assets": [
                    {
                        "name": "2026-02-26_all_CVEs_at_midnight.zip.zip",
                        "browser_download_url": "https://example.com/midnight.zip",
                    },
                    {
                        "name": "2026-02-26_delta_CVEs_at_0000Z.zip",
                        "browser_download_url": "https://example.com/delta.zip",
                    },
                ]
            },
        ]
        releases_resp.raise_for_status = MagicMock()

        mock_session = MagicMock()
        mock_session.get.side_effect = [latest_resp, releases_resp]

        url = get_latest_cvelist_zip_url(mock_session)
        assert url == "https://example.com/midnight.zip"


# ── download_and_extract_zip ─────────────────────────────────────────────────


class TestDownloadAndExtractZip:
    def _make_zip_bytes(self, files: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return buf.getvalue()

    def test_simple_zip(self):
        zb = self._make_zip_bytes({"hello.txt": b"world"})
        out = download_and_extract_zip(zb)
        try:
            assert (out / "hello.txt").read_text() == "world"
        finally:
            import shutil

            shutil.rmtree(out, ignore_errors=True)

    def test_nested_cves_zip(self):
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as inner:
            inner.writestr("cves/2024/10xxx/CVE-2024-10001.json", '{"id": 1}')
        inner_bytes = inner_buf.getvalue()

        outer = self._make_zip_bytes({"cves.zip": inner_bytes})
        out = download_and_extract_zip(outer)
        try:
            assert (out / "cves" / "2024" / "10xxx" / "CVE-2024-10001.json").exists()
        finally:
            import shutil

            shutil.rmtree(out, ignore_errors=True)


# ── download_cisa_kev ────────────────────────────────────────────────────────


class TestDownloadCisaKev:
    def test_parses_kev(self):
        mock_session = MagicMock()
        mock_session.get.return_value.json.return_value = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-12345", "vendorProject": "Apache"},
                {"cveID": "CVE-2024-67890", "vendorProject": "Microsoft"},
                {"cveID": "not-valid"},
            ]
        }
        mock_session.get.return_value.raise_for_status = MagicMock()
        result = download_cisa_kev(mock_session)
        assert "CVE-2024-12345" in result
        assert "CVE-2024-67890" in result
        assert len(result) == 2

    def test_empty_list(self):
        mock_session = MagicMock()
        mock_session.get.return_value.json.return_value = {"vulnerabilities": []}
        mock_session.get.return_value.raise_for_status = MagicMock()
        assert download_cisa_kev(mock_session) == {}


# ── download_epss ────────────────────────────────────────────────────────────


class TestDownloadEpss:
    def _make_epss_gz(self, rows: list[tuple[str, str]]) -> bytes:
        buf = io.StringIO()
        buf.write("# comment line\n")
        writer = csv.writer(buf)
        writer.writerow(["cve", "epss", "percentile"])
        for cve, score in rows:
            writer.writerow([cve, score, "0.9"])
        raw = buf.getvalue().encode()
        gz_buf = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buf, mode="wb") as gz:
            gz.write(raw)
        return gz_buf.getvalue()

    def test_parses_scores(self):
        gz = self._make_epss_gz(
            [
                ("CVE-2024-12345", "0.85"),
                ("CVE-2024-67890", "0.12"),
            ]
        )
        mock_session = MagicMock()
        # download_bytes is called internally with retry; mock the session.get
        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [gz]
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_session.get.return_value = mock_resp

        result = download_epss(mock_session)
        assert result["CVE-2024-12345"] == pytest.approx(0.85)
        assert result["CVE-2024-67890"] == pytest.approx(0.12)


# ── download_patchthis ───────────────────────────────────────────────────────


class TestDownloadPatchthis:
    def _make_csv_bytes(self, col_name: str = "cveID") -> bytes:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=[col_name, "description"])
        writer.writeheader()
        writer.writerow({col_name: "CVE-2024-11111", "description": "Exploit A"})
        writer.writerow({col_name: "CVE-2024-22222", "description": "Exploit B"})
        return buf.getvalue().encode()

    def test_parses_cves(self):
        raw = self._make_csv_bytes("cveID")
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [raw]
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_session.get.return_value = mock_resp

        result = download_patchthis(mock_session)
        assert "CVE-2024-11111" in result
        assert "CVE-2024-22222" in result

    def test_alternate_column_names(self):
        raw = self._make_csv_bytes("cve")
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [raw]
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_session.get.return_value = mock_resp

        result = download_patchthis(mock_session)
        assert len(result) == 2

    def test_missing_column_raises(self):
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["id", "desc"])
        writer.writeheader()
        writer.writerow({"id": "1", "desc": "x"})
        raw = buf.getvalue().encode()

        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [raw]
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_session.get.return_value = mock_resp

        with pytest.raises(RuntimeError, match="missing a CVE identifier"):
            download_patchthis(mock_session)
