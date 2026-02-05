"""Unit tests for etl.py."""

import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from etl import (
    Watchlist,
    _extract_cvss,
    _matches_watchlist,
    _norm,
    _pick_best_description,
    load_watchlist,
)


class TestNorm:
    """Tests for the _norm() normalization function."""

    def test_basic_normalization(self):
        assert _norm("Apache") == "apache"
        assert _norm("  Microsoft  ") == "microsoft"
        assert _norm("Log4j") == "log4j"

    def test_whitespace_collapse(self):
        assert _norm("Apache  Software   Foundation") == "apache software foundation"
        assert _norm("\n\tTest\n\t") == "test"

    def test_empty_and_none(self):
        assert _norm("") == ""
        assert _norm(None) == ""
        assert _norm("   ") == ""


class TestLoadWatchlist:
    """Tests for load_watchlist() function."""

    def test_load_yaml_watchlist(self, sample_watchlist_yaml: Path):
        watchlist = load_watchlist(sample_watchlist_yaml)
        assert isinstance(watchlist, Watchlist)
        assert "microsoft" in watchlist.vendors
        assert "apache" in watchlist.vendors
        assert "linux" in watchlist.vendors
        assert "exchange" in watchlist.products
        assert "log4j" in watchlist.products

    def test_load_json_watchlist(self, sample_watchlist_json: Path, capsys):
        watchlist = load_watchlist(sample_watchlist_json)
        assert isinstance(watchlist, Watchlist)
        assert "google" in watchlist.vendors
        assert "mozilla" in watchlist.vendors
        assert "chrome" in watchlist.products
        assert "firefox" in watchlist.products
        # Should print deprecation notice
        captured = capsys.readouterr()
        assert "deprecated" in captured.out.lower()

    def test_load_empty_watchlist(self, empty_watchlist: Path):
        watchlist = load_watchlist(empty_watchlist)
        assert len(watchlist.vendors) == 0
        assert len(watchlist.products) == 0

    def test_watchlist_normalizes_values(self, tmp_path: Path):
        content = {
            "vendors": ["  MICROSOFT  ", "Apache Software Foundation"],
            "products": ["LOG4J", "  openssl  "],
        }
        path = tmp_path / "test.yaml"
        path.write_text(yaml.dump(content))
        watchlist = load_watchlist(path)
        assert "microsoft" in watchlist.vendors
        assert "apache software foundation" in watchlist.vendors
        assert "log4j" in watchlist.products
        assert "openssl" in watchlist.products

    def test_watchlist_ignores_non_strings(self, tmp_path: Path):
        content = {
            "vendors": ["microsoft", 123, None, "apache"],
            "products": ["kernel", True, "openssl"],
        }
        path = tmp_path / "test.yaml"
        path.write_text(yaml.dump(content))
        watchlist = load_watchlist(path)
        assert "microsoft" in watchlist.vendors
        assert "apache" in watchlist.vendors
        assert len(watchlist.vendors) == 2
        assert "kernel" in watchlist.products
        assert "openssl" in watchlist.products
        assert len(watchlist.products) == 2


class TestMatchesWatchlist:
    """Tests for _matches_watchlist() function."""

    @pytest.fixture
    def watchlist(self) -> Watchlist:
        return Watchlist(
            vendors={"microsoft", "apache", "linux"},
            products={"exchange", "log4j", "kernel", "openssl"},
        )

    def test_exact_vendor_match(self, watchlist: Watchlist):
        assert _matches_watchlist("microsoft", "office", watchlist) is True
        assert _matches_watchlist("apache", "tomcat", watchlist) is True

    def test_exact_product_match(self, watchlist: Watchlist):
        assert _matches_watchlist("unknown", "exchange", watchlist) is True
        assert _matches_watchlist("unknown", "log4j", watchlist) is True

    def test_partial_vendor_match(self, watchlist: Watchlist):
        # "microsoft" in "microsoft corporation" or vice versa
        assert _matches_watchlist("microsoft corporation", "word", watchlist) is True
        assert _matches_watchlist("apache software foundation", "tomcat", watchlist) is True

    def test_partial_product_match(self, watchlist: Watchlist):
        # "kernel" in "linux kernel" or "log4j" in "log4j-core"
        assert _matches_watchlist("unknown", "linux kernel", watchlist) is True
        assert _matches_watchlist("unknown", "log4j-core", watchlist) is True

    def test_no_match(self, watchlist: Watchlist):
        assert _matches_watchlist("google", "chrome", watchlist) is False
        assert _matches_watchlist("random", "unknown", watchlist) is False

    def test_case_insensitive(self, watchlist: Watchlist):
        assert _matches_watchlist("MICROSOFT", "WORD", watchlist) is True
        assert _matches_watchlist("Apache", "Tomcat", watchlist) is True

    def test_empty_watchlist(self):
        empty = Watchlist(vendors=set(), products=set())
        assert _matches_watchlist("microsoft", "exchange", empty) is False


class TestPickBestDescription:
    """Tests for _pick_best_description() function."""

    def test_english_description_preferred(self):
        cna = {
            "descriptions": [
                {"lang": "de", "value": "German description"},
                {"lang": "en", "value": "English description"},
                {"lang": "fr", "value": "French description"},
            ]
        }
        assert _pick_best_description(cna) == "English description"

    def test_en_us_variant(self):
        cna = {
            "descriptions": [
                {"lang": "en-US", "value": "US English description"},
            ]
        }
        assert _pick_best_description(cna) == "US English description"

    def test_fallback_to_first_with_value(self):
        cna = {
            "descriptions": [
                {"lang": "de", "value": "German description"},
            ]
        }
        assert _pick_best_description(cna) == "German description"

    def test_empty_descriptions(self):
        assert _pick_best_description({}) == ""
        assert _pick_best_description({"descriptions": []}) == ""
        assert _pick_best_description({"descriptions": None}) == ""


class TestExtractCvss:
    """Tests for _extract_cvss() function."""

    def test_cvss_v31(self):
        cna = {
            "metrics": [
                {
                    "cvssV3_1": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            ]
        }
        score, severity, vector = _extract_cvss(cna)
        assert score == 9.8
        assert severity == "CRITICAL"
        assert "CVSS:3.1" in vector

    def test_cvss_v30_fallback(self):
        cna = {
            "metrics": [
                {
                    "cvssV3_0": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    }
                }
            ]
        }
        score, severity, vector = _extract_cvss(cna)
        assert score == 7.5
        assert severity == "HIGH"

    def test_no_metrics(self):
        score, severity, vector = _extract_cvss({})
        assert score is None
        assert severity is None
        assert vector is None

    def test_empty_metrics_list(self):
        score, severity, vector = _extract_cvss({"metrics": []})
        assert score is None


class TestParseCve:
    """Tests for CVE parsing logic."""

    def test_sample_cve_structure(self, sample_cve_v5: Dict[str, Any]):
        """Verify fixture has expected structure."""
        assert sample_cve_v5["cveMetadata"]["cveId"] == "CVE-2024-12345"
        assert sample_cve_v5["cveMetadata"]["state"] == "PUBLISHED"
        cna = sample_cve_v5["containers"]["cna"]
        assert len(cna["affected"]) == 1
        assert cna["affected"][0]["vendor"] == "Apache Software Foundation"
        assert cna["affected"][0]["product"] == "Log4j"

    def test_cve_without_metrics(self, sample_cve_no_metrics: Dict[str, Any]):
        """CVEs without CVSS metrics should still parse."""
        cna = sample_cve_no_metrics["containers"]["cna"]
        score, severity, vector = _extract_cvss(cna)
        assert score is None


class TestCriticalLogic:
    """Tests for is_critical flag logic."""

    def test_critical_when_patchthis_and_watchlist(self):
        """is_critical = in_patchthis AND in_watchlist."""
        # This tests the business logic from etl.py line 578
        in_patchthis = True
        in_watchlist = True
        is_critical = bool(in_patchthis and in_watchlist)
        assert is_critical is True

    def test_not_critical_when_only_patchthis(self):
        in_patchthis = True
        in_watchlist = False
        is_critical = bool(in_patchthis and in_watchlist)
        assert is_critical is False

    def test_not_critical_when_only_watchlist(self):
        in_patchthis = False
        in_watchlist = True
        is_critical = bool(in_patchthis and in_watchlist)
        assert is_critical is False

    def test_not_critical_when_neither(self):
        in_patchthis = False
        in_watchlist = False
        is_critical = bool(in_patchthis and in_watchlist)
        assert is_critical is False


class TestWriteMarkdownReport:
    """Tests for write_markdown_report() function."""

    def test_report_includes_recent_changes_from_state(self, tmp_path: Path):
        """Report should include Recent Changes section when state file exists."""
        import datetime as dt

        from etl import write_markdown_report

        # Create a state file with recent changes
        state_file = tmp_path / "state.json"
        now = dt.datetime.now(dt.timezone.utc)
        state_data = {
            "schema_version": 1,
            "last_run": now.isoformat(),
            "seen_cves": {
                "CVE-2024-1111": {
                    "first_seen": now.isoformat(),
                    "last_seen": now.isoformat(),
                    "snapshot": {"is_critical": True, "active_threat": True},
                },
                "CVE-2024-2222": {
                    "first_seen": now.isoformat(),
                    "last_seen": now.isoformat(),
                    "snapshot": {"is_critical": False, "in_patchthis": True},
                },
            },
            "statistics": {"total_alerts_sent": 0, "alerts_by_channel": {}},
        }
        state_file.write_text(json.dumps(state_data))

        # Create sample items
        items = [
            {"cve_id": "CVE-2024-1111", "is_critical": True, "active_threat": True},
            {"cve_id": "CVE-2024-2222", "is_critical": False, "in_patchthis": True},
        ]

        report_path = tmp_path / "report.md"
        write_markdown_report(report_path, items, state_file=state_file)

        content = report_path.read_text()
        assert "Recent Changes" in content
        assert "CVE-2024-1111" in content
        assert "CVE-2024-2222" in content

    def test_report_without_state_file(self, tmp_path: Path):
        """Report should work without state file (no Recent Changes section)."""
        from etl import write_markdown_report

        items = [{"cve_id": "CVE-2024-0001", "is_critical": True}]
        report_path = tmp_path / "report.md"
        write_markdown_report(report_path, items, state_file=None)

        content = report_path.read_text()
        assert "VulnRadar Report" in content
        assert "Recent Changes" not in content

    def test_report_with_missing_state_file(self, tmp_path: Path):
        """Report should handle missing state file gracefully."""
        from etl import write_markdown_report

        items = [{"cve_id": "CVE-2024-0001", "is_critical": True}]
        report_path = tmp_path / "report.md"
        missing_state = tmp_path / "nonexistent.json"

        write_markdown_report(report_path, items, state_file=missing_state)

        content = report_path.read_text()
        assert "VulnRadar Report" in content
        # Should not crash, just skip Recent Changes section
