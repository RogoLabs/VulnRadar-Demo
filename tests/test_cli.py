"""Unit tests for vulnradar.cli — CLI helper functions."""

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest

from vulnradar.cli import _default_min_year, _generate_demo_cve, _load_items, _years_to_process

# ── _default_min_year ────────────────────────────────────────────────────────


class TestDefaultMinYear:
    def test_returns_recent(self):
        result = _default_min_year()
        current = dt.datetime.now().year
        assert result == current - 4

    def test_returns_int(self):
        assert isinstance(_default_min_year(), int)


# ── _years_to_process ───────────────────────────────────────────────────────


class TestYearsToProcess:
    def test_normal_range(self):
        assert _years_to_process(2022, 2024) == [2022, 2023, 2024]

    def test_single_year(self):
        assert _years_to_process(2024, 2024) == [2024]

    def test_inverted(self):
        assert _years_to_process(2025, 2020) == []

    def test_none_max(self):
        result = _years_to_process(2020, None)
        assert dt.datetime.now().year in result
        assert 2020 in result


# ── _generate_demo_cve ──────────────────────────────────────────────────────


class TestGenerateDemoCve:
    def test_structure(self):
        cve = _generate_demo_cve()
        assert cve["cve_id"] == "CVE-2099-DEMO"
        assert cve["is_critical"] is True
        assert cve["active_threat"] is True
        assert cve["in_patchthis"] is True
        assert cve["cvss_score"] == 9.8

    def test_epss_in_range(self):
        cve = _generate_demo_cve()
        assert 0.85 <= cve["probability_score"] <= 1.0

    def test_kev_present(self):
        cve = _generate_demo_cve()
        assert "kev" in cve
        assert cve["kev"]["cveID"] == "CVE-2099-DEMO"

    def test_due_date_format(self):
        cve = _generate_demo_cve()
        due = cve["kev"]["dueDate"]
        # Should be a valid date string YYYY-MM-DD
        parts = due.split("-")
        assert len(parts) == 3
        assert int(parts[0]) >= 2024


# ── _load_items ──────────────────────────────────────────────────────────────


class TestLoadItems:
    def test_dict_with_items(self, tmp_path: Path):
        path = tmp_path / "data.json"
        path.write_text(json.dumps({"items": [{"cve_id": "CVE-2024-001"}], "count": 1}))
        result = _load_items(path)
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2024-001"

    def test_bare_list(self, tmp_path: Path):
        path = tmp_path / "data.json"
        path.write_text(json.dumps([{"cve_id": "CVE-2024-002"}]))
        result = _load_items(path)
        assert len(result) == 1

    def test_empty_items(self, tmp_path: Path):
        path = tmp_path / "data.json"
        path.write_text(json.dumps({"items": [], "count": 0}))
        result = _load_items(path)
        assert result == []

    def test_unexpected_structure(self, tmp_path: Path):
        path = tmp_path / "data.json"
        path.write_text(json.dumps({"foo": "bar"}))
        result = _load_items(path)
        assert result == []
