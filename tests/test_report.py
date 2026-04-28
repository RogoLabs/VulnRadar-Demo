"""Unit tests for vulnradar.report — Jinja2 template-based report generation."""

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest

from vulnradar.report import _build_recent_changes, write_markdown_report

# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_item(
    cve_id: str = "CVE-2024-00001",
    cvss: float = 7.5,
    epss: float = 0.5,
    active_threat: bool = False,
    in_patchthis: bool = False,
    watchlist_hit: bool = True,
    is_critical: bool = False,
) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "description": f"Test vuln {cve_id}",
        "cvss_score": cvss,
        "cvss_severity": "HIGH",
        "probability_score": epss,
        "active_threat": active_threat,
        "in_patchthis": in_patchthis,
        "watchlist_hit": watchlist_hit,
        "in_watchlist": watchlist_hit,
        "is_critical": is_critical,
        "priority_label": "",
        "matched_terms": [],
    }


def _make_state_file(tmp_path: Path, cves: dict) -> Path:
    """Create a state.json with the given CVE entries."""
    now = dt.datetime.now(dt.timezone.utc)
    state = {"seen_cves": {}}
    for cve_id, opts in cves.items():
        first_seen = opts.get("first_seen", (now - dt.timedelta(days=1)).isoformat())
        state["seen_cves"][cve_id] = {
            "first_seen": first_seen,
            "snapshot": opts.get("snapshot", {}),
        }
    path = tmp_path / "state.json"
    path.write_text(json.dumps(state))
    return path


# ── _build_recent_changes ───────────────────────────────────────────────────


class TestBuildRecentChanges:
    def test_no_state_file(self):
        assert _build_recent_changes(None) == []

    def test_missing_file(self, tmp_path: Path):
        assert _build_recent_changes(tmp_path / "nope.json") == []

    def test_invalid_json(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("NOT JSON")
        assert _build_recent_changes(bad) == []

    def test_recent_cves(self, tmp_path: Path):
        state = _make_state_file(
            tmp_path,
            {
                "CVE-2024-11111": {"snapshot": {"active_threat": True}},
                "CVE-2024-22222": {"snapshot": {"in_patchthis": True}},
                "CVE-2024-33333": {"snapshot": {}},
            },
        )
        result = _build_recent_changes(state)
        assert len(result) == 3
        types = {r[2] for r in result}
        assert "🔴 In CISA KEV" in types
        assert "🟠 In PatchThis" in types

    def test_old_cves_excluded(self, tmp_path: Path):
        old_date = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).isoformat()
        state = _make_state_file(
            tmp_path,
            {
                "CVE-2024-OLD": {"first_seen": old_date, "snapshot": {}},
            },
        )
        result = _build_recent_changes(state)
        assert len(result) == 0


# ── write_markdown_report ────────────────────────────────────────────────────


class TestWriteMarkdownReport:
    def test_creates_report(self, tmp_path: Path):
        out = tmp_path / "report.md"
        items = [
            _make_item("CVE-2024-00001", cvss=9.8, epss=0.9, is_critical=True, active_threat=True),
            _make_item("CVE-2024-00002", cvss=7.0, epss=0.3),
        ]
        write_markdown_report(out, items)
        assert out.exists()
        text = out.read_text()
        assert "CVE-2024-00001" in text
        assert "CVE-2024-00002" in text

    def test_empty_items(self, tmp_path: Path):
        out = tmp_path / "report.md"
        write_markdown_report(out, [])
        assert out.exists()
        assert "0" in out.read_text()

    def test_with_state_file(self, tmp_path: Path):
        state = _make_state_file(
            tmp_path,
            {
                "CVE-2024-11111": {"snapshot": {"active_threat": True}},
            },
        )
        out = tmp_path / "report.md"
        items = [_make_item("CVE-2024-11111", active_threat=True)]
        write_markdown_report(out, items, state_file=state)
        text = out.read_text()
        assert "CVE-2024-11111" in text

    def test_atomic_write(self, tmp_path: Path):
        out = tmp_path / "report.md"
        write_markdown_report(out, [])
        assert not (tmp_path / "report.md.tmp").exists()

    def test_stats_in_report(self, tmp_path: Path):
        out = tmp_path / "report.md"
        items = [
            _make_item("CVE-2024-00001", active_threat=True, watchlist_hit=True),
            _make_item("CVE-2024-00002", in_patchthis=True, watchlist_hit=True),
        ]
        write_markdown_report(out, items)
        text = out.read_text()
        # Total should show 2
        assert "2" in text
