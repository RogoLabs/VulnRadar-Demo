"""Unit tests for vulnradar.config — Pydantic configuration models."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from pydantic import ValidationError

from vulnradar.config import (
    OptionsConfig,
    ThresholdsConfig,
    WatchlistConfig,
    find_watchlist,
    load_merged_watchlist,
    load_watchlist,
)

# ── ThresholdsConfig ─────────────────────────────────────────────────────────


class TestThresholdsConfig:
    """Tests for ThresholdsConfig Pydantic model."""

    def test_defaults(self):
        t = ThresholdsConfig()
        assert t.min_cvss == 0.0
        assert t.min_epss == 0.0

    def test_custom_values(self):
        t = ThresholdsConfig(min_cvss=7.0, min_epss=0.5)
        assert t.min_cvss == 7.0
        assert t.min_epss == 0.5

    def test_boundary_values(self):
        t = ThresholdsConfig(min_cvss=0.0, min_epss=0.0)
        assert t.min_cvss == 0.0
        t2 = ThresholdsConfig(min_cvss=10.0, min_epss=1.0)
        assert t2.min_cvss == 10.0
        assert t2.min_epss == 1.0

    def test_out_of_range_cvss(self):
        with pytest.raises(ValidationError):
            ThresholdsConfig(min_cvss=11.0)

    def test_out_of_range_epss(self):
        with pytest.raises(ValidationError):
            ThresholdsConfig(min_epss=1.5)

    def test_negative_values(self):
        with pytest.raises(ValidationError):
            ThresholdsConfig(min_cvss=-1.0)
        with pytest.raises(ValidationError):
            ThresholdsConfig(min_epss=-0.1)


# ── OptionsConfig ────────────────────────────────────────────────────────────


class TestOptionsConfig:
    """Tests for OptionsConfig Pydantic model."""

    def test_defaults(self):
        o = OptionsConfig()
        assert o.always_include_kev is True
        assert o.always_include_patchthis is True
        assert o.match_mode == "substring"

    def test_custom_values(self):
        o = OptionsConfig(always_include_kev=False, match_mode="exact")
        assert o.always_include_kev is False
        assert o.match_mode == "exact"


# ── WatchlistConfig ──────────────────────────────────────────────────────────


class TestWatchlistConfig:
    """Tests for WatchlistConfig Pydantic model."""

    def test_empty_defaults(self):
        wl = WatchlistConfig()
        assert wl.vendors == set()
        assert wl.products == set()
        assert wl.exclude_vendors == set()
        assert wl.exclude_products == set()

    def test_normalization(self):
        wl = WatchlistConfig(
            vendors=["  MICROSOFT  ", "Apache Software Foundation"],
            products=["LOG4J", "  openssl  "],
        )
        assert "microsoft" in wl.vendors
        assert "apache software foundation" in wl.vendors
        assert "log4j" in wl.products
        assert "openssl" in wl.products

    def test_filters_non_strings(self):
        wl = WatchlistConfig(vendors=["microsoft", 123, None, True])
        assert wl.vendors == {"microsoft"}

    def test_filters_empty_strings(self):
        wl = WatchlistConfig(vendors=["microsoft", "", "   "])
        assert wl.vendors == {"microsoft"}

    def test_whitespace_collapse(self):
        wl = WatchlistConfig(vendors=["apache  software   foundation"])
        assert "apache software foundation" in wl.vendors

    def test_none_input(self):
        wl = WatchlistConfig(vendors=None, products=None)
        assert wl.vendors == set()
        assert wl.products == set()

    def test_exclude_fields(self):
        wl = WatchlistConfig(
            vendors=["microsoft"],
            exclude_vendors=["n/a", "unknown"],
            exclude_products=["test"],
        )
        assert "n/a" in wl.exclude_vendors
        assert "unknown" in wl.exclude_vendors
        assert "test" in wl.exclude_products

    def test_thresholds_nested(self):
        wl = WatchlistConfig(thresholds={"min_cvss": 7.0, "min_epss": 0.3})
        assert wl.thresholds.min_cvss == 7.0
        assert wl.thresholds.min_epss == 0.3

    def test_options_nested(self):
        wl = WatchlistConfig(options={"always_include_kev": False, "match_mode": "exact"})
        assert wl.options.always_include_kev is False
        assert wl.options.match_mode == "exact"

    def test_set_input(self):
        wl = WatchlistConfig(vendors={"microsoft", "apache"})
        assert "microsoft" in wl.vendors
        assert "apache" in wl.vendors


# ── load_watchlist ───────────────────────────────────────────────────────────


class TestLoadWatchlistDirect:
    """Tests for load_watchlist() returning WatchlistConfig directly."""

    def test_yaml_file(self, tmp_path: Path):
        path = tmp_path / "test.yaml"
        path.write_text(yaml.dump({"vendors": ["microsoft"], "products": ["exchange"]}))
        cfg = load_watchlist(path)
        assert isinstance(cfg, WatchlistConfig)
        assert "microsoft" in cfg.vendors
        assert "exchange" in cfg.products

    def test_json_file_with_deprecation(self, tmp_path: Path, capsys):
        path = tmp_path / "test.json"
        path.write_text(json.dumps({"vendors": ["google"], "products": ["chrome"]}))
        cfg = load_watchlist(path)
        assert "google" in cfg.vendors
        captured = capsys.readouterr()
        assert "deprecated" in captured.out.lower()

    def test_unknown_extension_tries_yaml(self, tmp_path: Path):
        path = tmp_path / "test.conf"
        path.write_text(yaml.dump({"vendors": ["apache"]}))
        cfg = load_watchlist(path)
        assert "apache" in cfg.vendors

    def test_file_not_found(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_watchlist(tmp_path / "missing.yaml")

    def test_with_thresholds(self, tmp_path: Path):
        content = {
            "vendors": ["microsoft"],
            "thresholds": {"min_cvss": 7.0, "min_epss": 0.3},
        }
        path = tmp_path / "test.yaml"
        path.write_text(yaml.dump(content))
        cfg = load_watchlist(path)
        assert cfg.thresholds.min_cvss == 7.0
        assert cfg.thresholds.min_epss == 0.3

    def test_with_exclude_lists(self, tmp_path: Path):
        content = {
            "vendors": ["microsoft"],
            "exclude_vendors": ["n/a", "unknown"],
            "exclude_products": ["test"],
        }
        path = tmp_path / "test.yaml"
        path.write_text(yaml.dump(content))
        cfg = load_watchlist(path)
        assert "n/a" in cfg.exclude_vendors
        assert "test" in cfg.exclude_products


# ── load_merged_watchlist ────────────────────────────────────────────────────


class TestLoadMergedWatchlistDirect:
    """Tests for load_merged_watchlist() with the new module directly."""

    def test_merges_exclude_lists(self, tmp_path: Path):
        """Exclusions from sub-files are merged into the result."""
        main = tmp_path / "main.yaml"
        main.write_text(
            yaml.dump(
                {
                    "vendors": ["microsoft"],
                    "exclude_vendors": ["n/a"],
                }
            )
        )

        d = tmp_path / "extra"
        d.mkdir()
        (d / "team.yaml").write_text(
            yaml.dump(
                {
                    "vendors": ["apache"],
                    "exclude_vendors": ["unknown"],
                }
            )
        )

        cfg = load_merged_watchlist(main, d)
        assert "microsoft" in cfg.vendors
        assert "apache" in cfg.vendors
        assert "n/a" in cfg.exclude_vendors
        assert "unknown" in cfg.exclude_vendors

    def test_bad_subfile_skipped(self, tmp_path: Path, capsys):
        """Invalid YAML sub-files are skipped with a warning."""
        main = tmp_path / "main.yaml"
        main.write_text(yaml.dump({"vendors": ["microsoft"]}))

        d = tmp_path / "extra"
        d.mkdir()
        (d / "bad.yaml").write_text("{{invalid yaml")

        cfg = load_merged_watchlist(main, d)
        assert "microsoft" in cfg.vendors
        captured = capsys.readouterr()
        assert "Failed" in captured.out or "⚠" in captured.out


# ── find_watchlist ───────────────────────────────────────────────────────────


class TestFindWatchlist:
    """Tests for find_watchlist()."""

    def test_prefers_yaml(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "watchlist.yaml").write_text("vendors: []\n")
        (tmp_path / "watchlist.json").write_text("{}")
        assert find_watchlist() == "watchlist.yaml"

    def test_falls_back_to_yml(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "watchlist.yml").write_text("vendors: []\n")
        assert find_watchlist() == "watchlist.yml"

    def test_falls_back_to_json(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "watchlist.json").write_text("{}")
        assert find_watchlist() == "watchlist.json"

    def test_default_when_nothing_exists(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(FileNotFoundError, match="No watchlist.yaml found"):
            find_watchlist()

    def test_auto_copy_from_example(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "watchlist.example.yaml").write_text("vendors:\n  - microsoft\n")
        result = find_watchlist()
        assert result == "watchlist.yaml"
        assert (tmp_path / "watchlist.yaml").exists()
        assert "microsoft" in (tmp_path / "watchlist.yaml").read_text()
