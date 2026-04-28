"""Unit tests for Phase 7 features — severity thresholds & notification routing."""

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from vulnradar.config import (
    NotificationRoute,
    NotificationsConfig,
    ThresholdsConfig,
    WatchlistConfig,
)
from vulnradar.enrichment import build_radar_data
from vulnradar.notifications import (
    _resolve_env,
    filter_items_for_route,
    load_routed_providers,
)
from vulnradar.notifications.discord import DiscordProvider
from vulnradar.notifications.slack import SlackProvider
from vulnradar.notifications.teams import TeamsProvider

# ── helpers ──────────────────────────────────────────────────────────────────


def _make_cve_file(cves_root: Path, cve_id: str, vendor: str, product: str, cvss: float = 5.0) -> Path:
    year, num = cve_id.split("-")[1], int(cve_id.split("-")[2])
    group = f"{num // 1000}xxx"
    dest = cves_root / year / group / f"{cve_id}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "datePublished": "2024-06-01T00:00:00.000Z",
        },
        "containers": {
            "cna": {
                "affected": [{"vendor": vendor, "product": product}],
                "descriptions": [{"lang": "en", "value": f"Vuln in {product}"}],
                "metrics": [{"cvssV3_1": {"baseScore": cvss, "baseSeverity": "CRITICAL" if cvss >= 9.0 else "HIGH"}}],
            }
        },
    }
    dest.write_text(json.dumps(doc))
    return dest


@pytest.fixture
def cve_tree(tmp_path: Path) -> Path:
    cves_root = tmp_path / "extracted" / "cves"
    _make_cve_file(cves_root, "CVE-2024-10001", "Apache", "Log4j", cvss=9.8)
    _make_cve_file(cves_root, "CVE-2024-10002", "Microsoft", "Exchange", cvss=7.5)
    _make_cve_file(cves_root, "CVE-2024-10003", "Linux", "Kernel", cvss=6.0)
    return tmp_path / "extracted"


# ── ThresholdsConfig ─────────────────────────────────────────────────────────


class TestThresholdsWithSeverity:
    def test_defaults_none(self):
        t = ThresholdsConfig()
        assert t.severity_threshold is None
        assert t.epss_threshold is None

    def test_custom_severity(self):
        t = ThresholdsConfig(severity_threshold=9.0, epss_threshold=0.5)
        assert t.severity_threshold == 9.0
        assert t.epss_threshold == 0.5

    def test_severity_out_of_range(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ThresholdsConfig(severity_threshold=11.0)

    def test_epss_out_of_range(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ThresholdsConfig(epss_threshold=1.5)


# ── Severity threshold in build_radar_data ───────────────────────────────────


class TestSeverityThresholdInBuild:
    def test_cvss_threshold_flags_critical(self, cve_tree: Path):
        """CVE with CVSS 9.8 on watchlist should be critical when threshold is 9.0."""
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors={"apache"},
            wl_products=set(),
            kev_by_cve={},
            epss_by_cve={},
            patchthis_cves=set(),
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
            severity_threshold=9.0,
        )
        assert len(items) == 1
        assert items[0]["is_critical"] is True
        assert "CVSS" in items[0]["priority_label"]

    def test_cvss_below_threshold_not_critical(self, cve_tree: Path):
        """CVE with CVSS 7.5 on watchlist should NOT be critical when threshold is 9.0."""
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors={"microsoft"},
            wl_products=set(),
            kev_by_cve={},
            epss_by_cve={},
            patchthis_cves=set(),
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
            severity_threshold=9.0,
        )
        assert len(items) == 1
        assert items[0]["is_critical"] is False

    def test_epss_threshold_flags_critical(self, cve_tree: Path):
        """CVE with EPSS 0.85 on watchlist should be critical when threshold is 0.5."""
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors={"linux"},
            wl_products=set(),
            kev_by_cve={},
            epss_by_cve={"CVE-2024-10003": 0.85},
            patchthis_cves=set(),
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
            epss_threshold=0.5,
        )
        assert len(items) == 1
        assert items[0]["is_critical"] is True

    def test_epss_below_threshold_not_critical(self, cve_tree: Path):
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors={"linux"},
            wl_products=set(),
            kev_by_cve={},
            epss_by_cve={"CVE-2024-10003": 0.1},
            patchthis_cves=set(),
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
            epss_threshold=0.5,
        )
        assert len(items) == 1
        assert items[0]["is_critical"] is False

    def test_patchthis_still_critical_without_thresholds(self, cve_tree: Path):
        """Original logic: patchthis + watchlist = critical, even without thresholds."""
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors={"apache"},
            wl_products=set(),
            kev_by_cve={},
            epss_by_cve={},
            patchthis_cves={"CVE-2024-10001"},
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
        )
        assert items[0]["is_critical"] is True
        assert "Active Exploit" in items[0]["priority_label"]

    def test_both_thresholds_combined(self, cve_tree: Path):
        """Both thresholds set — CVSS triggers first."""
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors={"apache"},
            wl_products=set(),
            kev_by_cve={},
            epss_by_cve={"CVE-2024-10001": 0.1},
            patchthis_cves=set(),
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
            severity_threshold=9.0,
            epss_threshold=0.5,
        )
        assert items[0]["is_critical"] is True


# ── NotificationRoute / NotificationsConfig ──────────────────────────────────


class TestNotificationRouteConfig:
    def test_default_filter(self):
        r = NotificationRoute(url="https://example.com/hook")
        assert r.filter == "all"
        assert r.max_alerts == 10

    def test_custom_filter(self):
        r = NotificationRoute(url="https://example.com/hook", filter="critical", max_alerts=5)
        assert r.filter == "critical"
        assert r.max_alerts == 5

    def test_notifications_config_empty(self):
        n = NotificationsConfig()
        assert n.discord == []
        assert n.slack == []
        assert n.teams == []

    def test_notifications_from_dict(self):
        n = NotificationsConfig.model_validate(
            {
                "discord": [
                    {"url": "https://discord.com/hook1", "filter": "critical"},
                    {"url": "https://discord.com/hook2", "filter": "all", "max_alerts": 5},
                ],
                "slack": [
                    {"url": "$SLACK_WEBHOOK_URL", "filter": "kev"},
                ],
            }
        )
        assert len(n.discord) == 2
        assert n.discord[0].filter == "critical"
        assert n.discord[1].max_alerts == 5
        assert len(n.slack) == 1

    def test_watchlist_config_with_notifications(self):
        wl = WatchlistConfig(
            vendors=["microsoft"],
            notifications={
                "discord": [{"url": "https://discord.com/hook", "filter": "critical"}],
            },
        )
        assert len(wl.notifications.discord) == 1
        assert wl.notifications.discord[0].filter == "critical"


# ── filter_items_for_route ───────────────────────────────────────────────────


class TestFilterItemsForRoute:
    def _items(self) -> list[dict]:
        return [
            {"cve_id": "A", "is_critical": True, "active_threat": True, "watchlist_hit": True},
            {"cve_id": "B", "is_critical": False, "active_threat": True, "watchlist_hit": True},
            {"cve_id": "C", "is_critical": False, "active_threat": False, "watchlist_hit": True},
            {"cve_id": "D", "is_critical": False, "active_threat": False, "watchlist_hit": False},
        ]

    def test_all(self):
        assert len(filter_items_for_route(self._items(), "all")) == 4

    def test_critical(self):
        result = filter_items_for_route(self._items(), "critical")
        assert len(result) == 1
        assert result[0]["cve_id"] == "A"

    def test_kev(self):
        result = filter_items_for_route(self._items(), "kev")
        assert len(result) == 2

    def test_watchlist(self):
        result = filter_items_for_route(self._items(), "watchlist")
        assert len(result) == 3

    def test_unknown_returns_all(self):
        assert len(filter_items_for_route(self._items(), "unknown")) == 4


# ── _resolve_env ─────────────────────────────────────────────────────────────


class TestResolveEnv:
    @patch.dict(os.environ, {"MY_WEBHOOK": "https://example.com/hook"})
    def test_env_var(self):
        assert _resolve_env("$MY_WEBHOOK") == "https://example.com/hook"

    def test_env_var_missing(self):
        assert _resolve_env("$NONEXISTENT_VAR_ABC") is None

    def test_literal_url(self):
        assert _resolve_env("https://example.com") == "https://example.com"

    def test_empty(self):
        assert _resolve_env("") is None


# ── load_routed_providers ────────────────────────────────────────────────────


class TestLoadRoutedProviders:
    def test_empty_config(self):
        config = NotificationsConfig()
        assert load_routed_providers(config) == []

    def test_discord_routes(self):
        config = NotificationsConfig(
            discord=[
                NotificationRoute(url="https://discord.com/hook1", filter="critical"),
                NotificationRoute(url="https://discord.com/hook2", filter="all", max_alerts=5),
            ],
        )
        routed = load_routed_providers(config)
        assert len(routed) == 2
        assert isinstance(routed[0][0], DiscordProvider)
        assert routed[0][1] == "critical"
        assert isinstance(routed[1][0], DiscordProvider)
        assert routed[1][0].max_alerts == 5

    def test_mixed_providers(self):
        config = NotificationsConfig(
            discord=[NotificationRoute(url="https://discord.com/hook")],
            slack=[NotificationRoute(url="https://hooks.slack.com/hook")],
            teams=[NotificationRoute(url="https://teams.com/hook")],
        )
        routed = load_routed_providers(config)
        assert len(routed) == 3
        types = {type(p) for p, _ in routed}
        assert types == {DiscordProvider, SlackProvider, TeamsProvider}

    @patch.dict(os.environ, {"SLACK_HOOK": "https://hooks.slack.com/actual"})
    def test_env_var_resolution(self):
        config = NotificationsConfig(
            slack=[NotificationRoute(url="$SLACK_HOOK", filter="kev")],
        )
        routed = load_routed_providers(config)
        assert len(routed) == 1
        assert routed[0][0].webhook_url == "https://hooks.slack.com/actual"
        assert routed[0][1] == "kev"

    def test_missing_env_var_skipped(self):
        config = NotificationsConfig(
            discord=[NotificationRoute(url="$NONEXISTENT_WEBHOOK_VAR")],
        )
        routed = load_routed_providers(config)
        assert len(routed) == 0
