"""Unit tests for vulnradar.notifications — base helpers and load_providers."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from vulnradar.notifications import load_providers
from vulnradar.notifications.base import NotificationProvider
from vulnradar.notifications.discord import DiscordProvider
from vulnradar.notifications.slack import SlackProvider
from vulnradar.notifications.teams import TeamsProvider
from vulnradar.state import Change

# ── _format_epss ─────────────────────────────────────────────────────────────


class TestFormatEpss:
    def test_float(self):
        assert NotificationProvider._format_epss(0.85) == "85.0%"

    def test_none(self):
        assert NotificationProvider._format_epss(None) == "N/A"

    def test_zero(self):
        assert NotificationProvider._format_epss(0) == "0.0%"

    def test_string_number(self):
        assert NotificationProvider._format_epss("0.12") == "12.0%"

    def test_bad_value(self):
        assert NotificationProvider._format_epss("bogus") == "N/A"


# ── _format_cvss ─────────────────────────────────────────────────────────────


class TestFormatCvss:
    def test_float(self):
        assert NotificationProvider._format_cvss(9.8) == "9.8"

    def test_none(self):
        assert NotificationProvider._format_cvss(None) == "N/A"

    def test_integer(self):
        assert NotificationProvider._format_cvss(7) == "7.0"

    def test_string_number(self):
        assert NotificationProvider._format_cvss("6.5") == "6.5"

    def test_bad_value(self):
        assert NotificationProvider._format_cvss("bad") == "N/A"


# ── _top_critical ────────────────────────────────────────────────────────────


class TestTopCritical:
    """Tests for _top_critical using a concrete subclass."""

    class _Stub(NotificationProvider):
        name = "stub"

        def send_alert(self, item, changes=None): ...
        def send_summary(self, items, repo, changes_by_cve=None): ...
        def send_baseline(self, items, critical_items, repo, *, vendors=None, products=None): ...

    def _stub(self):
        return self._Stub()

    def test_returns_top_n(self):
        items = [
            {"is_critical": True, "probability_score": 0.9},
            {"is_critical": True, "probability_score": 0.3},
            {"is_critical": True, "probability_score": 0.7},
            {"is_critical": False, "probability_score": 0.99},
        ]
        result = self._stub()._top_critical(items, n=2)
        assert len(result) == 2
        assert result[0]["probability_score"] == 0.9

    def test_empty(self):
        assert self._stub()._top_critical([], n=5) == []

    def test_no_critical(self):
        items = [{"is_critical": False, "probability_score": 0.8}]
        assert self._stub()._top_critical(items) == []


# ── _build_changes_summary ───────────────────────────────────────────────────


class TestBuildChangesSummary:
    class _Stub(NotificationProvider):
        name = "stub"

        def send_alert(self, item, changes=None): ...
        def send_summary(self, items, repo, changes_by_cve=None): ...
        def send_baseline(self, items, critical_items, repo, *, vendors=None, products=None): ...

    def _stub(self):
        return self._Stub()

    def test_none_input(self):
        assert self._stub()._build_changes_summary(None) == ""

    def test_empty_dict(self):
        assert self._stub()._build_changes_summary({}) == ""

    def test_new_cve(self):
        changes = {
            "CVE-2024-001": (
                {},
                [Change(cve_id="CVE-2024-001", change_type="NEW_CVE")],
            )
        }
        result = self._stub()._build_changes_summary(changes)
        assert "🆕" in result
        assert "1 new" in result

    def test_mixed_changes(self):
        changes = {
            "CVE-2024-001": ({}, [Change(cve_id="CVE-2024-001", change_type="NEW_CVE")]),
            "CVE-2024-002": ({}, [Change(cve_id="CVE-2024-002", change_type="NEW_KEV")]),
            "CVE-2024-003": ({}, [Change(cve_id="CVE-2024-003", change_type="NEW_PATCHTHIS")]),
            "CVE-2024-004": ({}, [Change(cve_id="CVE-2024-004", change_type="EPSS_SPIKE")]),
        }
        result = self._stub()._build_changes_summary(changes)
        assert "🆕" in result
        assert "⚠️" in result
        assert "🔥" in result
        assert "📈" in result

    def test_no_significant_changes(self):
        changes = {
            "CVE-2024-001": ({}, [Change(cve_id="CVE-2024-001", change_type="OTHER_EVENT")]),
        }
        result = self._stub()._build_changes_summary(changes)
        assert result == "No significant changes"


# ── load_providers ───────────────────────────────────────────────────────────


class TestLoadProviders:
    def test_no_webhooks(self):
        assert load_providers() == []

    def test_discord_only(self):
        providers = load_providers(discord_webhook="https://discord.example.com/hook")
        assert len(providers) == 1
        assert isinstance(providers[0], DiscordProvider)

    def test_slack_only(self):
        providers = load_providers(slack_webhook="https://hooks.slack.com/hook")
        assert len(providers) == 1
        assert isinstance(providers[0], SlackProvider)

    def test_teams_only(self):
        providers = load_providers(teams_webhook="https://teams.example.com/hook")
        assert len(providers) == 1
        assert isinstance(providers[0], TeamsProvider)

    def test_all_providers(self):
        providers = load_providers(
            discord_webhook="https://discord.example.com/hook",
            slack_webhook="https://hooks.slack.com/hook",
            teams_webhook="https://teams.example.com/hook",
        )
        assert len(providers) == 3
        names = {p.name for p in providers}
        assert names == {"discord", "slack", "teams"}

    def test_custom_max_alerts(self):
        providers = load_providers(discord_webhook="https://x.com", discord_max=5)
        assert providers[0].max_alerts == 5

    def test_none_webhooks_skipped(self):
        providers = load_providers(
            discord_webhook=None,
            slack_webhook=None,
            teams_webhook=None,
        )
        assert providers == []


# ── Provider instantiation ───────────────────────────────────────────────────


class TestProviderInstantiation:
    def test_discord_provider_attrs(self):
        p = DiscordProvider(webhook_url="https://discord.example.com/hook", max_alerts=15)
        assert p.name == "discord"
        assert p.max_alerts == 15

    def test_slack_provider_attrs(self):
        p = SlackProvider(webhook_url="https://hooks.slack.com/hook")
        assert p.name == "slack"

    def test_teams_provider_attrs(self):
        p = TeamsProvider(webhook_url="https://teams.example.com/hook")
        assert p.name == "teams"


# ── Provider send_alert ──────────────────────────────────────────────────────


def _sample_item(**overrides: Any) -> dict[str, Any]:
    base = {
        "cve_id": "CVE-2024-12345",
        "description": "Test vulnerability",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "probability_score": 0.85,
        "active_threat": True,
        "in_patchthis": True,
        "watchlist_hit": True,
        "in_watchlist": True,
        "is_critical": True,
        "priority_label": "CRITICAL",
        "matched_terms": ["vendor:apache"],
        "kev": {
            "cveID": "CVE-2024-12345",
            "dueDate": "2024-07-01",
            "dateAdded": "2024-06-16",
        },
    }
    base.update(overrides)
    return base


class TestDiscordSendAlert:
    @patch("vulnradar.notifications.discord.requests.post")
    def test_fires_webhook(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = DiscordProvider(webhook_url="https://discord.test/hook")
        p.send_alert(_sample_item())
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert "embeds" in payload
        assert "CRITICAL" in payload["embeds"][0]["title"]

    @patch("vulnradar.notifications.discord.requests.post")
    def test_with_changes(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = DiscordProvider(webhook_url="https://discord.test/hook")
        changes = [Change(cve_id="CVE-2024-12345", change_type="NEW_CVE")]
        p.send_alert(_sample_item(), changes=changes)
        mock_post.assert_called_once()

    @patch("vulnradar.notifications.discord.requests.post")
    def test_non_critical(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = DiscordProvider(webhook_url="https://discord.test/hook")
        p.send_alert(_sample_item(is_critical=False, active_threat=False))
        payload = mock_post.call_args[1]["json"]
        assert "ALERT" in payload["embeds"][0]["title"]


class TestSlackSendAlert:
    @patch("vulnradar.notifications.slack.requests.post")
    def test_fires_webhook(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = SlackProvider(webhook_url="https://hooks.slack.com/hook")
        p.send_alert(_sample_item())
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert "attachments" in payload

    @patch("vulnradar.notifications.slack.requests.post")
    def test_non_critical(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = SlackProvider(webhook_url="https://hooks.slack.com/hook")
        p.send_alert(_sample_item(is_critical=False, active_threat=True))
        mock_post.assert_called_once()


class TestTeamsSendAlert:
    @patch("vulnradar.notifications.teams.requests.post")
    def test_fires_webhook(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = TeamsProvider(webhook_url="https://teams.test/hook")
        p.send_alert(_sample_item())
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert "type" in payload

    @patch("vulnradar.notifications.teams.requests.post")
    def test_non_critical(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = TeamsProvider(webhook_url="https://teams.test/hook")
        p.send_alert(_sample_item(is_critical=False, active_threat=False))
        mock_post.assert_called_once()


# ── Provider send_summary ───────────────────────────────────────────────────


class TestDiscordSendSummary:
    @patch("vulnradar.notifications.discord.requests.post")
    def test_summary(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = DiscordProvider(webhook_url="https://discord.test/hook")
        items = [_sample_item(), _sample_item(cve_id="CVE-2024-99999", is_critical=False)]
        p.send_summary(items, "owner/repo")
        mock_post.assert_called_once()

    @patch("vulnradar.notifications.discord.requests.post")
    def test_summary_with_changes(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = DiscordProvider(webhook_url="https://discord.test/hook")
        changes = {"CVE-2024-12345": (_sample_item(), [Change(cve_id="CVE-2024-12345", change_type="NEW_CVE")])}
        p.send_summary([_sample_item()], "owner/repo", changes_by_cve=changes)
        mock_post.assert_called_once()


class TestSlackSendSummary:
    @patch("vulnradar.notifications.slack.requests.post")
    def test_summary(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = SlackProvider(webhook_url="https://hooks.slack.com/hook")
        p.send_summary([_sample_item()], "owner/repo")
        mock_post.assert_called_once()


class TestTeamsSendSummary:
    @patch("vulnradar.notifications.teams.requests.post")
    def test_summary(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = TeamsProvider(webhook_url="https://teams.test/hook")
        p.send_summary([_sample_item()], "owner/repo")
        mock_post.assert_called_once()


# ── Provider send_baseline ──────────────────────────────────────────────────


class TestDiscordSendBaseline:
    @patch("vulnradar.notifications.discord.requests.post")
    def test_baseline(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = DiscordProvider(webhook_url="https://discord.test/hook")
        items = [_sample_item()]
        p.send_baseline(items, items, "owner/repo")
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert "Baseline" in payload["embeds"][0]["title"]


class TestSlackSendBaseline:
    @patch("vulnradar.notifications.slack.requests.post")
    def test_baseline(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = SlackProvider(webhook_url="https://hooks.slack.com/hook")
        items = [_sample_item()]
        p.send_baseline(items, items, "owner/repo")
        mock_post.assert_called_once()


class TestTeamsSendBaseline:
    @patch("vulnradar.notifications.teams.requests.post")
    def test_baseline(self, mock_post: MagicMock):
        mock_post.return_value.raise_for_status = MagicMock()
        p = TeamsProvider(webhook_url="https://teams.test/hook")
        items = [_sample_item()]
        p.send_baseline(items, items, "owner/repo")
        mock_post.assert_called_once()
