"""Unit tests for notify.py."""

import json
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from notify import _issue_body, _load_items


class TestLoadItems:
    """Tests for _load_items() function."""

    def test_load_items_from_dict_with_items_key(self, tmp_path: Path):
        """Load items from {"items": [...]} format."""
        data = {
            "meta": {"generated": "2024-01-01"},
            "items": [
                {"cve_id": "CVE-2024-0001"},
                {"cve_id": "CVE-2024-0002"},
            ],
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))
        items = _load_items(path)
        assert len(items) == 2
        assert items[0]["cve_id"] == "CVE-2024-0001"

    def test_load_items_from_list(self, tmp_path: Path):
        """Load items from raw list format."""
        data = [
            {"cve_id": "CVE-2024-0001"},
            {"cve_id": "CVE-2024-0002"},
        ]
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))
        items = _load_items(path)
        assert len(items) == 2

    def test_load_items_empty(self, tmp_path: Path):
        """Empty data returns empty list."""
        path = tmp_path / "empty.json"
        path.write_text(json.dumps({"items": []}))
        items = _load_items(path)
        assert items == []


class TestIssueBody:
    """Tests for _issue_body() function."""

    def test_critical_priority_label(self, sample_radar_item: Dict[str, Any]):
        """Critical items should show CRITICAL priority."""
        body = _issue_body(sample_radar_item)
        assert "Priority: CRITICAL" in body

    def test_non_critical_priority_label(self, sample_radar_item: Dict[str, Any]):
        """Non-critical items should show ALERT priority."""
        item = {**sample_radar_item, "is_critical": False}
        body = _issue_body(item)
        assert "Priority: ALERT" in body

    def test_cve_id_in_body(self, sample_radar_item: Dict[str, Any]):
        """CVE ID should be in the body."""
        body = _issue_body(sample_radar_item)
        assert "CVE-2024-12345" in body

    def test_signals_section(self, sample_radar_item: Dict[str, Any]):
        """Signals section should show all flags."""
        body = _issue_body(sample_radar_item)
        assert "PatchThis: yes" in body
        assert "Watchlist: yes" in body
        assert "CISA KEV: yes" in body

    def test_epss_formatting(self, sample_radar_item: Dict[str, Any]):
        """EPSS should be formatted to 3 decimal places."""
        body = _issue_body(sample_radar_item)
        assert "EPSS: 0.850" in body

    def test_cvss_formatting(self, sample_radar_item: Dict[str, Any]):
        """CVSS should be formatted to 1 decimal place."""
        body = _issue_body(sample_radar_item)
        assert "CVSS: 9.8" in body

    def test_kev_due_date(self, sample_radar_item: Dict[str, Any]):
        """KEV due date should be shown when available."""
        body = _issue_body(sample_radar_item)
        assert "KEV Due Date: 2024-07-01" in body

    def test_cve_org_link(self, sample_radar_item: Dict[str, Any]):
        """CVE.org link should be included."""
        body = _issue_body(sample_radar_item)
        assert "https://www.cve.org/CVERecord?id=CVE-2024-12345" in body

    def test_description_included(self, sample_radar_item: Dict[str, Any]):
        """Description should be in body."""
        body = _issue_body(sample_radar_item)
        assert "A critical vulnerability" in body

    def test_missing_optional_fields(self):
        """Handle items with missing optional fields gracefully."""
        minimal = {
            "cve_id": "CVE-2024-00001",
            "is_critical": False,
        }
        body = _issue_body(minimal)
        assert "CVE-2024-00001" in body
        assert "Priority: ALERT" in body

    def test_none_epss_cvss(self):
        """Handle None values for EPSS and CVSS."""
        item = {
            "cve_id": "CVE-2024-00001",
            "probability_score": None,
            "cvss_score": None,
            "is_critical": False,
        }
        body = _issue_body(item)
        # Should not crash, just show empty
        assert "EPSS:" in body
        assert "CVSS:" in body


class TestDiscordPayload:
    """Tests for Discord notification formatting."""

    def test_discord_alert_structure(self, sample_radar_item: Dict[str, Any]):
        """Test Discord embed structure (without actually sending)."""
        # Import the function
        from notify import send_discord_alert

        # Mock requests.post
        with patch("notify.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_response

            send_discord_alert("https://fake.webhook.url", sample_radar_item)

            # Verify it was called
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            payload = call_args.kwargs.get("json") or call_args[1].get("json")

            # Check embed structure
            assert "embeds" in payload
            embed = payload["embeds"][0]
            assert "CVE-2024-12345" in embed["title"]
            assert "CRITICAL" in embed["title"]
            assert embed["color"] == 0xFF0000  # Red for critical

    def test_discord_summary_structure(self, sample_radar_item: Dict[str, Any]):
        """Test Discord summary embed structure."""
        from notify import send_discord_summary

        with patch("notify.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_response

            items = [sample_radar_item]
            send_discord_summary("https://fake.webhook.url", items, "test/repo")

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            payload = call_args.kwargs.get("json") or call_args[1].get("json")

            embed = payload["embeds"][0]
            assert "Summary" in embed["title"]
            assert any("Critical" in f["name"] for f in embed["fields"])


class TestSlackPayload:
    """Tests for Slack notification formatting."""

    def test_slack_alert_structure(self, sample_radar_item: Dict[str, Any]):
        """Test Slack message structure."""
        from notify import send_slack_alert

        with patch("notify.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_response

            send_slack_alert("https://hooks.slack.com/fake", sample_radar_item)

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            payload = call_args.kwargs.get("json") or call_args[1].get("json")

            assert "attachments" in payload
            assert payload["attachments"][0]["color"] == "danger"


class TestTeamsPayload:
    """Tests for Teams notification formatting."""

    def test_teams_alert_structure(self, sample_radar_item: Dict[str, Any]):
        """Test Teams Adaptive Card structure."""
        from notify import send_teams_alert

        with patch("notify.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_response

            send_teams_alert("https://teams.webhook.url", sample_radar_item)

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            payload = call_args.kwargs.get("json") or call_args[1].get("json")

            assert payload["type"] == "message"
            assert "attachments" in payload
            card = payload["attachments"][0]["content"]
            assert card["type"] == "AdaptiveCard"
            assert card["version"] == "1.4"


class TestStateManager:
    """Tests for StateManager class."""

    def test_empty_state_on_missing_file(self, tmp_path: Path):
        """StateManager creates empty state when file doesn't exist."""
        from notify import StateManager

        state = StateManager(tmp_path / "nonexistent.json")
        assert state.data["schema_version"] == 1
        assert state.data["seen_cves"] == {}
        assert state.data["last_run"] is None

    def test_save_and_load_state(self, tmp_path: Path):
        """State persists between saves."""
        from notify import StateManager

        state_path = tmp_path / "state.json"
        state1 = StateManager(state_path)
        state1.update_snapshot("CVE-2024-0001", {"is_critical": True})
        state1.save()

        state2 = StateManager(state_path)
        assert "CVE-2024-0001" in state2.data["seen_cves"]

    def test_is_new_cve(self, tmp_path: Path):
        """is_new_cve returns True for unseen CVEs."""
        from notify import StateManager

        state = StateManager(tmp_path / "state.json")
        assert state.is_new_cve("CVE-2024-0001") is True

        state.update_snapshot("CVE-2024-0001", {})
        assert state.is_new_cve("CVE-2024-0001") is False

    def test_detect_new_cve(self, tmp_path: Path):
        """Detect NEW_CVE change type for unseen CVE."""
        from notify import StateManager

        state = StateManager(tmp_path / "state.json")
        changes = state.detect_changes("CVE-2024-0001", {"is_critical": True})

        assert len(changes) == 1
        assert changes[0].change_type == "NEW_CVE"
        assert changes[0].cve_id == "CVE-2024-0001"

    def test_detect_new_kev(self, tmp_path: Path):
        """Detect NEW_KEV when active_threat changes to True."""
        from notify import StateManager

        state = StateManager(tmp_path / "state.json")
        # First seen - not in KEV
        state.update_snapshot("CVE-2024-0001", {"active_threat": False})

        # Now added to KEV
        changes = state.detect_changes("CVE-2024-0001", {"active_threat": True})

        assert len(changes) == 1
        assert changes[0].change_type == "NEW_KEV"

    def test_detect_new_patchthis(self, tmp_path: Path):
        """Detect NEW_PATCHTHIS when in_patchthis changes to True."""
        from notify import StateManager

        state = StateManager(tmp_path / "state.json")
        state.update_snapshot("CVE-2024-0001", {"in_patchthis": False})

        changes = state.detect_changes("CVE-2024-0001", {"in_patchthis": True})

        assert len(changes) == 1
        assert changes[0].change_type == "NEW_PATCHTHIS"

    def test_detect_became_critical(self, tmp_path: Path):
        """Detect BECAME_CRITICAL when is_critical changes to True."""
        from notify import StateManager

        state = StateManager(tmp_path / "state.json")
        state.update_snapshot("CVE-2024-0001", {"is_critical": False})

        changes = state.detect_changes("CVE-2024-0001", {"is_critical": True})

        assert len(changes) == 1
        assert changes[0].change_type == "BECAME_CRITICAL"

    def test_detect_epss_spike(self, tmp_path: Path):
        """Detect EPSS_SPIKE when EPSS increases by >= 0.3."""
        from notify import StateManager

        state = StateManager(tmp_path / "state.json")
        state.update_snapshot("CVE-2024-0001", {"probability_score": 0.1})

        # 0.1 -> 0.5 is a 0.4 spike (>= 0.3 threshold)
        changes = state.detect_changes("CVE-2024-0001", {"probability_score": 0.5})

        assert len(changes) == 1
        assert changes[0].change_type == "EPSS_SPIKE"
        assert changes[0].old_value == 0.1
        assert changes[0].new_value == 0.5

    def test_no_change_for_stable_cve(self, tmp_path: Path):
        """No changes detected for stable CVE."""
        from notify import StateManager

        state = StateManager(tmp_path / "state.json")
        item = {
            "is_critical": True,
            "active_threat": True,
            "in_patchthis": True,
            "probability_score": 0.5,
        }
        state.update_snapshot("CVE-2024-0001", item)

        changes = state.detect_changes("CVE-2024-0001", item)
        assert len(changes) == 0

    def test_mark_alerted(self, tmp_path: Path):
        """mark_alerted records channels and updates statistics."""
        from notify import StateManager

        state = StateManager(tmp_path / "state.json")
        state.update_snapshot("CVE-2024-0001", {})
        state.mark_alerted("CVE-2024-0001", ["discord", "slack"])

        entry = state.data["seen_cves"]["CVE-2024-0001"]
        assert "discord" in entry["alerted_channels"]
        assert "slack" in entry["alerted_channels"]
        assert state.data["statistics"]["total_alerts_sent"] == 2
        assert state.data["statistics"]["alerts_by_channel"]["discord"] == 1

    def test_prune_old_entries(self, tmp_path: Path):
        """prune_old_entries removes CVEs not seen recently."""
        from notify import StateManager
        import datetime as dt

        state = StateManager(tmp_path / "state.json")
        state.update_snapshot("CVE-2024-0001", {})

        # Manually set an old last_seen date
        old_date = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=200)).isoformat()
        state.data["seen_cves"]["CVE-2024-0001"]["last_seen"] = old_date

        pruned = state.prune_old_entries(days=180)
        assert pruned == 1
        assert "CVE-2024-0001" not in state.data["seen_cves"]


class TestChange:
    """Tests for Change dataclass."""

    def test_change_str_new_cve(self):
        """Test string representation for NEW_CVE."""
        from notify import Change

        change = Change(cve_id="CVE-2024-0001", change_type="NEW_CVE")
        assert "NEW" in str(change)
        assert "CVE-2024-0001" in str(change)

    def test_change_str_epss_spike(self):
        """Test string representation for EPSS_SPIKE includes values."""
        from notify import Change

        change = Change(
            cve_id="CVE-2024-0001",
            change_type="EPSS_SPIKE",
            old_value=0.1,
            new_value=0.5,
        )
        result = str(change)
        assert "EPSS SPIKE" in result
        assert "10.0%" in result
        assert "50.0%" in result
