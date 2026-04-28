"""State management for VulnRadar notifications.

Tracks seen CVEs and prevents duplicate alerts by maintaining persistent
state between runs. Detects meaningful changes (new CVEs, KEV additions,
EPSS spikes) that warrant alerting.
"""

import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Change:
    """Represents a change that warrants alerting.

    Attributes:
        cve_id: The CVE identifier (e.g., CVE-2024-12345).
        change_type: One of NEW_CVE, NEW_KEV, NEW_PATCHTHIS,
                     BECAME_CRITICAL, EPSS_SPIKE.
        old_value: Previous value (for comparisons like EPSS_SPIKE).
        new_value: Current value.
    """

    cve_id: str
    change_type: str
    old_value: Any = None
    new_value: Any = None

    def __str__(self) -> str:
        if self.change_type == "NEW_CVE":
            return f"🆕 NEW: {self.cve_id}"
        elif self.change_type == "NEW_KEV":
            return f"⚠️ NOW IN KEV: {self.cve_id}"
        elif self.change_type == "NEW_PATCHTHIS":
            return f"🔥 EXPLOIT INTEL: {self.cve_id} (PoC Available)"
        elif self.change_type == "BECAME_CRITICAL":
            return f"🚨 NOW CRITICAL: {self.cve_id}"
        elif self.change_type == "EPSS_SPIKE":
            old = f"{self.old_value:.1%}" if self.old_value else "N/A"
            new = f"{self.new_value:.1%}" if self.new_value else "N/A"
            return f"📈 EPSS SPIKE: {self.cve_id} ({old} → {new})"
        return f"{self.change_type}: {self.cve_id}"


class StateManager:
    """Manages persistent state to track seen CVEs and prevent duplicate alerts.

    State is stored as a JSON file with schema versioning. On each run,
    snapshots of CVE data are compared to detect meaningful changes.

    Attributes:
        path: Path to the state JSON file.
        data: In-memory state dictionary.
    """

    SCHEMA_VERSION = 1

    def __init__(self, path: Path):
        self.path = path
        self.data = self._load()

    def _load(self) -> dict[str, Any]:
        """Load state from file, or create empty state."""
        if self.path.exists():
            try:
                with self.path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("schema_version") != self.SCHEMA_VERSION:
                    print("State schema version mismatch, resetting state")
                    return self._empty_state()
                return data
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: Could not load state file ({e}), starting fresh")
                return self._empty_state()
        return self._empty_state()

    def _empty_state(self) -> dict[str, Any]:
        """Create empty state structure."""
        return {
            "schema_version": self.SCHEMA_VERSION,
            "last_run": None,
            "seen_cves": {},
            "statistics": {
                "total_alerts_sent": 0,
                "alerts_by_channel": {},
            },
        }

    def save(self) -> None:
        """Save state to file atomically (write-then-rename)."""
        self.data["last_run"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        tmp.replace(self.path)

    def is_new_cve(self, cve_id: str) -> bool:
        """Check if this CVE has never been seen before.

        Args:
            cve_id: The CVE identifier (e.g. ``CVE-2024-12345``).

        Returns:
            ``True`` if the CVE is not yet tracked in state.
        """
        return cve_id not in self.data["seen_cves"]

    def get_snapshot(self, cve_id: str) -> dict[str, Any] | None:
        """Get the previous snapshot for a CVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            Snapshot dict with keys like ``is_critical``, ``active_threat``,
            ``probability_score``, etc.  ``None`` if the CVE is unknown.
        """
        entry = self.data["seen_cves"].get(cve_id)
        if entry:
            return entry.get("snapshot")
        return None

    def detect_changes(self, cve_id: str, item: dict[str, Any]) -> list[Change]:
        """Detect changes that warrant alerting.

        Args:
            cve_id: The CVE identifier.
            item: Current radar data item for this CVE.

        Returns:
            List of Change objects describing what changed.
        """
        changes: list[Change] = []
        previous = self.get_snapshot(cve_id)

        # New CVE — never seen before
        if previous is None:
            changes.append(Change(cve_id=cve_id, change_type="NEW_CVE"))
            return changes

        # Check for KEV addition
        was_kev = bool(previous.get("active_threat"))
        is_kev = bool(item.get("active_threat"))
        if is_kev and not was_kev:
            changes.append(Change(cve_id=cve_id, change_type="NEW_KEV", old_value=False, new_value=True))

        # Check for PatchThis addition
        was_patchthis = bool(previous.get("in_patchthis"))
        is_patchthis = bool(item.get("in_patchthis"))
        if is_patchthis and not was_patchthis:
            changes.append(Change(cve_id=cve_id, change_type="NEW_PATCHTHIS", old_value=False, new_value=True))

        # Check for became critical
        was_critical = bool(previous.get("is_critical"))
        is_critical = bool(item.get("is_critical"))
        if is_critical and not was_critical:
            changes.append(Change(cve_id=cve_id, change_type="BECAME_CRITICAL", old_value=False, new_value=True))

        # Check for EPSS spike (≥0.3 increase)
        old_epss = previous.get("probability_score")
        new_epss = item.get("probability_score")
        if old_epss is not None and new_epss is not None:
            try:
                old_f = float(old_epss)
                new_f = float(new_epss)
                if new_f - old_f >= 0.3:
                    changes.append(Change(cve_id=cve_id, change_type="EPSS_SPIKE", old_value=old_f, new_value=new_f))
            except (ValueError, TypeError):
                pass

        return changes

    def update_snapshot(self, cve_id: str, item: dict[str, Any]) -> None:
        """Update the stored snapshot for a CVE.

        Creates the tracking entry if it doesn't exist.

        Args:
            cve_id: The CVE identifier.
            item: Current radar data item dict.
        """
        now = dt.datetime.now(dt.timezone.utc).isoformat()

        if cve_id not in self.data["seen_cves"]:
            self.data["seen_cves"][cve_id] = {
                "first_seen": now,
                "last_seen": now,
                "alerted_at": None,
                "alerted_channels": [],
                "snapshot": {},
            }

        entry = self.data["seen_cves"][cve_id]
        entry["last_seen"] = now
        entry["snapshot"] = {
            "is_critical": bool(item.get("is_critical")),
            "active_threat": bool(item.get("active_threat")),
            "in_patchthis": bool(item.get("in_patchthis")),
            "probability_score": item.get("probability_score"),
            "cvss_score": item.get("cvss_score"),
        }

    def mark_alerted(self, cve_id: str, channels: list[str]) -> None:
        """Mark a CVE as alerted on specific channels.

        Updates the ``alerted_at`` timestamp, adds channels to the
        ``alerted_channels`` set, and increments alert statistics.

        Args:
            cve_id: The CVE identifier.
            channels: List of channel names (e.g. ``["discord", "slack"]``).
        """
        if cve_id not in self.data["seen_cves"]:
            return

        now = dt.datetime.now(dt.timezone.utc).isoformat()
        entry = self.data["seen_cves"][cve_id]
        entry["alerted_at"] = now

        existing = set(entry.get("alerted_channels") or [])
        existing.update(channels)
        entry["alerted_channels"] = sorted(existing)

        self.data["statistics"]["total_alerts_sent"] += len(channels)
        for ch in channels:
            self.data["statistics"]["alerts_by_channel"][ch] = (
                self.data["statistics"]["alerts_by_channel"].get(ch, 0) + 1
            )

    def prune_old_entries(self, days: int = 180) -> int:
        """Remove CVEs not seen in the specified number of days.

        Args:
            days: Retention period.  CVEs whose ``last_seen`` is older
                than this many days ago will be pruned.

        Returns:
            Number of entries removed.
        """
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
        cutoff_str = cutoff.isoformat()

        to_remove = []
        for cve_id, entry in self.data["seen_cves"].items():
            last_seen = entry.get("last_seen", "")
            if last_seen < cutoff_str:
                to_remove.append(cve_id)

        for cve_id in to_remove:
            del self.data["seen_cves"][cve_id]

        return len(to_remove)

    def get_stats(self) -> dict[str, Any]:
        """Get summary statistics.

        Returns:
            Dict with ``total_tracked``, ``total_alerts_sent``,
            ``alerts_by_channel``, and ``last_run`` keys.
        """
        return {
            "total_tracked": len(self.data["seen_cves"]),
            "total_alerts_sent": self.data["statistics"]["total_alerts_sent"],
            "alerts_by_channel": self.data["statistics"]["alerts_by_channel"],
            "last_run": self.data.get("last_run"),
        }
