#!/usr/bin/env python3

import argparse
import datetime as dt
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

import requests

DEFAULT_TIMEOUT = (10, 60)


# ─────────────────────────────────────────────────────────────────────────────
# State Management - Prevents alert spam by tracking what's been seen/alerted
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Change:
    """Represents a change that warrants alerting."""
    cve_id: str
    change_type: str  # NEW_CVE, NEW_KEV, NEW_PATCHTHIS, BECAME_CRITICAL, EPSS_SPIKE
    old_value: Any = None
    new_value: Any = None
    
    def __str__(self) -> str:
        if self.change_type == "NEW_CVE":
            return f"🆕 NEW: {self.cve_id}"
        elif self.change_type == "NEW_KEV":
            return f"⚠️ NOW IN KEV: {self.cve_id}"
        elif self.change_type == "NEW_PATCHTHIS":
            return f"🔥 NOW IN PATCHTHIS: {self.cve_id}"
        elif self.change_type == "BECAME_CRITICAL":
            return f"🚨 NOW CRITICAL: {self.cve_id}"
        elif self.change_type == "EPSS_SPIKE":
            old = f"{self.old_value:.1%}" if self.old_value else "N/A"
            new = f"{self.new_value:.1%}" if self.new_value else "N/A"
            return f"📈 EPSS SPIKE: {self.cve_id} ({old} → {new})"
        return f"{self.change_type}: {self.cve_id}"


class StateManager:
    """Manages persistent state to track seen CVEs and prevent duplicate alerts."""
    
    SCHEMA_VERSION = 1
    
    def __init__(self, path: Path):
        self.path = path
        self.data = self._load()
    
    def _load(self) -> Dict[str, Any]:
        """Load state from file, or create empty state."""
        if self.path.exists():
            try:
                with self.path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                # Validate schema version
                if data.get("schema_version") != self.SCHEMA_VERSION:
                    print("State schema version mismatch, resetting state")
                    return self._empty_state()
                return data
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: Could not load state file ({e}), starting fresh")
                return self._empty_state()
        return self._empty_state()
    
    def _empty_state(self) -> Dict[str, Any]:
        """Create empty state structure."""
        return {
            "schema_version": self.SCHEMA_VERSION,
            "last_run": None,
            "seen_cves": {},
            "statistics": {
                "total_alerts_sent": 0,
                "alerts_by_channel": {},
            }
        }
    
    def save(self) -> None:
        """Save state to file."""
        self.data["last_run"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        tmp.replace(self.path)
    
    def is_new_cve(self, cve_id: str) -> bool:
        """Check if this CVE has never been seen before."""
        return cve_id not in self.data["seen_cves"]
    
    def get_snapshot(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get the previous snapshot for a CVE."""
        entry = self.data["seen_cves"].get(cve_id)
        if entry:
            return entry.get("snapshot")
        return None
    
    def detect_changes(self, cve_id: str, item: Dict[str, Any]) -> List[Change]:
        """
        Detect changes that warrant alerting.
        
        Returns list of Change objects describing what changed.
        """
        changes: List[Change] = []
        previous = self.get_snapshot(cve_id)
        
        # New CVE - never seen before
        if previous is None:
            changes.append(Change(cve_id=cve_id, change_type="NEW_CVE"))
            return changes  # No need to check other changes for new CVEs
        
        # Check for KEV addition
        was_kev = bool(previous.get("active_threat"))
        is_kev = bool(item.get("active_threat"))
        if is_kev and not was_kev:
            changes.append(Change(
                cve_id=cve_id, 
                change_type="NEW_KEV",
                old_value=False,
                new_value=True
            ))
        
        # Check for PatchThis addition
        was_patchthis = bool(previous.get("in_patchthis"))
        is_patchthis = bool(item.get("in_patchthis"))
        if is_patchthis and not was_patchthis:
            changes.append(Change(
                cve_id=cve_id,
                change_type="NEW_PATCHTHIS", 
                old_value=False,
                new_value=True
            ))
        
        # Check for became critical
        was_critical = bool(previous.get("is_critical"))
        is_critical = bool(item.get("is_critical"))
        if is_critical and not was_critical:
            changes.append(Change(
                cve_id=cve_id,
                change_type="BECAME_CRITICAL",
                old_value=False,
                new_value=True
            ))
        
        # Check for EPSS spike (≥0.3 increase)
        old_epss = previous.get("probability_score")
        new_epss = item.get("probability_score")
        if old_epss is not None and new_epss is not None:
            try:
                old_f = float(old_epss)
                new_f = float(new_epss)
                if new_f - old_f >= 0.3:  # 30% increase threshold
                    changes.append(Change(
                        cve_id=cve_id,
                        change_type="EPSS_SPIKE",
                        old_value=old_f,
                        new_value=new_f
                    ))
            except (ValueError, TypeError):
                pass
        
        return changes
    
    def update_snapshot(self, cve_id: str, item: Dict[str, Any]) -> None:
        """Update the stored snapshot for a CVE."""
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
    
    def mark_alerted(self, cve_id: str, channels: List[str]) -> None:
        """Mark a CVE as alerted on specific channels."""
        if cve_id not in self.data["seen_cves"]:
            return
        
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        entry = self.data["seen_cves"][cve_id]
        entry["alerted_at"] = now
        
        # Add new channels to the list
        existing = set(entry.get("alerted_channels") or [])
        existing.update(channels)
        entry["alerted_channels"] = sorted(existing)
        
        # Update statistics
        self.data["statistics"]["total_alerts_sent"] += len(channels)
        for ch in channels:
            self.data["statistics"]["alerts_by_channel"][ch] = \
                self.data["statistics"]["alerts_by_channel"].get(ch, 0) + 1
    
    def prune_old_entries(self, days: int = 180) -> int:
        """Remove CVEs not seen in the specified number of days."""
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
    
    def get_stats(self) -> Dict[str, Any]:
        """Get summary statistics."""
        return {
            "total_tracked": len(self.data["seen_cves"]),
            "total_alerts_sent": self.data["statistics"]["total_alerts_sent"],
            "alerts_by_channel": self.data["statistics"]["alerts_by_channel"],
            "last_run": self.data.get("last_run"),
        }


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# GitHub API helpers
# ─────────────────────────────────────────────────────────────────────────────


def _session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "User-Agent": "VulnRadar-Notify/0.1",
            "Authorization": f"Bearer {token}",
        }
    )
    return s


def _load_items(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return payload["items"]
    if isinstance(payload, list):
        return payload
    return []


def _iter_recent_issues(session: requests.Session, repo: str, *, max_pages: int = 3) -> Iterable[Dict[str, Any]]:
    """Yield recent issues (not PRs) without using Search API."""

    base = f"https://api.github.com/repos/{repo}/issues"
    for page in range(1, max_pages + 1):
        r = session.get(
            base,
            params={"state": "all", "per_page": 100, "page": page},
            timeout=DEFAULT_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list) or not data:
            return
        for issue in data:
            if not isinstance(issue, dict):
                continue
            if "pull_request" in issue:
                continue
            yield issue


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


def _existing_notified_cves(session: requests.Session, repo: str) -> Set[str]:
    out: Set[str] = set()
    for issue in _iter_recent_issues(session, repo, max_pages=4):
        title = str(issue.get("title") or "")
        if "[VulnRadar]" not in title:
            continue
        m = _CVE_RE.search(title)
        if m:
            out.add(m.group(0).upper())
    return out


def _create_issue(session: requests.Session, repo: str, title: str, body: str, labels: Optional[List[str]] = None) -> None:
    url = f"https://api.github.com/repos/{repo}/issues"
    payload: Dict[str, Any] = {"title": title, "body": body}
    if labels:
        payload["labels"] = labels
    r = session.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def _issue_body(item: Dict[str, Any]) -> str:
    cve_id = str(item.get("cve_id") or "")
    desc = str(item.get("description") or "").strip()
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    kev = bool(item.get("active_threat"))
    patch = bool(item.get("in_patchthis"))
    watch = bool(item.get("watchlist_hit"))
    is_critical = bool(item.get("is_critical"))
    priority = "CRITICAL" if is_critical else "ALERT"
    kev_due = ""
    kev_obj = item.get("kev")
    if isinstance(kev_obj, dict):
        kev_due = str(kev_obj.get("dueDate") or "").strip()

    def fmt(x: Any, ndigits: int) -> str:
        try:
            return f"{float(x):.{ndigits}f}"
        except Exception:
            return ""

    lines = []
    lines.append(f"CVE: {cve_id}")
    lines.append(f"Priority: {priority}" if priority else "Priority: (none)")
    lines.append("")
    lines.append("Signals:")
    lines.append(f"- PatchThis: {'yes' if patch else 'no'}")
    lines.append(f"- Watchlist: {'yes' if watch else 'no'}")
    lines.append(f"- CISA KEV: {'yes' if kev else 'no'}")
    if kev_due:
        lines.append(f"- KEV Due Date: {kev_due}")
    lines.append(f"- EPSS: {fmt(epss, 3)}")
    lines.append(f"- CVSS: {fmt(cvss, 1)}")
    lines.append("")
    if desc:
        lines.append("Description:")
        lines.append(desc)
        lines.append("")
    lines.append(f"CVE.org record: https://www.cve.org/CVERecord?id={cve_id}")
    return "\n".join(lines)


def send_discord_alert(webhook_url: str, item: Dict[str, Any], changes: Optional[List[Change]] = None) -> None:
    """Send a formatted Discord embed for a CVE finding."""
    cve_id = str(item.get("cve_id") or "")
    desc = str(item.get("description") or "")[:500]
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    kev = bool(item.get("active_threat"))
    patch = bool(item.get("in_patchthis"))
    is_critical = bool(item.get("is_critical"))
    
    # Color: red for critical, orange for KEV, blue for others
    if is_critical:
        color = 0xFF0000  # Red
        priority = "🚨 CRITICAL"
    elif kev:
        color = 0xFFA500  # Orange
        priority = "⚠️ KEV"
    else:
        color = 0x3498DB  # Blue
        priority = "ℹ️ ALERT"
    
    # Add change reason to description if available
    if changes:
        change_str = " | ".join(str(c) for c in changes)
        desc = f"**Change:** {change_str}\n\n{desc}"
    
    # Format scores
    try:
        epss_str = f"{float(epss):.1%}" if epss is not None else "N/A"
    except Exception:
        epss_str = "N/A"
    try:
        cvss_str = f"{float(cvss):.1f}" if cvss is not None else "N/A"
    except Exception:
        cvss_str = "N/A"
    
    # Get KEV due date if available
    kev_due = ""
    kev_obj = item.get("kev")
    if isinstance(kev_obj, dict):
        kev_due = str(kev_obj.get("dueDate") or "")
    
    fields = [
        {"name": "EPSS", "value": epss_str, "inline": True},
        {"name": "CVSS", "value": cvss_str, "inline": True},
        {"name": "KEV", "value": "✅ Yes" if kev else "❌ No", "inline": True},
        {"name": "PatchThis", "value": "✅ Yes" if patch else "❌ No", "inline": True},
    ]
    
    if kev_due:
        fields.append({"name": "KEV Due Date", "value": kev_due, "inline": True})
    
    payload = {
        "embeds": [{
            "title": f"{priority}: {cve_id}",
            "description": desc if desc else "No description available.",
            "color": color,
            "fields": fields,
            "url": f"https://www.cve.org/CVERecord?id={cve_id}",
            "footer": {"text": "VulnRadar Alert"}
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def send_discord_summary(webhook_url: str, items: List[Dict[str, Any]], repo: str, changes_by_cve: Optional[Dict[str, tuple]] = None) -> None:
    """Send a summary embed to Discord with counts and top findings."""
    total = len(items)
    critical_count = sum(1 for i in items if bool(i.get("is_critical")))
    kev_count = sum(1 for i in items if bool(i.get("active_threat")))
    patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))
    
    # Get top 5 critical items
    critical_items = [i for i in items if bool(i.get("is_critical"))]
    critical_items.sort(key=lambda x: float(x.get("probability_score") or 0), reverse=True)
    top_5 = critical_items[:5]
    
    top_list = ""
    for i in top_5:
        cve = i.get("cve_id", "")
        epss = i.get("probability_score")
        try:
            epss_str = f"{float(epss):.1%}" if epss else "?"
        except Exception:
            epss_str = "?"
        top_list += f"• [{cve}](https://www.cve.org/CVERecord?id={cve}) (EPSS: {epss_str})\n"
    
    if not top_list:
        top_list = "No critical findings."
    
    color = 0xFF0000 if critical_count > 0 else 0x00FF00
    
    # Build change summary if available
    changes_summary = ""
    if changes_by_cve:
        new_count = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_CVE" for c in chs))
        kev_added = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_KEV" for c in chs))
        patch_added = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_PATCHTHIS" for c in chs))
        epss_spike = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "EPSS_SPIKE" for c in chs))
        
        parts = []
        if new_count > 0:
            parts.append(f"🆕 {new_count} new")
        if kev_added > 0:
            parts.append(f"⚠️ {kev_added} added to KEV")
        if patch_added > 0:
            parts.append(f"🔥 {patch_added} added to PatchThis")
        if epss_spike > 0:
            parts.append(f"📈 {epss_spike} EPSS spike")
        changes_summary = " | ".join(parts) if parts else "No significant changes"
    
    fields = [
        {"name": "Total CVEs", "value": str(total), "inline": True},
        {"name": "🚨 Critical", "value": str(critical_count), "inline": True},
        {"name": "⚠️ CISA KEV", "value": str(kev_count), "inline": True},
        {"name": "🔥 PatchThis", "value": str(patch_count), "inline": True},
    ]
    
    if changes_summary:
        fields.append({"name": "📊 Changes Since Last Run", "value": changes_summary, "inline": False})
    
    fields.append({"name": "Top Critical Findings", "value": top_list, "inline": False})
    
    payload = {
        "embeds": [{
            "title": "📊 VulnRadar Summary",
            "color": color,
            "fields": fields,
            "footer": {"text": f"Repo: {repo}"}
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


# ─────────────────────────────────────────────────────────────────────────────
# Slack Webhooks
# ─────────────────────────────────────────────────────────────────────────────

def send_slack_alert(webhook_url: str, item: Dict[str, Any], changes: Optional[List[Change]] = None) -> None:
    """Send a formatted Slack message for a CVE finding."""
    cve_id = str(item.get("cve_id") or "")
    desc = str(item.get("description") or "")[:500]
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    kev = bool(item.get("active_threat"))
    patch = bool(item.get("in_patchthis"))
    is_critical = bool(item.get("is_critical"))
    
    # Priority indicator
    if is_critical:
        priority = "🚨 *CRITICAL*"
        color = "danger"
    elif kev:
        priority = "⚠️ *KEV*"
        color = "warning"
    else:
        priority = "ℹ️ *ALERT*"
        color = "#3498DB"
    
    # Add change reason if available
    if changes:
        change_str = " | ".join(str(c) for c in changes)
        desc = f"*Change:* {change_str}\n\n{desc}"
    
    # Format scores
    try:
        epss_str = f"{float(epss):.1%}" if epss is not None else "N/A"
    except Exception:
        epss_str = "N/A"
    try:
        cvss_str = f"{float(cvss):.1f}" if cvss is not None else "N/A"
    except Exception:
        cvss_str = "N/A"
    
    cve_url = f"https://www.cve.org/CVERecord?id={cve_id}"
    
    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{priority}: <{cve_url}|{cve_id}>\n{desc}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*EPSS:* {epss_str}"},
                        {"type": "mrkdwn", "text": f"*CVSS:* {cvss_str}"},
                        {"type": "mrkdwn", "text": f"*KEV:* {'✅ Yes' if kev else '❌ No'}"},
                        {"type": "mrkdwn", "text": f"*PatchThis:* {'✅ Yes' if patch else '❌ No'}"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": "VulnRadar Alert"}]
                }
            ]
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def send_slack_summary(webhook_url: str, items: List[Dict[str, Any]], repo: str, changes_by_cve: Optional[Dict[str, tuple]] = None) -> None:
    """Send a summary message to Slack with counts and top findings."""
    total = len(items)
    critical_count = sum(1 for i in items if bool(i.get("is_critical")))
    kev_count = sum(1 for i in items if bool(i.get("active_threat")))
    patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))
    
    # Get top 5 critical items
    critical_items = [i for i in items if bool(i.get("is_critical"))]
    critical_items.sort(key=lambda x: float(x.get("probability_score") or 0), reverse=True)
    top_5 = critical_items[:5]
    
    top_list = ""
    for i in top_5:
        cve = i.get("cve_id", "")
        epss = i.get("probability_score")
        cve_url = f"https://www.cve.org/CVERecord?id={cve}"
        try:
            epss_str = f"{float(epss):.1%}" if epss else "?"
        except Exception:
            epss_str = "?"
        top_list += f"• <{cve_url}|{cve}> (EPSS: {epss_str})\n"
    
    if not top_list:
        top_list = "No critical findings."
    
    color = "danger" if critical_count > 0 else "good"
    
    # Build change summary if available
    changes_summary = ""
    if changes_by_cve:
        new_count = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_CVE" for c in chs))
        kev_added = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_KEV" for c in chs))
        patch_added = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_PATCHTHIS" for c in chs))
        epss_spike = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "EPSS_SPIKE" for c in chs))
        
        parts = []
        if new_count > 0:
            parts.append(f"🆕 {new_count} new")
        if kev_added > 0:
            parts.append(f"⚠️ {kev_added} added to KEV")
        if patch_added > 0:
            parts.append(f"🔥 {patch_added} added to PatchThis")
        if epss_spike > 0:
            parts.append(f"📈 {epss_spike} EPSS spike")
        changes_summary = " | ".join(parts) if parts else "No significant changes"
    
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "📊 VulnRadar Summary", "emoji": True}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Total CVEs:* {total}"},
                {"type": "mrkdwn", "text": f"*🚨 Critical:* {critical_count}"},
                {"type": "mrkdwn", "text": f"*⚠️ CISA KEV:* {kev_count}"},
                {"type": "mrkdwn", "text": f"*🔥 PatchThis:* {patch_count}"},
            ]
        },
    ]
    
    if changes_summary:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*📊 Changes Since Last Run:*\n{changes_summary}"}
        })
    
    blocks.extend([
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top Critical Findings:*\n{top_list}"}
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Repo: {repo}"}]
        }
    ])
    
    payload = {
        "attachments": [{
            "color": color,
            "blocks": blocks
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Teams Webhooks (Adaptive Cards)
# ─────────────────────────────────────────────────────────────────────────────

def send_teams_alert(webhook_url: str, item: Dict[str, Any], changes: Optional[List[Change]] = None) -> None:
    """Send a formatted Teams Adaptive Card for a CVE finding."""
    cve_id = str(item.get("cve_id") or "")
    desc = str(item.get("description") or "")[:500]
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    kev = bool(item.get("active_threat"))
    patch = bool(item.get("in_patchthis"))
    is_critical = bool(item.get("is_critical"))
    
    # Priority indicator and color
    if is_critical:
        priority = "🚨 CRITICAL"
        color = "attention"
    elif kev:
        priority = "⚠️ KEV"
        color = "warning"
    else:
        priority = "ℹ️ ALERT"
        color = "accent"
    
    # Add change reason if available
    if changes:
        change_str = " | ".join(str(c) for c in changes)
        desc = f"**Change:** {change_str}\n\n{desc}"
    
    # Format scores
    try:
        epss_str = f"{float(epss):.1%}" if epss is not None else "N/A"
    except Exception:
        epss_str = "N/A"
    try:
        cvss_str = f"{float(cvss):.1f}" if cvss is not None else "N/A"
    except Exception:
        cvss_str = "N/A"
    
    cve_url = f"https://www.cve.org/CVERecord?id={cve_id}"
    
    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": f"{priority}: {cve_id}",
                        "weight": "Bolder",
                        "size": "Large",
                        "color": color
                    },
                    {
                        "type": "TextBlock",
                        "text": desc if desc else "No description available.",
                        "wrap": True
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "EPSS", "value": epss_str},
                            {"title": "CVSS", "value": cvss_str},
                            {"title": "KEV", "value": "✅ Yes" if kev else "❌ No"},
                            {"title": "PatchThis", "value": "✅ Yes" if patch else "❌ No"},
                        ]
                    }
                ],
                "actions": [
                    {
                        "type": "Action.OpenUrl",
                        "title": "View CVE Details",
                        "url": cve_url
                    }
                ]
            }
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def send_teams_summary(webhook_url: str, items: List[Dict[str, Any]], repo: str, changes_by_cve: Optional[Dict[str, tuple]] = None) -> None:
    """Send a summary Adaptive Card to Teams with counts and top findings."""
    total = len(items)
    critical_count = sum(1 for i in items if bool(i.get("is_critical")))
    kev_count = sum(1 for i in items if bool(i.get("active_threat")))
    patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))
    
    # Get top 5 critical items
    critical_items = [i for i in items if bool(i.get("is_critical"))]
    critical_items.sort(key=lambda x: float(x.get("probability_score") or 0), reverse=True)
    top_5 = critical_items[:5]
    
    top_list = ""
    for i in top_5:
        cve = i.get("cve_id", "")
        epss = i.get("probability_score")
        try:
            epss_str = f"{float(epss):.1%}" if epss else "?"
        except Exception:
            epss_str = "?"
        top_list += f"- [{cve}](https://www.cve.org/CVERecord?id={cve}) (EPSS: {epss_str})\n"
    
    if not top_list:
        top_list = "No critical findings."
    
    color = "attention" if critical_count > 0 else "good"
    
    # Build change summary if available
    changes_summary = ""
    if changes_by_cve:
        new_count = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_CVE" for c in chs))
        kev_added = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_KEV" for c in chs))
        patch_added = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_PATCHTHIS" for c in chs))
        epss_spike = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "EPSS_SPIKE" for c in chs))
        
        parts = []
        if new_count > 0:
            parts.append(f"🆕 {new_count} new")
        if kev_added > 0:
            parts.append(f"⚠️ {kev_added} added to KEV")
        if patch_added > 0:
            parts.append(f"🔥 {patch_added} added to PatchThis")
        if epss_spike > 0:
            parts.append(f"📈 {epss_spike} EPSS spike")
        changes_summary = " | ".join(parts) if parts else "No significant changes"
    
    body = [
        {
            "type": "TextBlock",
            "text": "📊 VulnRadar Summary",
            "weight": "Bolder",
            "size": "Large"
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {"type": "TextBlock", "text": "Total CVEs", "weight": "Bolder"},
                        {"type": "TextBlock", "text": str(total), "size": "ExtraLarge", "color": color}
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {"type": "TextBlock", "text": "🚨 Critical", "weight": "Bolder"},
                        {"type": "TextBlock", "text": str(critical_count), "size": "ExtraLarge", "color": "attention"}
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {"type": "TextBlock", "text": "⚠️ KEV", "weight": "Bolder"},
                        {"type": "TextBlock", "text": str(kev_count), "size": "ExtraLarge", "color": "warning"}
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {"type": "TextBlock", "text": "🔥 PatchThis", "weight": "Bolder"},
                        {"type": "TextBlock", "text": str(patch_count), "size": "ExtraLarge"}
                    ]
                }
            ]
        },
    ]
    
    if changes_summary:
        body.append({
            "type": "TextBlock",
            "text": f"**📊 Changes Since Last Run:** {changes_summary}",
            "wrap": True,
            "spacing": "Medium"
        })
    
    body.extend([
        {
            "type": "TextBlock",
            "text": "**Top Critical Findings:**",
            "weight": "Bolder",
            "spacing": "Medium"
        },
        {
            "type": "TextBlock",
            "text": top_list,
            "wrap": True
        },
        {
            "type": "TextBlock",
            "text": f"Repo: {repo}",
            "size": "Small",
            "isSubtle": True,
            "spacing": "Medium"
        }
    ])
    
    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body
            }
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def main() -> int:
    p = argparse.ArgumentParser(description="VulnRadar notifications (GitHub Issues + Discord)")
    p.add_argument("--in", dest="inp", default="data/radar_data.json", help="Path to radar_data.json")
    p.add_argument("--max", dest="max_items", type=int, default=25, help="Max issues to create per run")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print would-notify CVEs without creating issues",
    )
    # State management options
    p.add_argument(
        "--state",
        dest="state_file",
        default="data/state.json",
        help="Path to state file for tracking alerts (default: data/state.json)",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Ignore state and force all notifications (for testing)",
    )
    p.add_argument(
        "--no-state",
        action="store_true",
        help="Don't use state tracking (behaves like old version, may spam)",
    )
    # Discord options
    p.add_argument(
        "--discord-webhook",
        dest="discord_webhook",
        default=os.environ.get("DISCORD_WEBHOOK_URL"),
        help="Discord webhook URL (or set DISCORD_WEBHOOK_URL env var)",
    )
    p.add_argument(
        "--discord-summary-only",
        action="store_true",
        help="Only send a summary to Discord, not individual alerts",
    )
    p.add_argument(
        "--discord-max",
        dest="discord_max",
        type=int,
        default=10,
        help="Max individual Discord alerts per run (default: 10)",
    )
    # Slack options
    p.add_argument(
        "--slack-webhook",
        dest="slack_webhook",
        default=os.environ.get("SLACK_WEBHOOK_URL"),
        help="Slack webhook URL (or set SLACK_WEBHOOK_URL env var)",
    )
    p.add_argument(
        "--slack-summary-only",
        action="store_true",
        help="Only send a summary to Slack, not individual alerts",
    )
    p.add_argument(
        "--slack-max",
        dest="slack_max",
        type=int,
        default=10,
        help="Max individual Slack alerts per run (default: 10)",
    )
    # Microsoft Teams options
    p.add_argument(
        "--teams-webhook",
        dest="teams_webhook",
        default=os.environ.get("TEAMS_WEBHOOK_URL"),
        help="Microsoft Teams webhook URL (or set TEAMS_WEBHOOK_URL env var)",
    )
    p.add_argument(
        "--teams-summary-only",
        action="store_true",
        help="Only send a summary to Teams, not individual alerts",
    )
    p.add_argument(
        "--teams-max",
        dest="teams_max",
        type=int,
        default=10,
        help="Max individual Teams alerts per run (default: 10)",
    )
    args = p.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        raise SystemExit("GITHUB_REPOSITORY is required")
    if not token:
        raise SystemExit("GITHUB_TOKEN (or GH_TOKEN) is required")

    items = _load_items(Path(args.inp))
    
    # Initialize state manager (unless --no-state)
    state: Optional[StateManager] = None
    if not args.no_state:
        state = StateManager(Path(args.state_file))
        stats = state.get_stats()
        print(f"State loaded: {stats['total_tracked']} CVEs tracked, {stats['total_alerts_sent']} alerts sent historically")
        
        # Prune old entries on each run
        pruned = state.prune_old_entries(days=180)
        if pruned > 0:
            print(f"Pruned {pruned} CVEs not seen in 180 days")

    # Detect changes for all items and build candidates list
    # Change format: {cve_id: (item, [Change, ...])}
    changes_by_cve: Dict[str, tuple] = {}
    
    for it in items:
        cve_id = str(it.get("cve_id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        
        if state and not args.force:
            changes = state.detect_changes(cve_id, it)
            # Update snapshot regardless of whether there are changes
            state.update_snapshot(cve_id, it)
            
            if changes:
                changes_by_cve[cve_id] = (it, changes)
        else:
            # No state or --force: treat all critical items as "new"
            if bool(it.get("is_critical")):
                changes_by_cve[cve_id] = (it, [Change(cve_id=cve_id, change_type="NEW_CVE")])
    
    # Filter to critical items that have changes
    candidates: List[Dict[str, Any]] = []
    for _cve_id, (it, _changes) in changes_by_cve.items():
        if bool(it.get("is_critical")):
            candidates.append(it)

    # Sort to notify highest first
    def key(it: Dict[str, Any]) -> tuple:
        try:
            epss = float(it.get("probability_score") or 0.0)
        except Exception:
            epss = 0.0
        try:
            cvss = float(it.get("cvss_score") or 0.0)
        except Exception:
            cvss = 0.0
        return (
            1 if bool(it.get("is_critical")) else 0,
            1 if bool(it.get("active_threat")) else 0,
            epss,
            cvss,
        )

    candidates = sorted(candidates, key=key, reverse=True)
    
    # Print change summary
    if state and not args.force:
        if changes_by_cve:
            print(f"\n📊 Detected {len(changes_by_cve)} CVEs with changes:")
            for _cve_id, (_it, changes) in list(changes_by_cve.items())[:10]:
                for change in changes:
                    print(f"  {change}")
            if len(changes_by_cve) > 10:
                print(f"  ... and {len(changes_by_cve) - 10} more")
            print()
        else:
            print("\n✅ No new changes detected. Skipping notifications.\n")
    
    # If no changes (and state is enabled), skip webhook notifications
    if state and not args.force and not changes_by_cve:
        # Still save state to update last_run
        if not args.dry_run:
            state.save()
            print(f"State saved to {args.state_file}")
        return 0

    session = _session(token)
    existing = _existing_notified_cves(session, repo)
    created = 0
    
    # Check if issues are enabled on the repo
    issues_enabled = True
    try:
        r = session.get(f"https://api.github.com/repos/{repo}", timeout=DEFAULT_TIMEOUT)
        if r.ok:
            repo_data = r.json()
            issues_enabled = repo_data.get("has_issues", True)
    except Exception:
        pass  # Assume issues are enabled if we can't check
    
    if not issues_enabled:
        print(f"GitHub Issues are disabled on {repo}, skipping issue creation.")
    else:
        for it in candidates:
            if created >= args.max_items:
                break
            cve_id = str(it.get("cve_id") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue

            if cve_id in existing:
                continue

            priority = "CRITICAL" if bool(it.get("is_critical")) else "ALERT"
            title = f"[VulnRadar] {priority}: {cve_id}"
            body = _issue_body(it)
            labels = ["vulnradar", "alert"]
            if bool(it.get("is_critical")):
                labels.append("critical")
            if bool(it.get("active_threat")):
                labels.append("kev")

            if args.dry_run:
                print(f"DRY RUN: would create issue: {title}")
                created += 1
                continue

            try:
                _create_issue(session, repo, title=title, body=body, labels=labels)
                print(f"Created issue for {cve_id}")
                existing.add(cve_id)
                created += 1
            except Exception as e:
                print(f"Failed to create issue for {cve_id}: {e}")
                break

        print(f"Done. Created {created} GitHub issues.")
    
    # Track channels alerted for state
    alerted_channels: Dict[str, List[str]] = {}  # cve_id -> list of channels
    
    # Discord notifications
    if args.discord_webhook:
        print("Sending Discord notifications...")
        try:
            # Only send summary if there are changes (or no state/force)
            if changes_by_cve or args.force or args.no_state:
                send_discord_summary(args.discord_webhook, items, repo, changes_by_cve if state else None)
                print("Sent Discord summary.")
            
            # Send individual alerts unless summary-only
            if not args.discord_summary_only:
                discord_sent = 0
                for it in candidates[:args.discord_max]:
                    cve_id = str(it.get("cve_id") or "").strip().upper()
                    changes = changes_by_cve.get(cve_id, (None, []))[1] if changes_by_cve else []
                    
                    if args.dry_run:
                        print(f"DRY RUN: would send Discord alert for {cve_id}")
                    else:
                        # Rate limit: Discord allows ~30 requests/minute per webhook
                        time.sleep(0.5)
                        send_discord_alert(args.discord_webhook, it, changes)
                        print(f"Sent Discord alert for {cve_id}")
                        # Track for state
                        if cve_id not in alerted_channels:
                            alerted_channels[cve_id] = []
                        alerted_channels[cve_id].append("discord")
                    discord_sent += 1
                print(f"Sent {discord_sent} Discord alerts.")
        except Exception as e:
            print(f"Discord notification failed: {e}")
    
    # Slack notifications
    if args.slack_webhook:
        print("Sending Slack notifications...")
        try:
            # Only send summary if there are changes
            if changes_by_cve or args.force or args.no_state:
                send_slack_summary(args.slack_webhook, items, repo, changes_by_cve if state else None)
                print("Sent Slack summary.")
            
            # Send individual alerts unless summary-only
            if not args.slack_summary_only:
                slack_sent = 0
                for it in candidates[:args.slack_max]:
                    cve_id = str(it.get("cve_id") or "").strip().upper()
                    changes = changes_by_cve.get(cve_id, (None, []))[1] if changes_by_cve else []
                    
                    if args.dry_run:
                        print(f"DRY RUN: would send Slack alert for {cve_id}")
                    else:
                        # Rate limit: Slack allows ~1 request/second
                        time.sleep(1.0)
                        send_slack_alert(args.slack_webhook, it, changes)
                        print(f"Sent Slack alert for {cve_id}")
                        if cve_id not in alerted_channels:
                            alerted_channels[cve_id] = []
                        alerted_channels[cve_id].append("slack")
                    slack_sent += 1
                print(f"Sent {slack_sent} Slack alerts.")
        except Exception as e:
            print(f"Slack notification failed: {e}")
    
    # Microsoft Teams notifications
    if args.teams_webhook:
        print("Sending Teams notifications...")
        try:
            # Only send summary if there are changes
            if changes_by_cve or args.force or args.no_state:
                send_teams_summary(args.teams_webhook, items, repo, changes_by_cve if state else None)
                print("Sent Teams summary.")
            
            # Send individual alerts unless summary-only
            if not args.teams_summary_only:
                teams_sent = 0
                for it in candidates[:args.teams_max]:
                    cve_id = str(it.get("cve_id") or "").strip().upper()
                    changes = changes_by_cve.get(cve_id, (None, []))[1] if changes_by_cve else []
                    
                    if args.dry_run:
                        print(f"DRY RUN: would send Teams alert for {cve_id}")
                    else:
                        # Rate limit: Teams allows ~4 requests/second
                        time.sleep(0.5)
                        send_teams_alert(args.teams_webhook, it, changes)
                        print(f"Sent Teams alert for {cve_id}")
                        if cve_id not in alerted_channels:
                            alerted_channels[cve_id] = []
                        alerted_channels[cve_id].append("teams")
                    teams_sent += 1
                print(f"Sent {teams_sent} Teams alerts.")
        except Exception as e:
            print(f"Teams notification failed: {e}")
    
    # Update state with alerted CVEs
    if state and not args.dry_run:
        for cve_id, channels in alerted_channels.items():
            state.mark_alerted(cve_id, channels)
        state.save()
        stats = state.get_stats()
        print(f"State saved to {args.state_file} ({stats['total_tracked']} CVEs tracked)")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
