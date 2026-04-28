#!/usr/bin/env python3
"""VulnRadar Notify — thin shim.

This file re-exports all public symbols from the ``vulnradar`` package so that
existing ``from notify import …`` imports, CI workflows, and ``python notify.py``
invocations continue to work unchanged.

The real implementation lives in ``vulnradar/``.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import requests  # noqa: F401 — kept so tests can mock notify.requests.post

# ── CLI helpers ──────────────────────────────────────────────────────────────
from vulnradar.cli import (
    _generate_demo_cve,
    _load_items,
    main_notify,
)

# ── GitHub Issues statics ────────────────────────────────────────────────────
from vulnradar.notifications.github_issues import GitHubIssueProvider

# ── Core types ───────────────────────────────────────────────────────────────
from vulnradar.state import Change, StateManager

# Backward-compatible aliases for standalone functions the tests import:


def _issue_body(item: Dict[str, Any], changes: list | None = None) -> str:
    return GitHubIssueProvider.format_issue_body(item, changes)


def _escalation_comment(change: Change, item: Dict[str, Any]) -> str:
    return GitHubIssueProvider.format_escalation_comment(change, item)


def _extract_dynamic_labels(item: Dict[str, Any], max_labels: int = 3) -> List[str]:
    return GitHubIssueProvider.extract_dynamic_labels(item, max_labels)


def _extract_severity_label(item: Dict[str, Any]) -> Optional[str]:
    return GitHubIssueProvider.extract_severity_label(item)


def _parse_project_url(url: str) -> Optional[Dict[str, Any]]:
    return GitHubIssueProvider._parse_project_url(url)


def _create_weekly_summary_issue(
    session: requests.Session,
    repo: str,
    items: List[Dict[str, Any]],
    project_url: Optional[str],
) -> None:
    """Backward-compat wrapper for weekly summary issue creation.

    The old standalone function used (session, repo, items, project_url).
    The new provider uses an instance. We instantiate one temporarily.
    """
    import os

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    provider = GitHubIssueProvider(
        repo=repo,
        token=token,
        project_url=project_url,
    )
    # Inject the session the caller supplied so test mocks on it still work.
    provider.session = session
    provider.create_weekly_summary(items, state=None)


# ── Webhook provider wrappers ───────────────────────────────────────────────
# The tests patch ``notify.requests.post``. By importing ``requests`` at the
# module level above and having these thin wrappers call the provider methods
# (which also call ``requests.post``), the mock path needs to match the
# provider module.  For full backward compat we keep the wrapper signature
# identical and document the new mock path in the test updates.

from vulnradar.notifications.discord import DiscordProvider  # noqa: E402
from vulnradar.notifications.slack import SlackProvider  # noqa: E402
from vulnradar.notifications.teams import TeamsProvider  # noqa: E402


def send_discord_alert(webhook_url: str, item: Dict[str, Any]) -> None:
    DiscordProvider(webhook_url).send_alert(item)


def send_discord_summary(
    webhook_url: str,
    items: List[Dict[str, Any]],
    repo: str,
) -> None:
    DiscordProvider(webhook_url).send_summary(items, repo)


def send_slack_alert(webhook_url: str, item: Dict[str, Any]) -> None:
    SlackProvider(webhook_url).send_alert(item)


def send_teams_alert(webhook_url: str, item: Dict[str, Any]) -> None:
    TeamsProvider(webhook_url).send_alert(item)


def main() -> int:
    return main_notify()


if __name__ == "__main__":
    raise SystemExit(main())
