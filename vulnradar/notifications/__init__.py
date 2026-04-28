"""Notification providers for VulnRadar.

This package implements the Strategy pattern for sending alerts
to different platforms. Each provider extends ``NotificationProvider``
and implements ``send_alert``, ``send_summary``, and ``send_baseline``.

Adding a new provider (e.g., Matrix, PagerDuty) requires only:
1. Create a new file in this package.
2. Subclass ``NotificationProvider``.
3. Register it in ``load_providers()``.
"""

from .base import NotificationProvider
from .discord import DiscordProvider
from .github_issues import GitHubIssueProvider
from .slack import SlackProvider
from .teams import TeamsProvider

__all__ = [
    "NotificationProvider",
    "DiscordProvider",
    "SlackProvider",
    "TeamsProvider",
    "GitHubIssueProvider",
    "load_providers",
    "load_routed_providers",
    "filter_items_for_route",
]


def load_providers(
    *,
    discord_webhook: str | None = None,
    discord_max: int = 10,
    slack_webhook: str | None = None,
    slack_max: int = 10,
    teams_webhook: str | None = None,
    teams_max: int = 10,
) -> list[NotificationProvider]:
    """Dynamically create notification providers based on configuration.

    Args:
        discord_webhook: Discord webhook URL.
        discord_max: Max individual Discord alerts per run.
        slack_webhook: Slack webhook URL.
        slack_max: Max individual Slack alerts per run.
        teams_webhook: Teams webhook URL.
        teams_max: Max individual Teams alerts per run.

    Returns:
        List of active notification providers.
    """
    providers: list[NotificationProvider] = []
    if discord_webhook:
        providers.append(DiscordProvider(webhook_url=discord_webhook, max_alerts=discord_max))
    if slack_webhook:
        providers.append(SlackProvider(webhook_url=slack_webhook, max_alerts=slack_max))
    if teams_webhook:
        providers.append(TeamsProvider(webhook_url=teams_webhook, max_alerts=teams_max))
    return providers


def filter_items_for_route(
    items: list[dict],
    route_filter: str,
) -> list[dict]:
    """Filter radar items based on a notification route filter.

    Args:
        items: Full list of radar items.
        route_filter: One of ``all``, ``critical``, ``kev``, ``watchlist``.

    Returns:
        Filtered list of items matching the route's criteria.
    """
    if route_filter == "all":
        return items
    if route_filter == "critical":
        return [i for i in items if bool(i.get("is_critical"))]
    if route_filter == "kev":
        return [i for i in items if bool(i.get("active_threat"))]
    if route_filter == "watchlist":
        return [i for i in items if bool(i.get("watchlist_hit"))]
    return items


def load_routed_providers(
    notifications_config: "NotificationsConfig",  # noqa: F821
) -> list[tuple[NotificationProvider, str]]:
    """Create providers from YAML-based notification routing config.

    Each route produces a separate provider instance with its own
    webhook URL, max alerts, and severity filter.

    Args:
        notifications_config: ``NotificationsConfig`` from the watchlist.

    Returns:
        List of ``(provider, filter_name)`` tuples.
    """
    routed: list[tuple[NotificationProvider, str]] = []

    for route in notifications_config.discord:
        url = _resolve_env(route.url)
        if url:
            routed.append(
                (
                    DiscordProvider(webhook_url=url, max_alerts=route.max_alerts),
                    route.filter,
                )
            )

    for route in notifications_config.slack:
        url = _resolve_env(route.url)
        if url:
            routed.append(
                (
                    SlackProvider(webhook_url=url, max_alerts=route.max_alerts),
                    route.filter,
                )
            )

    for route in notifications_config.teams:
        url = _resolve_env(route.url)
        if url:
            routed.append(
                (
                    TeamsProvider(webhook_url=url, max_alerts=route.max_alerts),
                    route.filter,
                )
            )

    return routed


def _resolve_env(value: str) -> str | None:
    """Resolve ``$ENV_VAR`` references in a string.

    If the value starts with ``$``, look it up in ``os.environ``.
    Otherwise return as-is.  Returns ``None`` if the env var is unset.
    """
    import os

    if value.startswith("$"):
        return os.environ.get(value[1:])
    return value if value else None
