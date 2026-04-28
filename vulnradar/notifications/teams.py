"""Microsoft Teams notification provider."""

from typing import Any

import requests

from ..state import Change
from .base import NotificationProvider

DEFAULT_TIMEOUT = (10, 60)


class TeamsProvider(NotificationProvider):
    """Send VulnRadar alerts via Microsoft Teams webhooks.

    Uses Adaptive Cards v1.4 for rich, interactive notifications.

    Args:
        webhook_url: Teams incoming webhook URL.
        max_alerts: Maximum individual alerts per run.
    """

    name = "teams"
    rate_limit_delay = 0.5  # Teams allows ~4 req/sec

    def __init__(self, webhook_url: str, max_alerts: int = 10):
        self.webhook_url = webhook_url
        self.max_alerts = max_alerts

    def send_alert(self, item: dict[str, Any], changes: list[Change] | None = None) -> None:
        """Send a Teams Adaptive Card for a single CVE.

        Args:
            item: Radar data item dict.
            changes: Optional list of changes that triggered this alert.
        """
        cve_id = str(item.get("cve_id") or "")
        desc = str(item.get("description") or "")[:500]
        epss = item.get("probability_score")
        cvss = item.get("cvss_score")
        kev = bool(item.get("active_threat"))
        patch = bool(item.get("in_patchthis"))
        is_critical = bool(item.get("is_critical"))

        if is_critical:
            priority, color = "🚨 CRITICAL", "attention"
        elif kev:
            priority, color = "⚠️ KEV", "warning"
        else:
            priority, color = "ℹ️ ALERT", "accent"

        if changes:
            change_str = " | ".join(str(c) for c in changes)
            desc = f"**Change:** {change_str}\n\n{desc}"

        cve_url = f"https://www.cve.org/CVERecord?id={cve_id}"

        payload = {
            "type": "message",
            "attachments": [
                {
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
                                "color": color,
                            },
                            {"type": "TextBlock", "text": desc or "No description available.", "wrap": True},
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "EPSS", "value": self._format_epss(epss)},
                                    {"title": "CVSS", "value": self._format_cvss(cvss)},
                                    {"title": "KEV", "value": "✅ Yes" if kev else "❌ No"},
                                    {"title": "PatchThis", "value": "✅ Yes" if patch else "❌ No"},
                                ],
                            },
                        ],
                        "actions": [{"type": "Action.OpenUrl", "title": "View CVE Details", "url": cve_url}],
                    },
                }
            ],
        }

        r = requests.post(self.webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()

    def send_summary(
        self,
        items: list[dict[str, Any]],
        repo: str,
        changes_by_cve: dict[str, tuple] | None = None,
    ) -> None:
        """Send a summary Adaptive Card to Teams.

        Args:
            items: All radar items.
            repo: GitHub repository slug.
            changes_by_cve: Optional dict of CVE ID to ``(item, [Change])``
                tuples.
        """
        total = len(items)
        critical_count = sum(1 for i in items if bool(i.get("is_critical")))
        kev_count = sum(1 for i in items if bool(i.get("active_threat")))
        patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))

        top_5 = self._top_critical(items, n=5)
        top_list = ""
        for i in top_5:
            cve = i.get("cve_id", "")
            top_list += f"- [{cve}](https://www.cve.org/CVERecord?id={cve}) (EPSS: {self._format_epss(i.get('probability_score'))})\n"
        if not top_list:
            top_list = "No critical findings."

        color = "attention" if critical_count > 0 else "good"
        changes_summary = self._build_changes_summary(changes_by_cve)

        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "text": "📊 VulnRadar Summary", "weight": "Bolder", "size": "Large"},
            {
                "type": "ColumnSet",
                "columns": [
                    {
                        "type": "Column",
                        "width": "stretch",
                        "items": [
                            {"type": "TextBlock", "text": "Total CVEs", "weight": "Bolder"},
                            {"type": "TextBlock", "text": str(total), "size": "ExtraLarge", "color": color},
                        ],
                    },
                    {
                        "type": "Column",
                        "width": "stretch",
                        "items": [
                            {"type": "TextBlock", "text": "🚨 Critical", "weight": "Bolder"},
                            {
                                "type": "TextBlock",
                                "text": str(critical_count),
                                "size": "ExtraLarge",
                                "color": "attention",
                            },
                        ],
                    },
                    {
                        "type": "Column",
                        "width": "stretch",
                        "items": [
                            {"type": "TextBlock", "text": "⚠️ KEV", "weight": "Bolder"},
                            {"type": "TextBlock", "text": str(kev_count), "size": "ExtraLarge", "color": "warning"},
                        ],
                    },
                    {
                        "type": "Column",
                        "width": "stretch",
                        "items": [
                            {"type": "TextBlock", "text": "🔥 Exploit Intel", "weight": "Bolder"},
                            {"type": "TextBlock", "text": str(patch_count), "size": "ExtraLarge"},
                        ],
                    },
                ],
            },
        ]

        if changes_summary:
            body.append(
                {
                    "type": "TextBlock",
                    "text": f"**📊 Changes Since Last Run:** {changes_summary}",
                    "wrap": True,
                    "spacing": "Medium",
                }
            )

        body.extend(
            [
                {"type": "TextBlock", "text": "**Top Critical Findings:**", "weight": "Bolder", "spacing": "Medium"},
                {"type": "TextBlock", "text": top_list, "wrap": True},
                {"type": "TextBlock", "text": f"Repo: {repo}", "size": "Small", "isSubtle": True, "spacing": "Medium"},
            ]
        )

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body,
                    },
                }
            ],
        }

        r = requests.post(self.webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()

    def send_baseline(
        self,
        items: list[dict[str, Any]],
        critical_items: list[dict[str, Any]],
        repo: str,
        *,
        vendors: list[str] | None = None,
        products: list[str] | None = None,
    ) -> None:
        """Send a first-run baseline summary to Teams.

        Args:
            items: All radar items.
            critical_items: Subset of items marked as critical.
            repo: GitHub repository slug.
            vendors: List of monitored vendors from watchlist.
            products: List of monitored products from watchlist.
        """
        total = len(items)
        critical_count = len(critical_items)
        kev_count = sum(1 for i in items if bool(i.get("active_threat")))
        patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))

        sorted_critical = sorted(critical_items, key=lambda x: float(x.get("probability_score") or 0), reverse=True)[
            :10
        ]
        top_list = ""
        for item in sorted_critical:
            cve = item.get("cve_id", "")
            kev_icon = "🔴" if item.get("active_threat") else "⚪"
            top_list += f"- {kev_icon} [{cve}](https://www.cve.org/CVERecord?id={cve}) (EPSS: {self._format_epss(item.get('probability_score'))})\n"
        if not top_list:
            top_list = "No critical findings."

        # Build monitoring list
        monitoring_parts = []
        if vendors:
            monitoring_parts.append(f"**Vendors:** {', '.join(vendors)}")
        if products:
            monitoring_parts.append(f"**Products:** {', '.join(products)}")
        monitoring_text = "\n\n".join(monitoring_parts) if monitoring_parts else "_No watchlist configured_"

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": "🚀 VulnRadar Baseline Established",
                                "weight": "Bolder",
                                "size": "Large",
                                "color": "Good",
                            },
                            {
                                "type": "TextBlock",
                                "text": (
                                    "**First run complete!** Your vulnerability baseline has been established.\n\n"
                                    "Going forward, you'll only receive alerts for:\n"
                                    "- 🆕 New CVEs matching your watchlist\n"
                                    "- ⚠️ CVEs added to CISA KEV\n"
                                    "- 🔥 CVEs added to PatchThis\n"
                                    "- 📈 Significant EPSS increases"
                                ),
                                "wrap": True,
                            },
                            {
                                "type": "TextBlock",
                                "text": "**📋 Monitoring:**",
                                "weight": "Bolder",
                                "spacing": "Medium",
                            },
                            {"type": "TextBlock", "text": monitoring_text, "wrap": True},
                            {
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {"type": "TextBlock", "text": "Total CVEs", "weight": "Bolder"},
                                            {"type": "TextBlock", "text": str(total), "size": "ExtraLarge"},
                                        ],
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {"type": "TextBlock", "text": "🚨 Critical", "weight": "Bolder"},
                                            {
                                                "type": "TextBlock",
                                                "text": str(critical_count),
                                                "size": "ExtraLarge",
                                                "color": "Attention",
                                            },
                                        ],
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {"type": "TextBlock", "text": "⚠️ KEV", "weight": "Bolder"},
                                            {
                                                "type": "TextBlock",
                                                "text": str(kev_count),
                                                "size": "ExtraLarge",
                                                "color": "Warning",
                                            },
                                        ],
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {"type": "TextBlock", "text": "🔥 Exploit Intel", "weight": "Bolder"},
                                            {"type": "TextBlock", "text": str(patch_count), "size": "ExtraLarge"},
                                        ],
                                    },
                                ],
                            },
                            {
                                "type": "TextBlock",
                                "text": "**Top 10 Critical (by EPSS):**",
                                "weight": "Bolder",
                                "spacing": "Medium",
                            },
                            {"type": "TextBlock", "text": top_list, "wrap": True},
                            {"type": "TextBlock", "text": repo, "size": "Small", "isSubtle": True, "spacing": "Medium"},
                        ],
                    },
                }
            ],
        }

        r = requests.post(self.webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
