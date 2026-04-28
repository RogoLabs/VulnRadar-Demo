"""Slack notification provider."""

from typing import Any

import requests

from ..state import Change
from .base import NotificationProvider

DEFAULT_TIMEOUT = (10, 60)


class SlackProvider(NotificationProvider):
    """Send VulnRadar alerts via Slack webhooks.

    Uses Slack's Block Kit for rich, formatted notifications.

    Args:
        webhook_url: Slack incoming webhook URL.
        max_alerts: Maximum individual alerts per run.
    """

    name = "slack"
    rate_limit_delay = 1.0  # Slack allows ~1 req/sec

    def __init__(self, webhook_url: str, max_alerts: int = 10):
        self.webhook_url = webhook_url
        self.max_alerts = max_alerts

    def send_alert(self, item: dict[str, Any], changes: list[Change] | None = None) -> None:
        """Send a Slack message for a single CVE.

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
            priority, color = "🚨 *CRITICAL*", "danger"
        elif kev:
            priority, color = "⚠️ *KEV*", "warning"
        else:
            priority, color = "ℹ️ *ALERT*", "#3498DB"

        if changes:
            change_str = " | ".join(str(c) for c in changes)
            desc = f"*Change:* {change_str}\n\n{desc}"

        cve_url = f"https://www.cve.org/CVERecord?id={cve_id}"

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"{priority}: <{cve_url}|{cve_id}>\n{desc}"},
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*EPSS:* {self._format_epss(epss)}"},
                                {"type": "mrkdwn", "text": f"*CVSS:* {self._format_cvss(cvss)}"},
                                {"type": "mrkdwn", "text": f"*KEV:* {'✅ Yes' if kev else '❌ No'}"},
                                {"type": "mrkdwn", "text": f"*PatchThis:* {'✅ Yes' if patch else '❌ No'}"},
                            ],
                        },
                        {"type": "context", "elements": [{"type": "mrkdwn", "text": "VulnRadar Alert"}]},
                    ],
                }
            ]
        }

        r = requests.post(self.webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()

    def send_summary(
        self,
        items: list[dict[str, Any]],
        repo: str,
        changes_by_cve: dict[str, tuple] | None = None,
    ) -> None:
        """Send a summary message to Slack.

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
            cve_url = f"https://www.cve.org/CVERecord?id={cve}"
            top_list += f"• <{cve_url}|{cve}> (EPSS: {self._format_epss(i.get('probability_score'))})\n"
        if not top_list:
            top_list = "No critical findings."

        color = "danger" if critical_count > 0 else "good"
        changes_summary = self._build_changes_summary(changes_by_cve)

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "📊 VulnRadar Summary", "emoji": True}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total CVEs:* {total}"},
                    {"type": "mrkdwn", "text": f"*🚨 Critical:* {critical_count}"},
                    {"type": "mrkdwn", "text": f"*⚠️ CISA KEV:* {kev_count}"},
                    {"type": "mrkdwn", "text": f"*🔥 Exploit Intel:* {patch_count}"},
                ],
            },
        ]

        if changes_summary:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*📊 Changes Since Last Run:*\n{changes_summary}"},
                }
            )

        blocks.extend(
            [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Top Critical Findings:*\n{top_list}"}},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Repo: {repo}"}]},
            ]
        )

        payload = {"attachments": [{"color": color, "blocks": blocks}]}

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
        """Send a first-run baseline summary to Slack.

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
            cve_url = f"https://www.cve.org/CVERecord?id={cve}"
            top_list += f"{kev_icon} <{cve_url}|{cve}> (EPSS: {self._format_epss(item.get('probability_score'))})\n"
        if not top_list:
            top_list = "No critical findings."

        # Build monitoring list
        monitoring_parts = []
        if vendors:
            monitoring_parts.append(f"*Vendors:* {', '.join(vendors)}")
        if products:
            monitoring_parts.append(f"*Products:* {', '.join(products)}")
        monitoring_text = "\n".join(monitoring_parts) if monitoring_parts else "_No watchlist configured_"

        payload = {
            "attachments": [
                {
                    "color": "good",
                    "blocks": [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": "🚀 VulnRadar Baseline Established", "emoji": True},
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    "*First run complete!* Your vulnerability baseline has been established.\n\n"
                                    "Going forward, you'll only receive alerts for:\n"
                                    "• 🆕 New CVEs matching your watchlist\n"
                                    "• ⚠️ CVEs added to CISA KEV\n"
                                    "• 🔥 CVEs added to PatchThis\n"
                                    "• 📈 Significant EPSS increases"
                                ),
                            },
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*📋 Monitoring:*\n{monitoring_text}"},
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Total CVEs:* {total}"},
                                {"type": "mrkdwn", "text": f"*🚨 Critical:* {critical_count}"},
                                {"type": "mrkdwn", "text": f"*⚠️ CISA KEV:* {kev_count}"},
                                {"type": "mrkdwn", "text": f"*🔥 Exploit Intel:* {patch_count}"},
                            ],
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*Top 10 Critical (by EPSS):*\n{top_list}"},
                        },
                        {"type": "context", "elements": [{"type": "mrkdwn", "text": repo}]},
                    ],
                }
            ]
        }

        r = requests.post(self.webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
