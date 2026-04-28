"""Discord notification provider."""

from typing import Any

import requests

from ..state import Change
from .base import NotificationProvider

DEFAULT_TIMEOUT = (10, 60)


class DiscordProvider(NotificationProvider):
    """Send VulnRadar alerts via Discord webhooks.

    Uses Discord's embed format for rich, color-coded notifications.

    Args:
        webhook_url: Discord webhook URL.
        max_alerts: Maximum individual alerts per run.
    """

    name = "discord"
    rate_limit_delay = 0.5  # Discord allows ~30 req/min

    def __init__(self, webhook_url: str, max_alerts: int = 10):
        self.webhook_url = webhook_url
        self.max_alerts = max_alerts

    def send_alert(self, item: dict[str, Any], changes: list[Change] | None = None) -> None:
        """Send a Discord embed for a single CVE.

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
            color, priority = 0xFF0000, "🚨 CRITICAL"
        elif kev:
            color, priority = 0xFFA500, "⚠️ KEV"
        else:
            color, priority = 0x3498DB, "ℹ️ ALERT"

        if changes:
            change_str = " | ".join(str(c) for c in changes)
            desc = f"**Change:** {change_str}\n\n{desc}"

        kev_due = ""
        kev_obj = item.get("kev")
        if isinstance(kev_obj, dict):
            kev_due = str(kev_obj.get("dueDate") or "")

        fields = [
            {"name": "EPSS", "value": self._format_epss(epss), "inline": True},
            {"name": "CVSS", "value": self._format_cvss(cvss), "inline": True},
            {"name": "KEV", "value": "✅ Yes" if kev else "❌ No", "inline": True},
            {"name": "Exploit Intel", "value": "✅ Yes" if patch else "❌ No", "inline": True},
        ]
        if kev_due:
            fields.append({"name": "KEV Due Date", "value": kev_due, "inline": True})

        payload = {
            "embeds": [
                {
                    "title": f"{priority}: {cve_id}",
                    "description": desc or "No description available.",
                    "color": color,
                    "fields": fields,
                    "url": f"https://www.cve.org/CVERecord?id={cve_id}",
                    "footer": {"text": "VulnRadar Alert"},
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
        """Send a summary embed to Discord.

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
            top_list += f"• [{cve}](https://www.cve.org/CVERecord?id={cve}) (EPSS: {self._format_epss(i.get('probability_score'))})\n"
        if not top_list:
            top_list = "No critical findings."

        color = 0xFF0000 if critical_count > 0 else 0x00FF00
        changes_summary = self._build_changes_summary(changes_by_cve)

        fields = [
            {"name": "Total CVEs", "value": str(total), "inline": True},
            {"name": "🚨 Critical", "value": str(critical_count), "inline": True},
            {"name": "⚠️ CISA KEV", "value": str(kev_count), "inline": True},
            {"name": "🔥 Exploit Intel", "value": str(patch_count), "inline": True},
        ]
        if changes_summary:
            fields.append({"name": "📊 Changes Since Last Run", "value": changes_summary, "inline": False})
        fields.append({"name": "Top Critical Findings", "value": top_list, "inline": False})

        payload = {
            "embeds": [
                {
                    "title": "📊 VulnRadar Summary",
                    "color": color,
                    "fields": fields,
                    "footer": {"text": f"Repo: {repo}"},
                }
            ]
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
        """Send a first-run baseline summary to Discord.

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
            top_list += f"{kev_icon} [{cve}](https://www.cve.org/CVERecord?id={cve}) (EPSS: {self._format_epss(item.get('probability_score'))})\n"
        if not top_list:
            top_list = "No critical findings."

        # Build monitoring list
        monitoring_parts = []
        if vendors:
            monitoring_parts.append(f"**Vendors:** {', '.join(vendors)}")
        if products:
            monitoring_parts.append(f"**Products:** {', '.join(products)}")
        monitoring_text = "\n".join(monitoring_parts) if monitoring_parts else "_No watchlist configured_"

        payload = {
            "embeds": [
                {
                    "title": "🚀 VulnRadar Baseline Established",
                    "description": (
                        "**First run complete!** Your vulnerability baseline has been established.\n\n"
                        "Going forward, you'll only receive alerts for:\n"
                        "• 🆕 New CVEs matching your watchlist\n"
                        "• ⚠️ CVEs added to CISA KEV\n"
                        "• 🔥 CVEs added to PatchThis\n"
                        "• 📈 Significant EPSS increases"
                    ),
                    "color": 0x00FF00,
                    "fields": [
                        {"name": "📋 Monitoring", "value": monitoring_text, "inline": False},
                        {"name": "Total CVEs", "value": str(total), "inline": True},
                        {"name": "🚨 Critical", "value": str(critical_count), "inline": True},
                        {"name": "⚠️ CISA KEV", "value": str(kev_count), "inline": True},
                        {"name": "🔥 Exploit Intel", "value": str(patch_count), "inline": True},
                        {"name": "Top 10 Critical (by EPSS)", "value": top_list, "inline": False},
                    ],
                    "footer": {"text": repo},
                }
            ]
        }

        r = requests.post(self.webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
