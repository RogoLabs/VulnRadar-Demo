"""Abstract base class for notification providers."""

from abc import ABC, abstractmethod
from typing import Any

from ..state import Change


class NotificationProvider(ABC):
    """Base class for all VulnRadar notification providers.

    Each provider must implement three methods corresponding to the
    three notification scenarios:

    - ``send_alert``: Individual CVE alert.
    - ``send_summary``: Periodic summary with stats and top findings.
    - ``send_baseline``: First-run baseline establishment message.

    Attributes:
        name: Short identifier for this provider (e.g., ``discord``).
        max_alerts: Maximum individual alerts to send per run.
        rate_limit_delay: Seconds to wait between requests.
    """

    name: str = "base"
    max_alerts: int = 10
    rate_limit_delay: float = 0.5

    @abstractmethod
    def send_alert(self, item: dict[str, Any], changes: list[Change] | None = None) -> None:
        """Send an individual CVE alert.

        Args:
            item: Radar data item dict.
            changes: Optional list of changes that triggered this alert.
        """
        ...

    @abstractmethod
    def send_summary(
        self,
        items: list[dict[str, Any]],
        repo: str,
        changes_by_cve: dict[str, tuple] | None = None,
    ) -> None:
        """Send a summary with stats and top findings.

        Args:
            items: All radar items.
            repo: GitHub repository slug (``owner/repo``).
            changes_by_cve: Optional dict of CVE ID to ``(item, [Change])``
                tuples for change context.
        """
        ...

    @abstractmethod
    def send_baseline(
        self,
        items: list[dict[str, Any]],
        critical_items: list[dict[str, Any]],
        repo: str,
        *,
        vendors: list[str] | None = None,
        products: list[str] | None = None,
    ) -> None:
        """Send a first-run baseline establishment message.

        Args:
            items: All radar items.
            critical_items: Subset of items marked as critical.
            repo: GitHub repository slug.
            vendors: List of monitored vendors from watchlist.
            products: List of monitored products from watchlist.
        """
        ...

    def _build_changes_summary(self, changes_by_cve: dict[str, tuple] | None) -> str:
        """Build a human-readable summary of changes since the last run.

        Args:
            changes_by_cve: Dict of CVE ID to ``(item, [Change])`` tuples.

        Returns:
            Summary string like ``🆕 3 new | ⚠️ 1 added to KEV``.
        """
        if not changes_by_cve:
            return ""

        new_count = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_CVE" for c in chs))
        kev_added = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_KEV" for c in chs))
        patch_added = sum(
            1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "NEW_PATCHTHIS" for c in chs)
        )
        epss_spike = sum(1 for _, (_, chs) in changes_by_cve.items() if any(c.change_type == "EPSS_SPIKE" for c in chs))

        parts = []
        if new_count > 0:
            parts.append(f"🆕 {new_count} new")
        if kev_added > 0:
            parts.append(f"⚠️ {kev_added} added to KEV")
        if patch_added > 0:
            parts.append(f"🔥 {patch_added} new exploit intel")
        if epss_spike > 0:
            parts.append(f"📈 {epss_spike} EPSS spike")
        return " | ".join(parts) if parts else "No significant changes"

    def _top_critical(self, items: list[dict[str, Any]], n: int = 5) -> list[dict[str, Any]]:
        """Get the top N critical items sorted by EPSS.

        Args:
            items: All radar items.
            n: Number of items to return.

        Returns:
            Sorted list of critical items.
        """
        critical = [i for i in items if bool(i.get("is_critical"))]
        critical.sort(key=lambda x: float(x.get("probability_score") or 0), reverse=True)
        return critical[:n]

    @staticmethod
    def _format_epss(epss: Any) -> str:
        """Format an EPSS score as a percentage string."""
        try:
            return f"{float(epss):.1%}" if epss is not None else "N/A"
        except Exception:
            return "N/A"

    @staticmethod
    def _format_cvss(cvss: Any) -> str:
        """Format a CVSS score to 1 decimal place."""
        try:
            return f"{float(cvss):.1f}" if cvss is not None else "N/A"
        except Exception:
            return "N/A"
