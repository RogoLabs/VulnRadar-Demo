"""GitHub Issues notification provider.

Handles issue creation, escalation comments, baseline summaries,
weekly digests, and GitHub Projects v2 integration.
"""

import datetime as dt
import re
from typing import Any

import requests

from ..state import Change
from .base import NotificationProvider

DEFAULT_TIMEOUT = (10, 60)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


class GitHubIssueProvider(NotificationProvider):
    """Create GitHub Issues for VulnRadar findings.

    This provider is special — it's not a webhook but uses the GitHub
    API to create issues, add escalation comments, and integrate with
    GitHub Projects v2.

    Args:
        token: GitHub personal access token.
        repo: Repository slug (``owner/repo``).
        max_alerts: Maximum issues to create per run.
        project_url: Optional GitHub Projects v2 URL.
    """

    name = "github_issues"

    def __init__(
        self,
        token: str,
        repo: str,
        max_alerts: int = 25,
        project_url: str | None = None,
    ):
        self.repo = repo
        self.max_alerts = max_alerts
        self.project_url = project_url
        self.session = self._make_session(token)
        self._existing_cves: set[str] | None = None
        self._issue_map: dict[str, int] | None = None
        self._project_id: str | None = None

    @staticmethod
    def _make_session(token: str) -> requests.Session:
        s = requests.Session()
        s.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "User-Agent": "VulnRadar-Notify/0.2",
                "Authorization": f"Bearer {token}",
            }
        )
        return s

    # ─── GitHub API helpers ───────────────────────────────────────────

    def _iter_recent_issues(self, *, max_pages: int = 3):
        """Yield recent issues (not PRs) from the repo."""
        base = f"https://api.github.com/repos/{self.repo}/issues"
        for page in range(1, max_pages + 1):
            params = {"state": "all", "per_page": 100, "page": page}
            r = self.session.get(base, params=params, timeout=DEFAULT_TIMEOUT)
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

    def _load_existing_cves(self) -> set[str]:
        """Load CVE IDs from existing VulnRadar issues."""
        if self._existing_cves is not None:
            return self._existing_cves
        out: set[str] = set()
        for issue in self._iter_recent_issues(max_pages=4):
            title = str(issue.get("title") or "")
            if "[VulnRadar]" not in title:
                continue
            m = _CVE_RE.search(title)
            if m:
                out.add(m.group(0).upper())
        self._existing_cves = out
        return out

    def _load_issue_map(self) -> dict[str, int]:
        """Load mapping of CVE ID → issue number for open VulnRadar issues."""
        if self._issue_map is not None:
            return self._issue_map
        out: dict[str, int] = {}
        for issue in self._iter_recent_issues(max_pages=4):
            title = str(issue.get("title") or "")
            if "[VulnRadar]" not in title:
                continue
            if issue.get("state") != "open":
                continue
            m = _CVE_RE.search(title)
            if m:
                cve_id = m.group(0).upper()
                issue_num = issue.get("number")
                if issue_num and cve_id not in out:
                    out[cve_id] = int(issue_num)
        self._issue_map = out
        return out

    def _create_issue(self, title: str, body: str, labels: list[str] | None = None) -> dict[str, Any] | None:
        """Create a GitHub issue."""
        url = f"https://api.github.com/repos/{self.repo}/issues"
        payload: dict[str, Any] = {"title": title, "body": body}
        if labels:
            payload["labels"] = labels
        r = self.session.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def _add_comment(self, issue_number: int, body: str) -> None:
        """Add a comment to an existing issue."""
        url = f"https://api.github.com/repos/{self.repo}/issues/{issue_number}/comments"
        r = self.session.post(url, json={"body": body}, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()

    def _issues_enabled(self) -> bool:
        """Check if issues are enabled on the repo."""
        try:
            r = self.session.get(f"https://api.github.com/repos/{self.repo}", timeout=DEFAULT_TIMEOUT)
            if r.ok:
                return r.json().get("has_issues", True)
        except Exception:
            pass
        return True

    # ─── GitHub Projects v2 ───────────────────────────────────────────

    def _resolve_project_id(self) -> str | None:
        """Resolve the GitHub Projects v2 node ID from the project URL."""
        if not self.project_url:
            return None
        if self._project_id is not None:
            return self._project_id

        parsed = self._parse_project_url(self.project_url)
        if not parsed:
            print(f"⚠️ Invalid project URL format: {self.project_url}")
            return None

        owner, owner_type, number = parsed["owner"], parsed["type"], parsed["number"]

        if owner_type == "user":
            query = """
            query($owner: String!, $number: Int!) {
                user(login: $owner) { projectV2(number: $number) { id title } }
            }
            """
        else:
            query = """
            query($owner: String!, $number: Int!) {
                organization(login: $owner) { projectV2(number: $number) { id title } }
            }
            """

        url = "https://api.github.com/graphql"
        r = self.session.post(
            url, json={"query": query, "variables": {"owner": owner, "number": number}}, timeout=DEFAULT_TIMEOUT
        )
        r.raise_for_status()
        data = r.json()

        if "errors" in data:
            print(f"GraphQL error getting project: {data['errors']}")
            return None

        key = "user" if owner_type == "user" else "organization"
        project = data.get("data", {}).get(key, {}).get("projectV2")
        if project:
            self._project_id = project.get("id")
            return self._project_id
        return None

    def _add_to_project(self, content_node_id: str) -> bool:
        """Add an issue to the GitHub Project board."""
        project_id = self._resolve_project_id()
        if not project_id:
            return False

        mutation = """
        mutation($projectId: ID!, $contentId: ID!) {
            addProjectV2ItemByContentId(input: {projectId: $projectId, contentId: $contentId}) {
                item { id }
            }
        }
        """
        url = "https://api.github.com/graphql"
        r = self.session.post(
            url,
            json={
                "query": mutation,
                "variables": {"projectId": project_id, "contentId": content_node_id},
            },
            timeout=DEFAULT_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if "errors" in data:
            print(f"GraphQL error adding to project: {data['errors']}")
            return False
        return data.get("data", {}).get("addProjectV2ItemByContentId", {}).get("item") is not None

    @staticmethod
    def _parse_project_url(project_url: str) -> dict[str, Any] | None:
        """Parse a GitHub Projects URL."""
        user_match = re.match(r"https?://github\.com/users/([^/]+)/projects/(\d+)", project_url)
        if user_match:
            return {"owner": user_match.group(1), "type": "user", "number": int(user_match.group(2))}
        org_match = re.match(r"https?://github\.com/orgs/([^/]+)/projects/(\d+)", project_url)
        if org_match:
            return {"owner": org_match.group(1), "type": "organization", "number": int(org_match.group(2))}
        return None

    # ─── Issue body formatting ────────────────────────────────────────

    @staticmethod
    def format_issue_body(item: dict[str, Any], changes: list[Change] | None = None) -> str:
        """Generate a rich GitHub issue body for a CVE.

        Args:
            item: Radar item dict.
            changes: Optional list of triggering changes.

        Returns:
            Markdown-formatted issue body.
        """
        cve_id = str(item.get("cve_id") or "")
        desc = str(item.get("description") or "").strip()
        epss = item.get("probability_score")
        cvss = item.get("cvss_score")
        kev = bool(item.get("active_threat"))
        patch = bool(item.get("in_patchthis"))
        watch = bool(item.get("watchlist_hit"))

        kev_obj = item.get("kev") or {}
        kev_due = str(kev_obj.get("dueDate") or "").strip() if isinstance(kev_obj, dict) else ""
        kev_vendor = str(kev_obj.get("vendorProject") or "").strip() if isinstance(kev_obj, dict) else ""
        kev_product = str(kev_obj.get("product") or "").strip() if isinstance(kev_obj, dict) else ""
        kev_name = str(kev_obj.get("vulnerabilityName") or "").strip() if isinstance(kev_obj, dict) else ""

        vendor = str(item.get("vendor") or "Unknown").strip()
        product = str(item.get("product") or "Unknown").strip()
        affected = item.get("affected_versions") or item.get("affected") or []
        references = item.get("references") or []

        def fmt(x, ndigits):
            try:
                return f"{float(x):.{ndigits}f}"
            except Exception:
                return "N/A"

        def fmt_pct(x):
            try:
                return f"{float(x):.1%}"
            except Exception:
                return "N/A"

        lines: list[str] = []

        if changes:
            lines.append("## 🔔 Alert Reason")
            lines.append("")
            for c in changes:
                lines.append(f"> {c}")
            lines.append("")

        lines.append("## Overview")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **CVE ID** | [{cve_id}](https://www.cve.org/CVERecord?id={cve_id}) |")
        lines.append(f"| **Vendor** | {vendor if vendor != 'Unknown' else kev_vendor or 'Unknown'} |")
        lines.append(f"| **Product** | {product if product != 'Unknown' else kev_product or 'Unknown'} |")
        lines.append(f"| **CVSS Score** | {fmt(cvss, 1)} |")
        lines.append(f"| **EPSS Score** | {fmt_pct(epss)} |")
        lines.append("")

        lines.append("## ⚠️ Threat Signals")
        lines.append("")
        lines.append("| Signal | Status |")
        lines.append("|--------|--------|")
        lines.append(f"| CISA KEV | {'🔴 **YES** - Known Exploited' if kev else '⚪ No'} |")
        lines.append(f"| Exploit Intel | {'🟠 **YES** - PoC Available' if patch else '⚪ No'} |")
        lines.append(f"| Watchlist Match | {'🟡 **YES**' if watch else '⚪ No'} |")
        if kev_due:
            lines.append(f"| KEV Remediation Due | **{kev_due}** |")
        lines.append("")

        lines.append("## 📝 Description")
        lines.append("")
        if kev_name:
            lines.append(f"**{kev_name}**")
            lines.append("")
        lines.append(desc if desc else "_No description available._")
        lines.append("")

        if affected:
            lines.append("## 📦 Affected Versions")
            lines.append("")
            if isinstance(affected, list):
                for aff in affected[:10]:
                    if isinstance(aff, dict):
                        v = aff.get("version") or aff.get("versionValue") or str(aff)
                        lines.append(f"- {v}")
                    else:
                        lines.append(f"- {aff}")
                if len(affected) > 10:
                    lines.append(f"- _...and {len(affected) - 10} more_")
            lines.append("")

        lines.append("## 🔗 References")
        lines.append("")
        lines.append(f"- [CVE.org Record](https://www.cve.org/CVERecord?id={cve_id})")
        lines.append(f"- [NVD Entry](https://nvd.nist.gov/vuln/detail/{cve_id})")
        if kev:
            lines.append("- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)")

        if references:
            ref_list = references if isinstance(references, list) else []
            for ref in ref_list[:5]:
                if isinstance(ref, dict):
                    url = ref.get("url") or ref.get("href") or ""
                    if url:
                        display = f"{url[:50]}..." if len(url) > 50 else url
                        lines.append(f"- [{display}]({url})")
                elif isinstance(ref, str) and ref.startswith("http"):
                    display = f"{ref[:50]}..." if len(ref) > 50 else ref
                    lines.append(f"- [{display}]({ref})")

        lines.append("")
        lines.append("---")
        lines.append("_Generated by [VulnRadar](https://github.com/RogoLabs/VulnRadar)_")
        return "\n".join(lines)

    @staticmethod
    def format_escalation_comment(change: Change, item: dict[str, Any]) -> str:
        """Generate a comment body for escalation events.

        Args:
            change: The change that triggered the escalation.
            item: Current radar data item dict.

        Returns:
            Markdown-formatted comment body.
        """
        cve_id = change.cve_id
        lines = ["## ⚠️ Status Update", ""]

        if change.change_type == "NEW_KEV":
            lines.extend(
                [
                    f"🚨 **{cve_id} has been added to CISA KEV!**",
                    "",
                    "This vulnerability is now confirmed to be actively exploited in the wild.",
                    "",
                ]
            )
            kev = item.get("kev") if isinstance(item.get("kev"), dict) else {}
            if kev:
                due = kev.get("dueDate")
                if due:
                    lines.append(f"**Remediation Due Date:** {due}")
                lines.append("")
            lines.extend(
                [
                    "**Action Required:** Prioritize patching immediately.",
                    "",
                    "[View CISA KEV Entry](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
                ]
            )
        elif change.change_type == "NEW_PATCHTHIS":
            lines.extend(
                [
                    f"🔥 **{cve_id} now has Exploit Intel (PoC Available)!**",
                    "",
                    "A proof-of-concept or exploit code has been identified for this vulnerability.",
                    "",
                    "**Action Required:** Increase priority - exploitation is now easier.",
                ]
            )
        else:
            lines.extend(
                [
                    f"📢 **{cve_id} status has changed**",
                    "",
                    f"Change type: {change.change_type}",
                ]
            )

        lines.extend(["", "---", "_Escalation comment by [VulnRadar](https://github.com/RogoLabs/VulnRadar)_"])
        return "\n".join(lines)

    @staticmethod
    def extract_dynamic_labels(item: dict[str, Any], max_labels: int = 3) -> list[str]:
        """Extract vendor/product labels from matched_terms.

        Args:
            item: Radar data item dict.
            max_labels: Maximum number of labels to return.

        Returns:
            List of cleaned label strings (e.g. ``["apache", "log4j"]``).
        """
        matched = item.get("matched_terms") or []
        if not isinstance(matched, list):
            return []
        labels: list[str] = []
        for term in matched:
            if not isinstance(term, str):
                continue
            clean = term.lower().strip().replace(" ", "-")
            if len(clean) <= 50 and clean not in labels:
                labels.append(clean)
            if len(labels) >= max_labels:
                break
        return labels

    @staticmethod
    def extract_severity_label(item: dict[str, Any]) -> str | None:
        """Extract severity label based on CVSS score.

        Args:
            item: Radar data item dict.

        Returns:
            Label string like ``severity:critical`` or ``None``
            if CVSS is unavailable.
        """
        cvss = item.get("cvss_score")
        if cvss is None:
            return None
        try:
            score = float(cvss)
        except (ValueError, TypeError):
            return None
        if score >= 9.0:
            return "severity:critical"
        elif score >= 7.0:
            return "severity:high"
        elif score >= 4.0:
            return "severity:medium"
        else:
            return "severity:low"

    # ─── NotificationProvider interface ───────────────────────────────

    def send_alert(self, item: dict[str, Any], changes: list[Change] | None = None) -> None:
        """Create a GitHub issue for a CVE (not used in provider loop — see send_all)."""
        pass  # GitHub issues are handled specially in send_all

    def send_summary(
        self,
        items: list[dict[str, Any]],
        repo: str,
        changes_by_cve: dict[str, tuple] | None = None,
    ) -> None:
        """Not applicable for GitHub issues."""
        pass

    def send_baseline(
        self,
        items: list[dict[str, Any]],
        critical_items: list[dict[str, Any]],
        repo: str,
        *,
        vendors: list[str] | None = None,
        products: list[str] | None = None,
    ) -> None:
        """Create a single baseline summary issue on first run.

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

        sorted_critical = sorted(critical_items, key=lambda x: float(x.get("probability_score") or 0), reverse=True)

        # Build monitoring list
        monitoring_lines = []
        if vendors:
            monitoring_lines.append(f"- **Vendors:** {', '.join(vendors)}")
        if products:
            monitoring_lines.append(f"- **Products:** {', '.join(products)}")
        monitoring_text = "\n".join(monitoring_lines) if monitoring_lines else "_No watchlist configured_"

        lines = [
            "# 🚀 VulnRadar Baseline Established",
            "",
            "This is the **first run** of VulnRadar on this repository. Instead of creating individual issues for all existing findings, this summary establishes your baseline.",
            "",
            "## 📋 Monitoring",
            "",
            monitoring_text,
            "",
            "**Going forward, VulnRadar will only create issues for:**",
            "- 🆕 New CVEs that match your watchlist",
            "- ⚠️ Existing CVEs newly added to CISA KEV",
            "- 🔥 Existing CVEs with new exploit intel (PoC available)",
            "- 📈 CVEs with significant EPSS increases (≥30%)",
            "",
            "---",
            "",
            "## 📊 Current State Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Total CVEs Tracked | {total} |",
            f"| 🚨 Critical (require action) | {critical_count} |",
            f"| ⚠️ In CISA KEV | {kev_count} |",
            f"| 🔥 Exploit Intel (PoC) | {patch_count} |",
            "",
            "---",
            "",
            "## 🔴 Top 20 Critical Findings",
            "",
            "These are your highest-priority items based on EPSS score:",
            "",
            "| CVE ID | EPSS | CVSS | KEV | Exploit | Description |",
            "|--------|------|------|-----|-----------|-------------|",
        ]

        for item in sorted_critical[:20]:
            cve_id = item.get("cve_id", "")
            desc = str(item.get("description") or "")[:60].replace("|", "\\|").replace("\n", " ")
            kev = bool(item.get("active_threat"))
            patch = bool(item.get("in_patchthis"))
            lines.append(
                f"| [{cve_id}](https://www.cve.org/CVERecord?id={cve_id}) | "
                f"{self._format_epss(item.get('probability_score'))} | "
                f"{self._format_cvss(item.get('cvss_score'))} | "
                f"{'🔴' if kev else '⚪'} | {'🟠' if patch else '⚪'} | {desc}... |"
            )

        if len(sorted_critical) > 20:
            lines.append(f"| ... | | | | | _and {len(sorted_critical) - 20} more critical findings_ |")

        lines.extend(
            [
                "",
                "---",
                "",
                "## 📋 Next Steps",
                "",
                "1. **Review the critical findings above** - these need attention",
                "2. **Check your watchlist** (`watchlist.yaml`) to ensure it covers your vendors/products",
                "3. **Close this issue** once you've reviewed the baseline",
                "",
                "Future VulnRadar runs will only alert on **new or changed** CVEs.",
                "",
                "---",
                "_Generated by [VulnRadar](https://github.com/RogoLabs/VulnRadar) - First Run Baseline_",
            ]
        )

        body = "\n".join(lines)
        title = f"[VulnRadar] 🚀 Baseline Established - {critical_count} Critical Findings"
        self._create_issue(title=title, body=body, labels=["vulnradar", "baseline"])
        print(f"Created baseline summary issue with {critical_count} critical findings")

    def create_weekly_summary(
        self,
        items: list[dict[str, Any]],
        state=None,
    ) -> None:
        """Create a weekly summary issue.

        Args:
            items: All radar items.
            state: Optional ``StateManager`` for change statistics.
        """
        now = dt.datetime.now(dt.timezone.utc)
        week_ago = now - dt.timedelta(days=7)
        week_start = week_ago.strftime("%b %d")
        week_end = now.strftime("%b %d, %Y")

        total = len(items)
        critical_count = sum(1 for i in items if bool(i.get("is_critical")))
        kev_count = sum(1 for i in items if bool(i.get("active_threat")))
        patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))

        new_cves_this_week = 0
        if state:
            for _, entry in state.data.get("seen_cves", {}).items():
                first_seen = entry.get("first_seen")
                if first_seen:
                    try:
                        first_seen_dt = dt.datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                        if first_seen_dt >= week_ago:
                            new_cves_this_week += 1
                    except (ValueError, TypeError):
                        pass

        critical_items = [i for i in items if bool(i.get("is_critical"))]
        critical_items.sort(key=lambda x: float(x.get("probability_score") or 0), reverse=True)
        top_10 = critical_items[:10]

        lines = [
            "# 📊 VulnRadar Weekly Summary",
            "",
            f"**Week of {week_start} - {week_end}**",
            "",
            "---",
            "",
            "## 📈 This Week's Activity",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| 🆕 New CVEs This Week | {new_cves_this_week} |",
            f"| 📊 Total CVEs Tracked | {total} |",
            f"| 🚨 Critical (Exploit + Watchlist) | {critical_count} |",
            f"| ⚠️ In CISA KEV | {kev_count} |",
            f"| 🔥 Exploit Intel Available | {patch_count} |",
            "",
            "---",
            "",
            "## 🔴 Top 10 Critical Findings",
            "",
            "| CVE ID | EPSS | CVSS | KEV | Exploit | Description |",
            "|--------|------|------|-----|---------|-------------|",
        ]

        for item in top_10:
            cve_id = item.get("cve_id", "")
            desc = str(item.get("description") or "")[:50].replace("|", "\\|").replace("\n", " ")
            kev = bool(item.get("active_threat"))
            patch = bool(item.get("in_patchthis"))
            lines.append(
                f"| [{cve_id}](https://www.cve.org/CVERecord?id={cve_id}) | "
                f"{self._format_epss(item.get('probability_score'))} | "
                f"{self._format_cvss(item.get('cvss_score'))} | "
                f"{'🔴' if kev else '⚪'} | {'🟠' if patch else '⚪'} | {desc}... |"
            )

        lines.extend(
            [
                "",
                "---",
                "",
                "## 📋 Quick Actions",
                "",
                "1. **Review open critical issues** - prioritize by EPSS score",
                "2. **Check for stale issues** - close resolved CVEs",
                "3. **Update watchlist** if you've added new tech to your stack",
                "",
                "---",
                f"_Generated by [VulnRadar](https://github.com/RogoLabs/VulnRadar) | {now.strftime('%Y-%m-%d %H:%M UTC')}_",
            ]
        )

        body = "\n".join(lines)
        title = f"[VulnRadar] 📊 Weekly Summary - {week_start} to {week_end}"
        self._create_issue(title=title, body=body, labels=["vulnradar", "weekly-summary"])
        print(f"Created weekly summary issue: {title}")

    def send_all(
        self,
        candidates: list[dict[str, Any]],
        changes_by_cve: dict[str, tuple],
        *,
        dry_run: bool = False,
    ) -> tuple[int, int]:
        """Create issues and escalation comments for all candidates.

        Args:
            candidates: Critical items that need new issues.
            changes_by_cve: All detected changes for escalation.
            dry_run: If True, print actions without executing.

        Returns:
            Tuple of (issues_created, escalations_added).
        """
        existing = self._load_existing_cves()
        issue_map = self._load_issue_map()
        created = 0
        escalated = 0

        # Process escalation comments on existing issues
        escalation_types = {"NEW_KEV", "NEW_PATCHTHIS"}
        for cve_id, (it, item_changes) in changes_by_cve.items():
            escalation_changes = [c for c in item_changes if c.change_type in escalation_types]
            if escalation_changes and cve_id in issue_map:
                issue_num = issue_map[cve_id]
                for change in escalation_changes:
                    comment_body = self.format_escalation_comment(change, it)
                    if dry_run:
                        print(
                            f"DRY RUN: would add escalation comment to #{issue_num} for {cve_id}: {change.change_type}"
                        )
                        escalated += 1
                        continue
                    try:
                        self._add_comment(issue_num, comment_body)
                        print(f"Added escalation comment to #{issue_num} for {cve_id}: {change.change_type}")
                        escalated += 1
                    except Exception as e:
                        print(f"Failed to add comment to #{issue_num}: {e}")

        # Create new issues
        for it in candidates:
            if created >= self.max_alerts:
                break
            cve_id = str(it.get("cve_id") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue

            item_changes = changes_by_cve.get(cve_id, (None, []))[1]

            if cve_id in existing:
                continue

            priority = "CRITICAL" if bool(it.get("is_critical")) else "ALERT"
            title = f"[VulnRadar] {priority}: {cve_id}"
            body = self.format_issue_body(it, item_changes)
            labels = ["vulnradar", "alert"]
            if bool(it.get("is_critical")):
                labels.append("critical")
            if bool(it.get("active_threat")):
                labels.append("kev")
            labels.extend(self.extract_dynamic_labels(it))
            severity_label = self.extract_severity_label(it)
            if severity_label:
                labels.append(severity_label)

            if dry_run:
                print(f"DRY RUN: would create issue: {title} (labels: {labels})")
                created += 1
                continue

            try:
                issue_data = self._create_issue(title=title, body=body, labels=labels)
                print(f"Created issue for {cve_id}")
                existing.add(cve_id)
                created += 1

                if self.project_url and issue_data and issue_data.get("node_id"):
                    if self._add_to_project(issue_data["node_id"]):
                        print("  → Added to project board")
            except Exception as e:
                print(f"Failed to create issue for {cve_id}: {e}")
                break

        print(f"Done. Created {created} GitHub issues, added {escalated} escalation comments.")
        return created, escalated
