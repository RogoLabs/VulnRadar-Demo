#!/usr/bin/env python3

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

import requests

DEFAULT_TIMEOUT = (10, 60)


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
    is_warning = bool(item.get("is_warning"))
    priority = "CRITICAL" if is_critical else ("WARNING" if is_warning else "ALERT")
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


def main() -> int:
    p = argparse.ArgumentParser(description="VulnRadar notifications (GitHub Issues)")
    p.add_argument("--in", dest="inp", default="data/radar_data.json", help="Path to radar_data.json")
    p.add_argument("--max", dest="max_items", type=int, default=25, help="Max issues to create per run")
    p.add_argument(
        "--include-warnings",
        action="store_true",
        help="Also notify on PatchThis WARNING (shadow IT) items",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print would-notify CVEs without creating issues",
    )
    args = p.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        raise SystemExit("GITHUB_REPOSITORY is required")
    if not token:
        raise SystemExit("GITHUB_TOKEN (or GH_TOKEN) is required")

    items = _load_items(Path(args.inp))

    # Notify policy:
    # - Always notify on is_critical
    # - Optionally notify on is_warning
    candidates: List[Dict[str, Any]] = []
    for it in items:
        if bool(it.get("is_critical")):
            candidates.append(it)
        elif args.include_warnings and bool(it.get("is_warning")):
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
            1 if bool(it.get("is_warning")) else 0,
            epss,
            cvss,
        )

    candidates = sorted(candidates, key=key, reverse=True)

    session = _session(token)
    existing = _existing_notified_cves(session, repo)
    created = 0
    for it in candidates:
        if created >= args.max_items:
            break
        cve_id = str(it.get("cve_id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue

        if cve_id in existing:
            continue

        priority = "CRITICAL" if bool(it.get("is_critical")) else ("WARNING" if bool(it.get("is_warning")) else "ALERT")
        title = f"[VulnRadar] {priority}: {cve_id}"
        body = _issue_body(it)
        labels = ["vulnradar", "alert"]
        if bool(it.get("is_critical")):
            labels.append("critical")
        if bool(it.get("is_warning")):
            labels.append("warning")
        if bool(it.get("active_threat")):
            labels.append("kev")

        if args.dry_run:
            print(f"DRY RUN: would create issue: {title}")
            created += 1
            continue

        _create_issue(session, repo, title=title, body=body, labels=labels)
        print(f"Created issue for {cve_id}")
        existing.add(cve_id)
        created += 1

    print(f"Done. Created {created} issues.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
