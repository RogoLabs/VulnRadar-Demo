"""Report generation using Jinja2 templates.

Replaces the hand-built ``write_markdown_report()`` in ``etl.py`` with
a template-driven approach.  The default template lives at
``vulnradar/templates/report.md.j2``.
"""

import datetime as dt
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .parsers import risk_bucket, risk_sort_key

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _build_recent_changes(state_file: Path | None) -> list[tuple[str, str, str]]:
    """Extract recent changes from the state file for the report."""
    if state_file is None or not state_file.exists():
        return []

    try:
        with state_file.open("r", encoding="utf-8") as f:
            state_data = json.load(f)
    except (json.JSONDecodeError, KeyError, TypeError):
        return []

    seven_days_ago = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)
    recent: list[tuple[str, str, str]] = []

    for cve_id, entry in state_data.get("seen_cves", {}).items():
        first_seen_str = entry.get("first_seen")
        if not first_seen_str:
            continue
        try:
            first_seen = dt.datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
            if first_seen < seven_days_ago:
                continue
        except (ValueError, TypeError):
            continue

        snapshot = entry.get("snapshot", {})
        if snapshot.get("active_threat"):
            change_type = "🔴 In CISA KEV"
        elif snapshot.get("in_patchthis"):
            change_type = "🟠 In PatchThis"
        elif snapshot.get("is_critical"):
            change_type = "🔥 Critical"
        else:
            change_type = "🆕 New"

        date_str = first_seen.strftime("%b %d")
        recent.append((date_str, cve_id, change_type))

    recent.sort(key=lambda x: x[0], reverse=True)
    return recent


def _now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def write_markdown_report(
    path: Path,
    items: list[dict[str, Any]],
    state_file: Path | None = None,
) -> None:
    """Write a GitHub-renderable Markdown report using Jinja2.

    Args:
        path: Output path for the markdown report.
        items: List of CVE items to report on.
        state_file: Optional path to ``state.json`` for recent changes.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    total = len(items)
    watch_hits = sum(1 for i in items if bool(i.get("watchlist_hit")))
    kev_count = sum(1 for i in items if bool(i.get("active_threat")))
    patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))
    critical_patch_watch = sum(1 for i in items if bool(i.get("in_patchthis")) and bool(i.get("watchlist_hit")))

    top = sorted(items, key=risk_sort_key, reverse=True)[:200]
    # Annotate each item with its risk bucket for the template
    for i in top:
        i["bucket"] = risk_bucket(i)

    critical_items = [i for i in items if bool(i.get("is_critical"))]
    critical_top = sorted(critical_items, key=risk_sort_key, reverse=True)[:25]

    recent_changes = _build_recent_changes(state_file)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(default_for_string=False, default=False),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.md.j2")

    rendered = template.render(
        generated_at=_now_utc_iso(),
        total=total,
        watch_hits=watch_hits,
        kev_count=kev_count,
        patch_count=patch_count,
        critical_patch_watch=critical_patch_watch,
        top=top,
        critical_top=critical_top,
        recent_changes=recent_changes,
    )

    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(rendered)
    tmp.replace(path)
