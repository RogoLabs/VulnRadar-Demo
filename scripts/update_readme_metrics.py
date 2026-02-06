#!/usr/bin/env python3
"""Update README.md with current VulnRadar metrics.

This script reads radar_data.json and updates dynamic badge/stats
sections in README.md. It's designed to run after the ETL workflow.

Usage:
    python scripts/update_readme_metrics.py

The script looks for markdown comments like:
    <!-- METRICS START -->
    ... dynamic content ...
    <!-- METRICS END -->

And replaces the content between them with current stats.
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def load_radar_data(path: Path) -> List[Dict[str, Any]]:
    """Load radar data from JSON file."""
    if not path.exists():
        return []
    
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    if isinstance(data, dict) and "items" in data:
        return data["items"]
    elif isinstance(data, list):
        return data
    return []


def calculate_metrics(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate metrics from radar data."""
    if not items:
        return {
            "total": 0,
            "critical": 0,
            "kev": 0,
            "exploit_intel": 0,
            "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        }
    
    total = len(items)
    critical = sum(1 for i in items if bool(i.get("is_critical")))
    kev = sum(1 for i in items if bool(i.get("active_threat")))
    exploit_intel = sum(1 for i in items if bool(i.get("in_patchthis")))
    
    # Get last modified time from meta if available
    last_updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    
    return {
        "total": total,
        "critical": critical,
        "kev": kev,
        "exploit_intel": exploit_intel,
        "last_updated": last_updated,
    }


def generate_metrics_section(metrics: Dict[str, Any]) -> str:
    """Generate the metrics markdown section."""
    lines = [
        "| 📊 **CVEs Tracked** | 🚨 **Critical** | ⚠️ **In KEV** | 🔥 **Exploit Intel** |",
        "|:---:|:---:|:---:|:---:|",
        f"| {metrics['total']} | {metrics['critical']} | {metrics['kev']} | {metrics['exploit_intel']} |",
        "",
        f"_Last scanned: {metrics['last_updated']}_",
    ]
    return "\n".join(lines)


def update_readme(readme_path: Path, metrics: Dict[str, Any]) -> bool:
    """Update README.md with new metrics.
    
    Returns True if changes were made, False otherwise.
    """
    if not readme_path.exists():
        print(f"README not found: {readme_path}")
        return False
    
    content = readme_path.read_text(encoding="utf-8")
    
    # Look for metrics section markers
    pattern = r"(<!-- METRICS START -->).*(<!-- METRICS END -->)"
    
    if not re.search(pattern, content, re.DOTALL):
        print("No metrics section found in README. Add these markers:")
        print("  <!-- METRICS START -->")
        print("  <!-- METRICS END -->")
        return False
    
    new_metrics = generate_metrics_section(metrics)
    replacement = f"<!-- METRICS START -->\n{new_metrics}\n<!-- METRICS END -->"
    
    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    
    if new_content == content:
        print("No changes needed.")
        return False
    
    readme_path.write_text(new_content, encoding="utf-8")
    print("Updated README metrics:")
    print(f"  - Total CVEs: {metrics['total']}")
    print(f"  - Critical: {metrics['critical']}")
    print(f"  - KEV: {metrics['kev']}")
    print(f"  - Exploit Intel: {metrics['exploit_intel']}")
    return True


def main() -> int:
    """Main entry point."""
    # Find paths relative to script location or cwd
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    
    radar_path = repo_root / "data" / "radar_data.json"
    readme_path = repo_root / "README.md"
    
    # Also check cwd
    if not radar_path.exists():
        radar_path = Path("data/radar_data.json")
    if not readme_path.exists():
        readme_path = Path("README.md")
    
    items = load_radar_data(radar_path)
    metrics = calculate_metrics(items)
    
    if update_readme(readme_path, metrics):
        return 0
    return 0  # Not an error if no changes needed


if __name__ == "__main__":
    sys.exit(main())
