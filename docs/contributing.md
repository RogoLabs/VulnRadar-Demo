# Contributing to VulnRadar

Thanks for your interest in contributing! VulnRadar is designed to be easy to extend.

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/VulnRadar.git
cd VulnRadar

# Install everything (runtime + dev deps + pre-commit hooks) in one command
make dev

# Or manually:
pip install -e ".[dev]"
pre-commit install

# Run the test suite
make test

# Run linting & formatting
make lint
make fmt
```

## Project Structure

```
vulnradar/                 # Core package
├── cli.py                 # argparse entry points (main_etl, main_notify)
├── config.py              # Pydantic models (WatchlistConfig, etc.)
├── downloaders.py         # Sequential HTTP fetchers (requests + tenacity)
├── async_downloaders.py   # Parallel fetchers (aiohttp, used with --parallel)
├── parsers.py             # CVE JSON parsing, CVSS extraction, matching
├── enrichment.py          # KEV/EPSS/PatchThis/NVD merge → radar items
├── report.py              # Jinja2 Markdown report writer
├── state.py               # StateManager for alert deduplication
├── notifications/         # Strategy-pattern notification providers
│   ├── base.py            # Abstract NotificationProvider
│   ├── discord.py         # DiscordProvider
│   ├── slack.py           # SlackProvider
│   ├── teams.py           # TeamsProvider
│   └── github_issues.py   # GitHubIssueProvider (+ Projects v2)
└── templates/
    └── report.md.j2       # Customizable Jinja2 report template
```

## Adding a New Notification Provider

The notification system uses a strategy pattern. Adding a provider (e.g., PagerDuty, email, Matrix) requires just one file.

### 1. Create the provider class

Create `vulnradar/notifications/pagerduty.py`:

```python
"""PagerDuty notification provider."""

import requests
from typing import Any

from .base import NotificationProvider
from ..state import Change


class PagerDutyProvider(NotificationProvider):
    """Send alerts to PagerDuty Events API."""

    name = "pagerduty"

    def __init__(self, routing_key: str, max_alerts: int = 10):
        self.routing_key = routing_key
        self.max_alerts = max_alerts

    def send_alert(self, item: dict[str, Any], changes: list[Change] | None = None) -> None:
        """Send an individual CVE alert."""
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"[VulnRadar] {item['cve_id']} — {item.get('description', '')[:120]}",
                "severity": "critical" if item.get("is_critical") else "warning",
                "source": "vulnradar",
            },
        }
        requests.post("https://events.pagerduty.com/v2/enqueue", json=payload, timeout=30)

    def send_summary(self, items: list[dict[str, Any]], repo: str,
                     changes_by_cve: dict[str, tuple] | None = None) -> None:
        """Send a summary (optional for PagerDuty — could be a no-op)."""
        pass

    def send_baseline(self, items: list[dict[str, Any]],
                      critical_items: list[dict[str, Any]], repo: str) -> None:
        """Send a baseline (optional — could be a no-op)."""
        pass
```

### 2. Register it in the provider loader

Add loading logic to `vulnradar/notifications/__init__.py`:

```python
from .pagerduty import PagerDutyProvider

# In load_providers():
if args.pagerduty_key:
    providers.append(PagerDutyProvider(routing_key=args.pagerduty_key))
```

### 3. Add the CLI flag

In `vulnradar/cli.py`, add the argparse argument for the notify subcommand:

```python
parser.add_argument("--pagerduty-key", help="PagerDuty routing key")
```

### 4. Add tests

Add `tests/test_pagerduty.py` with mocked `requests.post` calls to verify payload format. See `tests/test_notify.py` for examples.

### 5. Document it

Add a `docs/pagerduty.md` setup guide.

## Customizing the Report Template

The Markdown report is rendered from `vulnradar/templates/report.md.j2` using Jinja2.

### Available template variables

| Variable | Type | Description |
|----------|------|-------------|
| `generated_at` | str | ISO 8601 timestamp |
| `total` | int | Total radar items |
| `watch_hits` | int | Items matching watchlist |
| `kev_count` | int | Items in CISA KEV |
| `patch_count` | int | Items with PatchThis exploit intel |
| `critical_patch_watch` | int | Critical items (exploit intel + watchlist) |
| `critical_top` | list[dict] | Top 5 critical items |
| `items` | list[dict] | All radar items, sorted by risk |
| `recent_changes` | list[dict] | CVEs that changed recently |

### Each item dict contains

| Key | Type | Example |
|-----|------|---------|
| `cve_id` | str | `"CVE-2024-12345"` |
| `description` | str | `"Remote code execution in..."` |
| `cvss_score` | float \| None | `9.8` |
| `cvss_severity` | str \| None | `"CRITICAL"` |
| `probability_score` | float \| None | `0.85` |
| `is_critical` | bool | `true` |
| `priority_label` | str | `"CRITICAL (CVSS ≥ 9.0)"` |
| `active_threat` | bool | `true` |
| `watchlist_hit` | bool | `true` |
| `kev` | dict \| None | KEV metadata |
| `affected` | list[dict] | Vendor/product entries |

### Overriding the template

Copy the template and modify it:

```bash
cp vulnradar/templates/report.md.j2 my_report.md.j2
```

Then point to it in your workflow or pass a custom template path.

## Running Tests

```bash
# All tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=vulnradar --cov-report=term-missing

# Single test file
python -m pytest tests/test_features.py -v

# Tests matching a pattern
python -m pytest tests/ -k "test_severity"
```

### Test organisation

| File | Covers |
|------|--------|
| `test_etl.py` | CLI entry points, download orchestration |
| `test_notify.py` | Notification providers, GitHub Issues, Projects |
| `test_parsers.py` | CVE JSON parsing, CVSS extraction, risk scoring |
| `test_config.py` | Pydantic config validation |
| `test_enrichment.py` | KEV/EPSS/NVD enrichment merge |
| `test_downloaders.py` | HTTP fetchers with mocked responses |
| `test_report.py` | Jinja2 report rendering |
| `test_notifications.py` | Provider loading, payload formatting |
| `test_features.py` | Severity thresholds, notification routing |
| `test_async_downloaders.py` | Parallel download orchestrator |

## Code Style

- **Formatter:** ruff (line length 120, Python 3.11+)
- **Docstrings:** Google style with `Args:`, `Returns:`, `Raises:` sections
- **Type hints:** Required on all public function signatures
- **Imports:** stdlib → third-party → local, separated by blank lines

## Pull Request Checklist

- [ ] Tests pass: `python -m pytest tests/ -v`
- [ ] Linting passes: `ruff check vulnradar/ tests/`
- [ ] New public functions have Google-style docstrings
- [ ] New features include tests
- [ ] Documentation updated if user-facing behaviour changes
