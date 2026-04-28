# Configuration

VulnRadar is configured through `watchlist.yaml` (or `watchlist.d/*.yaml` for multi-team setups). All settings have sensible defaults — a minimal file with just `vendors:` is enough to get started.

## watchlist.yaml

### Vendors & Products

```yaml
vendors:
  - microsoft
  - apache
  - linux

products:
  - log4j
  - chrome
  - kubernetes
```

- **Case-insensitive** — `Microsoft` and `microsoft` are equivalent.
- **Substring matching** (default) — `apache` matches "Apache Software Foundation".
- Change to exact or regex matching with `options.match_mode`.

### Exclusions

```yaml
exclude_vendors:
  - n/a
  - unknown

exclude_products:
  - n/a
```

Excluded terms are removed *after* matching, so they act as a blocklist.

### Thresholds

```yaml
thresholds:
  min_cvss: 0.0            # Floor for inclusion (0.0 = include all)
  min_epss: 0.0            # Floor for inclusion (0.0 = include all)
  severity_threshold: 9.0  # Flag CVEs with CVSS >= 9.0 as CRITICAL
  epss_threshold: 0.5      # Flag CVEs with EPSS >= 50% as CRITICAL
```

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `min_cvss` | float | `0.0` | 0.0–10.0 | Minimum CVSS score to include in results |
| `min_epss` | float | `0.0` | 0.0–1.0 | Minimum EPSS probability to include |
| `severity_threshold` | float or null | `null` | 0.0–10.0 | CVSS score at or above which a watchlist-matching CVE is flagged **CRITICAL** |
| `epss_threshold` | float or null | `null` | 0.0–1.0 | EPSS probability at or above which a watchlist-matching CVE is flagged **CRITICAL** |

> **Note:** `severity_threshold` and `epss_threshold` expand the definition of "critical" beyond the default (exploit intel + watchlist hit). They only apply to CVEs that match your watchlist.

### Options

```yaml
options:
  always_include_kev: true        # Include KEV entries even if not on watchlist
  always_include_patchthis: true  # Include PatchThis entries even if not on watchlist
  match_mode: substring           # 'substring' | 'exact' | 'regex'
```

### Notification Routing

Route different alert severities to different webhook endpoints. Each provider (Discord, Slack, Teams) supports multiple routes.

```yaml
notifications:
  discord:
    - url: $DISCORD_CRITICAL_WEBHOOK   # Resolved from env var
      filter: critical                  # Only critical findings
      max_alerts: 25
    - url: $DISCORD_ALL_WEBHOOK
      filter: all                       # All findings
      max_alerts: 10
  slack:
    - url: $SLACK_WEBHOOK_URL
      filter: kev                       # Only KEV entries
  teams:
    - url: https://example.webhook.office.com/...
      filter: watchlist                 # All watchlist matches
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | *(required)* | Webhook URL. Prefix with `$` to read from an environment variable. |
| `filter` | string | `all` | One of `all`, `critical`, `kev`, `watchlist` |
| `max_alerts` | int | `10` | Maximum individual alert messages per run |

**Filter descriptions:**

| Filter | Includes |
|--------|----------|
| `all` | Every finding |
| `critical` | Only `is_critical == true` items (exploit intel, severity/EPSS thresholds) |
| `kev` | Only CVEs in the CISA KEV catalog |
| `watchlist` | Only CVEs matching your watchlist (excludes KEV-only / PatchThis-only) |

## Multi-Watchlist Support

For team collaboration, split configuration across `watchlist.d/*.yaml`:

```
watchlist.d/
├── infra-team.yaml
├── appsec-team.yaml
└── soc-team.yaml
```

Files are merged at runtime — vendors and products are unioned, thresholds use the most permissive value.

## Validation

```bash
python etl.py --validate-watchlist
```

Checks for unknown vendor/product names and common typos by fuzzy-matching against real CVE data.

## Config Model Reference

Configuration is validated by Pydantic models in `vulnradar/config.py`:

- **`WatchlistConfig`** — top-level model with `vendors`, `products`, `exclude_vendors`, `exclude_products`, `thresholds`, `options`, `notifications`
- **`ThresholdsConfig`** — `min_cvss`, `min_epss`, `severity_threshold`, `epss_threshold`
- **`OptionsConfig`** — `always_include_kev`, `always_include_patchthis`, `match_mode`
- **`NotificationsConfig`** — `discord`, `slack`, `teams` (each a list of `NotificationRoute`)
- **`NotificationRoute`** — `url`, `filter`, `max_alerts`

Invalid values produce clear Pydantic validation errors at startup.
