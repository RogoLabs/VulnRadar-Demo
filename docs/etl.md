# ETL

## Overview

The ETL downloads the CVE List V5 bulk ZIP, parses CVE JSON files, filters against the watchlist, enriches with KEV and EPSS, and writes `data/radar_data.json`.

It also downloads the PatchThis intelligence feed (CSV) and flags CVEs present in that feed.

## Default scan window

- Last 5 years (inclusive of current year)
- Override with `--min-year` / `--max-year`

## KEV scope

By default, the ETL only includes KEVs that fall inside the scanned year window.

If you want to pull **all KEVs**, even if they’re older than the scan window, run:

```bash
python etl.py --include-kev-outside-window
```

## Inclusion rules

- Include if `watchlist_hit == true` OR `active_threat == true` (CISA KEV) OR `in_patchthis == true`

## PatchThis prioritization

- `in_patchthis == true` AND `watchlist_hit == true` => `is_critical = true`
- `in_patchthis == true` AND `watchlist_hit == false` => `is_warning = true`
- `priority_label` is retained for human-readable output (report/issues)

## Verify

- Run `python etl.py`
- Ensure `data/radar_report.md` and `data/radar_data.json` update
