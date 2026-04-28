# Changelog

All notable changes to VulnRadar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **KEV + watchlist = always critical** — CVEs in CISA KEV that also match
  your watchlist are now automatically flagged `is_critical` with the priority
  label `CRITICAL (CISA KEV + Watchlist)`.  Previously these could slip through
  as non-critical if they didn't meet the CVSS/EPSS/PatchThis thresholds.
- **Individual KEV alerts on first run** — KEV + watchlist items are carved out
  of the first-run baseline summary and sent as individual alerts so you never
  miss an actively-exploited vulnerability in your stack.
- **Vendor-split output** (`--vendor-split`) — the ETL can now write per-vendor
  JSON files under `data/vendors/` alongside the monolithic `radar_data.json`.
  A `data/radar_index.json` manifest tracks all vendor files.  This keeps every
  file well under GitHub's 100 MB limit for large watchlists.
- **`load_vendor_split()`** / **`write_vendor_split()`** public API in
  `vulnradar.enrichment` for programmatic split I/O.
- **`_load_items()` directory support** — `notify.py --in data/` or
  `--in data/radar_index.json` loads from the vendor-split directory.

### Fixed

- **CVE List V5 download resilience** — `get_latest_cvelist_zip_url` now falls
  back to scanning the 5 most recent GitHub releases when the `/releases/latest`
  endpoint returns a release without the midnight bulk ZIP (e.g. the
  `at_end_of_day` release published by CVEProject/cvelistV5). This eliminates
  recurring ETL failures around 00:00–02:00 UTC.

## [0.2.0] - 2025-02-11

### Added

- NVD data feed enrichment (CVSS v2/v3, CWE, CPE counts) via yearly bulk JSON feeds.
- `--skip-nvd` flag to bypass NVD downloads for faster runs.
- NVD data caching with `--nvd-cache` to avoid re-downloading unchanged feeds.
- PatchThis intelligence feed integration for exploit-availability prioritization.
- Async parallel downloaders (`--parallel` flag) using aiohttp.
- Notification providers: Discord, Slack, Microsoft Teams, GitHub Issues (with Projects v2).
- Alert deduplication via `StateManager` — only notify on genuinely new CVEs.
- Jinja2-based Markdown report template (`vulnradar/templates/report.md.j2`).
- `--include-kev-outside-window` to pull KEVs older than the scan window.
- Pre-commit hooks (ruff, mypy, trailing-whitespace, etc.).
- Comprehensive test suite (323 tests).
- Full documentation site under `docs/`.

### Changed

- Refactored downloaders into `vulnradar/downloaders.py` with tenacity retry logic.
- Switched from flat-script ETL to a proper Python package (`vulnradar/`).

## [0.1.0] - 2025-01-15

### Added

- Initial release.
- CVE List V5 bulk export download and parsing.
- CISA KEV enrichment.
- EPSS score enrichment.
- Watchlist-based filtering (vendors and products).
- Markdown report generation.
- GitHub Actions workflow for scheduled hourly updates.
