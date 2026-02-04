# VulnRadar

VulnRadar is a lightweight “Vulnerability Radar” that:

- Downloads the latest CVE List V5 bulk export from `CVEProject/cvelistV5` (via GitHub Releases)
- Filters CVEs against a local watchlist (`watchlist.json`)
- Enriches matches with CISA KEV, FIRST.org EPSS, and PatchThis intelligence
- Writes a merged dataset to `data/radar_data.json`
- Writes a GitHub-renderable report to `data/radar_report.md` (primary output)

For full documentation and an implementation roadmap, start with: [docs/README.md](docs/README.md)

## Data Sources (No NVD API)

- CVE List V5 bulk ZIP: discovered using `https://api.github.com/repos/CVEProject/cvelistV5/releases/latest`
  and selecting the asset ending in `_all_CVEs_at_midnight.zip`.
- CISA KEV JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- EPSS daily scores (CSV, gz): `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`

## Watchlist

`watchlist.json` format:

```json
{

  "vendors": ["microsoft", "apache"],
  "products": ["log4j", "chrome"]
}
```

A CVE is considered relevant if any entry under `containers.cna.affected` matches any vendor or product.

## ETL (etl.py)

Generate/refresh the dataset:

```bash
python etl.py
```

Defaults:

- Scans the **last 5 years** of CVEs (inclusive of the current year) for performance.
- Includes CVEs if they match your watchlist, are in CISA KEV, or appear in PatchThis.
- Keeps CISA KEV items year-scoped by default; use `--include-kev-outside-window` to widen.

Override the scan window if needed:

```bash
python etl.py --min-year 2020 --max-year 2026
```

Notes:

- The GitHub API is rate-limited. In CI, the workflow uses `GITHUB_TOKEN` automatically.
- Output is written to `data/radar_data.json`.
- A GitHub-viewable summary is written to `data/radar_report.md`.

## Notifications

Workflow: `.github/workflows/notify.yml`

- Creates GitHub Issues for new CRITICAL PatchThis+Watchlist findings.
- Uses the repo `GITHUB_TOKEN` (no external services required).

## Automation

GitHub Actions workflow: `.github/workflows/update.yml`

- Runs the ETL every 6 hours
- Commits updated `data/radar_data.json` and `data/radar_report.md` to the `demo` branch (“git scraping”)

## Branches

- `main`: stable code, intended for people to fork/use without a noisy commit history.
- `demo`: auto-updated snapshot branch for testing; it is force-updated by CI to track `main` + the latest `data/` outputs.
