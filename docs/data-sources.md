# Data Sources

VulnRadar aggregates vulnerability intelligence from five authoritative sources, all accessible via public feeds (no API keys required except `GITHUB_TOKEN` for the CVE List).

## CVE List V5 (CVEProject/cvelistV5)

- **Primary CVE data source** - descriptions, affected products, basic CVSS
- Uses the GitHub Releases API to locate the latest asset ending in `_all_CVEs_at_midnight.zip`
- URL: `https://api.github.com/repos/CVEProject/cvelistV5/releases/latest`
- No NVD API is used

## CISA KEV (Known Exploited Vulnerabilities)

- **Active exploitation intelligence** - flags CVEs with confirmed wild exploitation
- JSON feed: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
- Sets `active_threat: true` and adds `kev` object with remediation details

## EPSS (Exploit Prediction Scoring System)

- **Exploitation probability scores** (0.0 - 1.0)
- Daily CSV (gzipped): <https://epss.empiricalsecurity.com/epss_scores-current.csv.gz>
- Maintained by FIRST.org
- Adds `probability_score` to each CVE

## PatchThis Intelligence Feed

- **Priority labeling** based on active exploitation in the wild
- CSV: <https://raw.githubusercontent.com/RogoLabs/patchthisapp/main/web/data.csv>
- Sets `in_patchthis: true` and `priority_label` for prioritization

## NVD Data Feeds

- **CVSS, CWE, and CPE enrichment** - fills gaps in CVE List V5 data
- Yearly JSON feeds (gzipped): `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz`
- **No API key required** - uses bulk data feeds instead of the rate-limited NVD API
- Adds `nvd` object with:
  - `cvss_v3_score`, `cvss_v3_severity`, `cvss_v3_vector`
  - `cvss_v2_score`, `cvss_v2_severity`, `cvss_v2_vector`  
  - `cwe_ids` - weakness enumeration (e.g., CWE-79, CWE-89)
  - `cpe_count`, `reference_count` - affected product and reference counts
- Falls back to NVD CVSS if CVE List V5 doesn't have CVSS data
- Can be skipped with `--skip-nvd` flag for faster runs

## Data Flow

```
┌─────────────────┐     ┌──────────────┐     ┌───────────────┐
│  CVE List V5    │────▶│              │────▶│               │
│  (base CVE data)│     │              │     │               │
└─────────────────┘     │              │     │               │
                        │              │     │               │
┌─────────────────┐     │    VulnRadar │     │  radar_data   │
│  CISA KEV       │────▶│      ETL     │────▶│    .json      │
│  (exploitation) │     │              │     │               │
└─────────────────┘     │              │     │               │
                        │              │     │               │
┌─────────────────┐     │              │     │               │
│  EPSS           │────▶│              │     │               │
│  (probability)  │     │              │     └───────────────┘
└─────────────────┘     │              │
                        │              │     ┌───────────────┐
┌─────────────────┐     │              │────▶│ radar_report  │
│  PatchThis      │────▶│              │     │     .md       │
│  (priority)     │     │              │     └───────────────┘
└─────────────────┘     │              │
                        │              │
┌─────────────────┐     │              │
│  NVD Feeds      │────▶│              │
│  (CVSS/CWE/CPE) │     │              │
└─────────────────┘     └──────────────┘
```

## Verify

- Confirm URLs are reachable
- Confirm ETL succeeds without manual downloads
- Test with `--skip-nvd` if NVD feeds are slow
