# VulnRadar Docs Plan

This folder is the long-form documentation for VulnRadar. The goal is to make the repo easy to **fork, run, and operate** without reading source code.

## Principles

- **Fork-friendly**: default instructions assume a fork (no write access to upstream).
- **Explain the “why”**: document data sources and why we avoid the NVD API.
- **Reproducible**: every guide should end with a “Verify” section.
- **Operational**: cover GitHub Actions, rate limits, failure modes, and recovery.
- **Security-minded**: document what we store, what we don’t, and how to run safely.

## Suggested Docs Structure

Create/maintain these pages (filenames below match the stub files in this folder):

1. `getting-started.md`
2. `configuration.md`
3. `data-sources.md`
4. `etl.md`
5. `data-schema.md`
6. `automation.md`
7. `operations.md`
8. `troubleshooting.md`
9. `security.md`
10. `faq.md`
11. `contributing.md`

## Roadmap (What to Write, In Order)

### Phase 1 — Minimal “Fork & Run” (Day 1)

**Goal:** A new user can fork, run locally, and understand outputs within 10 minutes.

- Getting started
  - Prereqs: Python version (recommend 3.11+), pip, optional `GITHUB_TOKEN` for API rate limits.
  - Install: `pip install -r requirements.txt`.
  - Generate data: `python etl.py`.
  - Verify: show expected files (`data/radar_report.md`, `data/radar_data.json`) and what success looks like.

- Configuration (watchlist)
  - Describe `watchlist.json` schema (`vendors`, `products`).
  - Provide matching behavior description (case-insensitive, substring match) + examples.
  - “Gotchas”: common vendor/product strings (e.g., `apache` vs `apache software foundation`).

- Data sources
  - CVE List V5: explain GitHub Releases lookup and the `_all_CVEs_at_midnight.zip` asset.
  - CISA KEV: what it represents, update cadence.
  - EPSS: what it represents (probability), update cadence.

- ETL quick explanation
  - What fields we extract: CVE ID, description, CVSS (when present), affected entries.
  - Default scan window: last 5 years inclusive.
  - Inclusion rules:
    - Keep CVEs that hit watchlist OR are KEVs OR appear in PatchThis.
  - Output paths: `data/radar_report.md` (primary), `data/radar_data.json` (machine-readable).

**Acceptance criteria:** Someone who hasn’t seen the code can run the tool end-to-end.

### Phase 2 — Operational & Automation (Day 2–3)

**Goal:** Explain how the repo stays updated and how to troubleshoot CI.

- Automation (GitHub Actions)
  - Explain branch model:
    - `main` remains clean for forks.
    - `demo` is an auto-updated snapshot: `main` + latest `data/radar_data.json`.
  - How to enable Actions on a fork.
  - Common failure modes:
    - GitHub API rate limits (fix: set `GITHUB_TOKEN` / run on schedule).
    - Large downloads/timeouts.
    - Non-fast-forward pushes (why we force-push demo).

- Operations
  - How often data updates (every 6 hours).
  - How to rotate watchlists.
  - Performance guidance: widening year range increases runtime a lot.
  - Cost/limits: network egress, Action minutes.

**Acceptance criteria:** Operators can explain what the workflow does and recover from failures.

### Phase 3 — Data Model & Risk Scoring (Day 3–5)

**Goal:** Make the output schema and ranking logic explicit so others can build on it.

- Data schema page
  - Document `data/radar_data.json` top-level structure: `generated_at`, `count`, `items`.
  - For each item document:
    - `cve_id`, `description`
    - `cvss_score`, `cvss_severity`, `cvss_vector`
    - `affected[]` (vendor/product/versions)
    - `watchlist_hit`, `matched_terms[]`
    - `active_threat`, `kev{...}`
    - `probability_score`

**Acceptance criteria:** Users can parse/consume the JSON without reading source.

### Phase 4 — Security & Governance (Week 2)

**Goal:** Make safe usage and contribution expectations clear.

- Security page
  - Data handling: what we store locally (derived CVE metadata), no secrets.
  - Tokens: best practices for `GITHUB_TOKEN` / PATs.
  - Supply chain: pinning dependencies, verifying sources.

- Contributing
  - Coding style, linting (if you adopt `ruff`/`black` later).
  - How to add a new enrichment source.
  - How to add new visualizations.

- FAQ + Troubleshooting
  - “Why is my radar empty?”
  - “Why did ETL take so long?”
  - “How do I include more years?”
  - “My fork can’t push to demo.”

**Acceptance criteria:** Repo is safe and approachable for external users.

## Cross-Cutting Tasks (Good to Do Anytime)

- Add simple diagrams (Mermaid) in `etl.md` and `automation.md`.
- Add a “Verification checklist” to every page.

## Definition of Done (Docs)

For each page:

- Contains a short purpose statement.
- Has copy/pastable commands.
- Mentions defaults and how to override.
- Ends with a “Verify” section.
