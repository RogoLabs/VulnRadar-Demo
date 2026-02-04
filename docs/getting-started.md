# Getting Started

## Goal

Run the ETL to generate a GitHub-renderable report (`data/radar_report.md`).

## Prerequisites

- Python 3.11+ recommended
- pip
- Optional: `GITHUB_TOKEN` (helps avoid GitHub API rate limits)

## Install

```bash
pip install -r requirements.txt
```

## Generate Data

```bash
python etl.py
```

## Verify

- `data/radar_report.md` exists (open it in GitHub or in your editor)
- `data/radar_data.json` exists (machine-readable payload for notifications)
