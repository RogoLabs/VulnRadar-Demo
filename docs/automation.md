# Automation

## Workflow

See `.github/workflows/update.yml`.

- Runs every hour
- Executes `python etl.py`
- Publishes refreshed `data/radar_data.json` to the `demo` branch

## Branch model

- `main`: stable, fork-friendly
- `demo`: CI-updated snapshot of `main` + latest data

## Verify

- Run workflow via `workflow_dispatch`
- Confirm `demo` branch updates
