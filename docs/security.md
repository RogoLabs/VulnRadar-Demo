# Security

## Tokens

- Prefer ephemeral tokens.
- Don’t commit PATs.

## Data handling

- Output contains CVE metadata and enrichment fields.
- No secrets should be written to `data/`.

## Verify

- Ensure `data/radar_data.json` contains no secrets
