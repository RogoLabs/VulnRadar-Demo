# Troubleshooting

## ETL produces no results

- Check `watchlist.yaml` terms.
- Confirm network access to data sources.
- Try broadening the scan window: `python etl.py --min-year <year>`.

## "Could not find *_all_CVEs_at_midnight.zip asset" error

The upstream CVEProject/cvelistV5 repository publishes an `at_end_of_day`
release each night that does **not** include the midnight bulk ZIP. If the
GitHub `/releases/latest` endpoint returns that release, VulnRadar
automatically falls back to scanning the 5 most recent releases.

If you still see this error:

1. Check that the `GITHUB_TOKEN` secret is set (unauthenticated requests hit
   strict rate limits on the GitHub API).
2. Verify that <https://github.com/CVEProject/cvelistV5/releases> has recent
   releases with a `*_all_CVEs_at_midnight.zip` asset.
3. Try re-running the workflow — the upstream release assets may still be
   uploading.

## GitHub Action fails to push

- On forks: scheduled pushes may be restricted; run locally or adjust permissions.
- Ensure the workflow has `contents: write` permission.

## Verify

- Run `python etl.py --min-year <year>` to broaden scan window.
