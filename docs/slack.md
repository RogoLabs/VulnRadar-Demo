# Slack Webhook Integration

VulnRadar can send vulnerability alerts directly to your Slack workspace via incoming webhooks.

## Setup

### 1. Create a Slack App with Incoming Webhook

1. Go to [Slack API Apps](https://api.slack.com/apps)
2. Click **Create New App** → **From scratch**
3. Name it (e.g., "VulnRadar") and select your workspace
4. In the left sidebar, click **Incoming Webhooks**
5. Toggle **Activate Incoming Webhooks** to On
6. Click **Add New Webhook to Workspace**
7. Select the channel for alerts (e.g., `#security-alerts`)
8. Copy the webhook URL (starts with `https://hooks.slack.com/services/...`)

### 2. Add Secret to Your Fork

1. Go to your forked repo → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `SLACK_WEBHOOK_URL`
4. Value: Paste your webhook URL
5. Click **Add secret**

That's it! The next scheduled run will send alerts to Slack.

## Configuration Options

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |

### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--slack-webhook` | `$SLACK_WEBHOOK_URL` | Webhook URL |
| `--slack-summary-only` | false | Only send summary, no individual alerts |
| `--slack-max` | 10 | Max individual CVE alerts per run |

### Examples

```bash
# Summary only (no individual CVE alerts)
python notify.py --slack-webhook "$SLACK_WEBHOOK_URL" --slack-summary-only

# Limit to 5 individual alerts
python notify.py --slack-webhook "$SLACK_WEBHOOK_URL" --slack-max 5

# Dry run (test without sending)
python notify.py --slack-webhook "$SLACK_WEBHOOK_URL" --dry-run
```

## Message Format

### Summary Message
A daily overview with:
- Total CVEs matching your watchlist
- Count of critical, KEV, and Exploit Intel (PoC) findings
- Top 5 critical CVEs with EPSS scores

### Individual Alerts
Each CVE alert includes:
- Priority indicator (🚨 CRITICAL, ⚠️ KEV, ℹ️ ALERT)
- CVE ID with link to cve.org
- Description
- EPSS and CVSS scores
- KEV and Exploit Intel status

## Rate Limiting

VulnRadar includes a 1-second delay between messages to respect Slack's rate limits (~1 message/second for incoming webhooks).

## Troubleshooting

### Webhook Not Working

1. **Test the webhook manually:**
   ```bash
   curl -X POST -H 'Content-type: application/json' \
     --data '{"text":"Hello from VulnRadar!"}' \
     "$SLACK_WEBHOOK_URL"
   ```

2. **Check the secret is set correctly:**
   - Go to repo Settings → Secrets → Actions
   - Verify `SLACK_WEBHOOK_URL` exists

3. **Check workflow logs:**
   - Go to Actions tab → VulnRadar Notifications
   - Look for "Sending Slack notifications..." in the logs

### Messages Not Appearing

- Verify the webhook is configured for the correct channel
- Check if the Slack app has been removed from the workspace
- Look for errors in the workflow logs

### Rate Limited

If you see `429 Too Many Requests`:
- Reduce `--slack-max` to send fewer individual alerts
- Use `--slack-summary-only` to only send the summary

## Security Notes

- Webhook URLs are sensitive - never commit them to code
- Use GitHub Secrets to store the URL
- Rotate the webhook if it's ever exposed
- The webhook can only post to the configured channel
