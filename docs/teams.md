# Microsoft Teams Webhook Integration

VulnRadar can send vulnerability alerts to Microsoft Teams channels using Adaptive Cards via incoming webhooks.

## Setup

### 1. Create an Incoming Webhook in Teams

1. Open Microsoft Teams
2. Navigate to the channel where you want alerts
3. Click the **•••** menu next to the channel name
4. Select **Connectors** (or **Manage channel** → **Connectors**)
5. Find **Incoming Webhook** and click **Configure**
6. Name it (e.g., "VulnRadar") and optionally upload an icon
7. Click **Create**
8. Copy the webhook URL (starts with `https://...webhook.office.com/...`)
9. Click **Done**

> **Note:** If you're using the new Teams, you may need to use Workflows instead. See [Microsoft's documentation](https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498).

### 2. Add Secret to Your Fork

1. Go to your forked repo → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `TEAMS_WEBHOOK_URL`
4. Value: Paste your webhook URL
5. Click **Add secret**

That's it! The next scheduled run will send alerts to Teams.

## Configuration Options

### Environment Variables

| Variable | Description |
|----------|-------------|
| `TEAMS_WEBHOOK_URL` | Teams incoming webhook URL |

### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--teams-webhook` | `$TEAMS_WEBHOOK_URL` | Webhook URL |
| `--teams-summary-only` | false | Only send summary, no individual alerts |
| `--teams-max` | 10 | Max individual CVE alerts per run |

### Examples

```bash
# Summary only (no individual CVE alerts)
python notify.py --teams-webhook "$TEAMS_WEBHOOK_URL" --teams-summary-only

# Limit to 5 individual alerts
python notify.py --teams-webhook "$TEAMS_WEBHOOK_URL" --teams-max 5

# Dry run (test without sending)
python notify.py --teams-webhook "$TEAMS_WEBHOOK_URL" --dry-run
```

## Message Format

VulnRadar uses **Adaptive Cards** for rich formatting in Teams.

### Summary Card
A daily overview showing:
- Total CVEs matching your watchlist (large numbers in columns)
- Count of critical, KEV, and Exploit Intel (PoC) findings
- Top 5 critical CVEs with EPSS scores and links

### Individual Alert Cards
Each CVE alert includes:
- Priority indicator with color coding (CRITICAL=red, KEV=orange, ALERT=blue)
- CVE ID and description
- Fact set with EPSS, CVSS, KEV, and Exploit Intel status
- "View CVE Details" button linking to cve.org

## Rate Limiting

VulnRadar includes a 0.5-second delay between messages. Teams webhooks allow approximately 4 requests/second, so this provides a comfortable margin.

## Troubleshooting

### Webhook Not Working

1. **Test the webhook manually:**
   ```bash
   curl -H "Content-Type: application/json" -d '{
     "type": "message",
     "attachments": [{
       "contentType": "application/vnd.microsoft.card.adaptive",
       "content": {
         "type": "AdaptiveCard",
         "version": "1.4",
         "body": [{"type": "TextBlock", "text": "Hello from VulnRadar!"}]
       }
     }]
   }' "$TEAMS_WEBHOOK_URL"
   ```

2. **Check the secret is set correctly:**
   - Go to repo Settings → Secrets → Actions
   - Verify `TEAMS_WEBHOOK_URL` exists

3. **Check workflow logs:**
   - Go to Actions tab → VulnRadar Notifications
   - Look for "Sending Teams notifications..." in the logs

### Cards Not Rendering

- Ensure the webhook URL is for a channel connector, not a workflow
- Verify the Adaptive Card JSON is valid at [Adaptive Cards Designer](https://adaptivecards.io/designer/)
- Check if your Teams tenant has restrictions on connectors

### Common Errors

| Error | Solution |
|-------|----------|
| `403 Forbidden` | Webhook may be disabled or expired - recreate it |
| `400 Bad Request` | Card JSON may be malformed - check logs |
| `429 Too Many Requests` | Reduce `--teams-max` or use `--teams-summary-only` |

### Webhook Types

Microsoft Teams has different webhook types:

| Type | Supported | Notes |
|------|-----------|-------|
| Incoming Webhook (Connector) | ✅ Yes | Classic method, works with Adaptive Cards |
| Power Automate Workflow | ⚠️ Partial | May require different payload format |
| Bot Framework | ❌ No | Requires app registration |

VulnRadar is designed for the **Incoming Webhook (Connector)** method.

## Security Notes

- Webhook URLs are sensitive - never commit them to code
- Use GitHub Secrets to store the URL
- Rotate the webhook if it's ever exposed
- Webhooks can only post to the configured channel
- Consider channel permissions for who can see security alerts
