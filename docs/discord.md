# Discord Notifications

VulnRadar can send alerts directly to your Discord server via webhooks. You'll receive:

1. **Daily Summary** - Overview of findings with counts and top critical CVEs
2. **Individual Alerts** - Rich embeds for each critical CVE (optional)

## Setup Guide

### Step 1: Create a Discord Webhook

1. Open Discord and go to your server
2. Right-click the channel where you want alerts → **Edit Channel**
3. Go to **Integrations** → **Webhooks**
4. Click **New Webhook**
5. Give it a name (e.g., "VulnRadar")
6. Optionally set a custom avatar
7. Click **Copy Webhook URL**

> ⚠️ Keep this URL secret! Anyone with it can post to your channel.

### Step 2: Add the Webhook to GitHub

1. Go to your forked VulnRadar repository on GitHub
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `DISCORD_WEBHOOK_URL`
5. Value: Paste the webhook URL from Step 1
6. Click **Add secret**

That's it! The next time the notification workflow runs, you'll receive Discord alerts.

## What You'll Receive

### Daily Summary

A summary embed showing:
- Total CVEs found
- Critical count (Exploit Intel + Watchlist)
- CISA KEV count
- Exploit Intel count (PoC available)
- Top 5 critical findings with links

![Summary Example](https://img.shields.io/badge/Example-Summary-blue)

```
📊 VulnRadar Daily Summary
──────────────────────────
Total CVEs:    2,179
🚨 Critical:   45
⚠️ CISA KEV:   167
🔥 Exploit Intel: 173

Top Critical Findings:
• CVE-2025-24813 (EPSS: 94.2%)
• CVE-2025-53770 (EPSS: 90.5%)
• CVE-2025-59287 (EPSS: 73.5%)
...
```

### Individual Alerts

For each critical CVE, a detailed embed with:
- CVE ID and link
- Description (truncated)
- EPSS score
- CVSS score  
- KEV status
- Exploit Intel status (PoC available)
- KEV due date (if applicable)

Color coding:
- 🔴 **Red** - Critical (Exploit Intel + Watchlist)
- 🟠 **Orange** - CISA KEV
- 🔵 **Blue** - Other alerts

## Configuration Options

### Environment Variables

| Variable | Description |
|----------|-------------|
| `DISCORD_WEBHOOK_URL` | Your Discord webhook URL (required for Discord notifications) |

### Command Line Arguments

```bash
# Send to Discord with custom webhook
python notify.py --discord-webhook "https://discord.com/api/webhooks/..."

# Only send summary, no individual CVE alerts
python notify.py --discord-summary-only

# Limit individual alerts (default: 10)
python notify.py --discord-max 5

# Dry run (preview without sending)
python notify.py --dry-run
```

### Workflow Customization

Edit `.github/workflows/notify.yml` to customize:

```yaml
- name: Create GitHub Issue alerts
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    DISCORD_WEBHOOK_URL: ${{ secrets.DISCORD_WEBHOOK_URL }}
  run: |
    # Summary only (no individual alerts)
    python notify.py --discord-summary-only
    
    # Or with more individual alerts
    python notify.py --discord-max 20
```

## Testing Locally

You can test Discord notifications locally:

```bash
# Set environment variables
export GITHUB_TOKEN="your-github-token"
export GITHUB_REPOSITORY="YourUsername/VulnRadar"
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."

# Run with dry-run first
python notify.py --dry-run

# Then send for real
python notify.py --discord-max 3
```

## Troubleshooting

### No Discord messages appearing

1. **Check the secret name** - Must be exactly `DISCORD_WEBHOOK_URL`
2. **Check webhook URL** - Make sure it starts with `https://discord.com/api/webhooks/`
3. **Check channel permissions** - The webhook needs permission to post in the channel
4. **Check workflow logs** - Look for "Discord notification failed" errors

### Rate limiting

Discord has rate limits on webhooks. If you're sending too many alerts:
- Use `--discord-summary-only` to only send the summary
- Reduce `--discord-max` to send fewer individual alerts
- The default of 10 individual alerts should be safe

### Webhook deleted or invalid

If you regenerate your Discord webhook:
1. Go to GitHub → Settings → Secrets → Actions
2. Update the `DISCORD_WEBHOOK_URL` secret with the new URL

## Multiple Channels

To send to multiple Discord channels, you can:

1. Create multiple webhooks in Discord
2. Modify the workflow to call notify.py multiple times:

```yaml
- name: Send to security-alerts channel
  env:
    DISCORD_WEBHOOK_URL: ${{ secrets.DISCORD_WEBHOOK_SECURITY }}
  run: python notify.py --discord-summary-only

- name: Send to soc-team channel  
  env:
    DISCORD_WEBHOOK_URL: ${{ secrets.DISCORD_WEBHOOK_SOC }}
  run: python notify.py --discord-max 25
```

## Disabling Discord

To disable Discord notifications:
- Simply don't set the `DISCORD_WEBHOOK_URL` secret
- Or remove it from your repository secrets

The workflow will skip Discord notifications if the webhook URL is not set.
