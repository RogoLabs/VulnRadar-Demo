<p align="center">
  <h1 align="center">🛡️ VulnRadar</h1>
  <p align="center">
    <strong>Your personal vulnerability intelligence radar — fork, configure, and go!</strong>
  </p>
  <p align="center">
    <a href="https://github.com/RogoLabs/VulnRadar/blob/main/LICENSE"><img src="https://img.shields.io/github/license/RogoLabs/VulnRadar?style=flat-square" alt="License"></a>
    <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
    <a href="https://github.com/RogoLabs/VulnRadar/actions"><img src="https://img.shields.io/github/actions/workflow/status/RogoLabs/VulnRadar/update.yml?style=flat-square&label=ETL" alt="ETL Status"></a>
  </p>
</p>

---

VulnRadar is a **lightweight, GitHub-native vulnerability intelligence tool** that:

- 📥 Downloads the latest CVE data from `CVEProject/cvelistV5` and NVD data feeds
- 🎯 Filters CVEs against **your** tech stack via `watchlist.yaml`
- 🔥 Enriches with [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [EPSS](https://www.first.org/epss/), [NVD](https://nvd.nist.gov/), and [PatchThis](https://patchthis.app/) intelligence
- 📊 Generates a beautiful Markdown report viewable directly in GitHub
- 🚨 Creates GitHub Issues for critical findings
- 🔔 Sends Discord/Slack/Teams notifications (optional)

**No API keys. No external services. Just fork and go.**

---

## ⚡ Quick Start (Under 5 Minutes)

### 1️⃣ Fork this repository
Click the **Fork** button at the top right of this page.

### 2️⃣ Enable GitHub Actions
Go to your fork → **Actions** tab → Click **"I understand my workflows, go ahead and enable them"**

### 3️⃣ Configure your watchlist
Edit `watchlist.yaml` with your tech stack:

```yaml
vendors:
  - microsoft
  - apache
  - linux

products:
  - chrome
  - log4j
  - kubernetes
```

### 4️⃣ Run the ETL
Either wait for the scheduled run (every 6 hours) or:
- Go to **Actions** → **Update Vulnerability Radar Data** → **Run workflow**

### 5️⃣ View your report
Check `data/radar_report.md` in your fork — it renders beautifully in GitHub!

> 📺 **See it in action:** [VulnRadar-Demo](https://github.com/RogoLabs/VulnRadar-Demo) has a live example with real data.

---

## 🏗️ Architecture

```mermaid
flowchart LR
    subgraph Data Sources
        A[CVE List V5]
        B[CISA KEV]
        C[EPSS]
        D[PatchThis]
    end
    
    subgraph VulnRadar
        E[watchlist.yaml]
        F[etl.py]
    end
    
    subgraph Outputs
        G[radar_report.md]
        H[radar_data.json]
        I[GitHub Issues]
        J[Discord/Slack]
    end
    
    A --> F
    B --> F
    C --> F
    D --> F
    E --> F
    F --> G
    F --> H
    H --> I
    H --> J
```

---

## 📊 Data Sources

| Source | What It Provides | Update Frequency |
|--------|------------------|------------------|
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | All CVE records (bulk ZIP) | Daily midnight |
| [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) | CVSS scores, CPE, CWE, references | Daily |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities | As needed |
| [EPSS](https://www.first.org/epss/) | Exploit probability scores (0-1) | Daily |
| [PatchThis](https://patchthis.app/) | Crowd-sourced exploit intelligence | Continuous |

---

## 🎯 Watchlist Configuration

VulnRadar uses `watchlist.yaml` to filter CVEs relevant to **your** tech stack.

```yaml
# Add vendors (organizations)
vendors:
  - microsoft
  - apache
  - google

# Add products (specific software)
products:
  - exchange      # Microsoft Exchange
  - log4j         # Apache Log4j
  - kubernetes    # Container orchestration

# Optional: exclude noise
exclude_vendors:
  - n/a
  - unknown
```

**Tips:**
- Matching is **case-insensitive** and uses **substring matching**
- See `watchlist.example.yaml` for extensive examples by category
- Run `python etl.py --validate-watchlist` to check for typos

---

## 🚨 Priority Classification

VulnRadar automatically classifies findings:

| Priority | Condition | Action |
|----------|-----------|--------|
| 🔴 **CRITICAL** | In PatchThis AND in your watchlist | Immediate attention |
| 🟠 **WARNING** | In PatchThis but NOT in watchlist | Shadow IT risk |
| 🟡 **KEV** | In CISA KEV catalog | Active exploitation |
| ⚪ **Other** | Watchlist match only | Monitor |

---

## 🔔 Notifications

### GitHub Issues (Default)
Critical findings automatically create GitHub Issues with the `vulnradar` label.

### Discord (Optional)
Add `DISCORD_WEBHOOK_URL` to your repository secrets to receive Discord alerts.

### Slack/Teams (Optional)
Coming soon!

---

## 🖥️ Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/VulnRadar.git
cd VulnRadar

# Install dependencies
pip install -r requirements.txt

# Run the ETL
python etl.py

# View outputs
open data/radar_report.md      # Markdown report
open data/radar_data.json      # Raw JSON data
```

### CLI Options

```bash
# Scan specific year range
python etl.py --min-year 2023 --max-year 2026

# Include older KEVs outside scan window
python etl.py --include-kev-outside-window
```

---

## 📁 Repository Structure

```
VulnRadar/
├── etl.py                 # Main ETL script
├── notify.py              # GitHub Issues / Discord notifications
├── watchlist.yaml         # Your configuration (edit this!)
├── watchlist.example.yaml # Extensive examples by category
├── requirements.txt       # Python dependencies
├── data/
│   ├── radar_report.md    # GitHub-viewable report (auto-generated)
│   └── radar_data.json    # Machine-readable output (auto-generated)
├── docs/                  # Full documentation
└── .github/workflows/
    ├── update.yml         # Scheduled ETL (every 6 hours)
    └── notify.yml         # Issue creation on new findings
```

---

## 🔐 Security & Privacy

- **No API keys required** — uses only public data feeds
- **No data leaves your repo** — everything runs in GitHub Actions
- **`GITHUB_TOKEN` is automatic** — no PAT needed for basic operation
- **Outputs contain CVE metadata only** — no secrets, no PII

---

## 📚 Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | First-time setup |
| [Configuration](docs/configuration.md) | Watchlist deep-dive |
| [Data Sources](docs/data-sources.md) | How we gather intel |
| [ETL Reference](docs/etl.md) | CLI options and tuning |
| [Data Schema](docs/data-schema.md) | JSON output format |
| [Automation](docs/automation.md) | GitHub Actions setup |
| [Troubleshooting](docs/troubleshooting.md) | Common issues |

---

## 🆚 Why VulnRadar?

| Feature | VulnRadar | Typical Tools |
|---------|-----------|---------------|
| NVD API Required | ❌ No | ✅ Yes |
| API Keys | ❌ None | ✅ Multiple |
| Self-Hosted | ✅ Your GitHub | ❌ SaaS |
| Cost | ✅ Free | 💰 Often paid |
| Setup Time | ⚡ 5 minutes | 🐌 Hours |
| GitHub Native | ✅ Issues, Actions, Markdown | ❌ External dashboards |

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING](docs/contributing.md) for guidelines.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🔴 Live Demo

See VulnRadar in action with real data: **[VulnRadar-Demo](https://github.com/RogoLabs/VulnRadar-Demo)**

---

<p align="center">
  <strong>Built for BSidesGalway 2026</strong><br>
  <sub>Made with ☕ by <a href="https://github.com/RogoLabs">RogoLabs</a></sub>
</p>
