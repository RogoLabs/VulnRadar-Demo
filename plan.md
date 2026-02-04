# VulnRadar Improvement Plan – BSidesGalway Edition

> **Target:** Make VulnRadar a world-class "Fork & Go" vulnerability intelligence tool for your BSidesGalway presentation.
>
> **Timeline:** 1 week (Feb 4–11, 2026)
>
> **Demo Repo:** `VulnRadar-Demo` (all Actions testing happens there, not in the main repo)

---

## Executive Summary

VulnRadar is already a solid foundation: it pulls CVE data from bulk data feeds (no API keys required!), enriches with KEV/EPSS/PatchThis/NVD, and auto-generates GitHub-native reports. To make it **conference-worthy**, we need to:

1. **Perfect the "Fork & Go" experience** – zero-friction onboarding
2. **Add visual polish** – badges, diagrams, a slick README
3. **Harden for production** – tests, CI quality gates, better error handling
4. **Add killer features** – Slack/Teams webhooks, configurable thresholds, historical trending
5. **Create demo-ready materials** – sample outputs, a compelling watchlist, presentation assets

---

## Current State Assessment

### ✅ Strengths
- Clean ETL pipeline with retry logic (tenacity)
- **Five enrichment sources:**
  - CVE List V5 (bulk ZIP export - primary CVE data)
  - CISA KEV catalog (active exploitation flags)
  - FIRST.org EPSS (probability scores)
  - PatchThis intelligence feed (priority labels)
  - **NVD Data Feeds (CVSS, CWE, CPE enrichment - no API key!)** ← NEW!
- GitHub-native outputs (Markdown report, JSON data)
- Smart branch strategy (`main` clean, `demo` for CI outputs)
- Good documentation structure in `docs/`
- **No external API keys required** (uses public feeds + `GITHUB_TOKEN`)

### ⚠️ Areas for Improvement
- **No tests** – risky for a "production" tool
- **No CI quality gates** – linting, type checking missing
- **Basic error messages** – failures aren't user-friendly
- **Limited notification options** – only GitHub Issues
- **No badges** – missed opportunity for instant credibility
- **Sparse README** – good but not "wow"
- **Watchlist is too simple** – no regex, no exclusions, no severity filters
- **No historical data** – can't show trends over time
- **Docs are stubs** – many pages are skeletal

---

## Week-Long Sprint Plan

### Day 1 (Tuesday): Fork & Go Polish 🎯

**Goal:** Anyone can fork and have it running in under 5 minutes.

#### Tasks

- [ ] **Add repository badges to README**
  ```markdown
  ![License](https://img.shields.io/github/license/RogoLabs/VulnRadar)
  ![Python](https://img.shields.io/badge/python-3.11+-blue)
  ![Last Commit](https://img.shields.io/github/last-commit/RogoLabs/VulnRadar)
  ![GitHub Actions](https://img.shields.io/github/actions/workflow/status/RogoLabs/VulnRadar/update.yml?label=ETL)
  ```

- [ ] **Create `.github/FUNDING.yml`** (optional, for sponsorship)

- [ ] **Add "Fork This Repo" button/instructions** in README
  - Screenshot of the fork button
  - "Enable Actions on your fork" callout with screenshot
  - Estimated time: "< 5 minutes to first report"

- [ ] **Create `watchlist.example.json`** with diverse, compelling examples
  ```json
  {
    "vendors": ["microsoft", "apache", "google", "mozilla", "linux"],
    "products": ["exchange", "log4j", "chrome", "firefox", "kernel", "openssl"]
  }
  ```

- [ ] **Add "Quick Start" hero section to README**
  ```markdown
  ## ⚡ Quick Start (2 minutes)
  
  1. Fork this repo
  2. Enable GitHub Actions
  3. Edit `watchlist.json` with your tech stack
  4. Wait 6 hours (or trigger manually)
  5. Check `data/radar_report.md`
  ```

- [ ] **Disable workflows by default in main repo**
  - Add `if: github.repository == 'YOUR_FORK'` pattern OR
  - Document in README that users must enable Actions
  - Create `.github/workflows/README.md` explaining fork-first design

---

### Day 2 (Wednesday): Code Quality & Testing 🧪

**Goal:** Add confidence with tests and linting.

#### Tasks

- [ ] **Add `pytest` + test structure**
  ```
  tests/
    __init__.py
    test_etl.py
    test_notify.py
    conftest.py
    fixtures/
      sample_cve.json
      sample_kev.json
      sample_watchlist.json
  ```

- [ ] **Write core unit tests**
  - `test_load_watchlist()` – various inputs
  - `test_matches_watchlist()` – edge cases
  - `test_parse_cve_json()` – with fixture data
  - `test_risk_bucket()` – priority logic
  - `test_issue_body()` – notification formatting

- [ ] **Add `ruff` for linting** (fast, modern)
  ```toml
  # pyproject.toml
  [tool.ruff]
  line-length = 120
  select = ["E", "F", "I", "UP", "B"]
  ```

- [ ] **Add `mypy` for type checking**
  - Already have type hints in code – leverage them!

- [ ] **Create CI workflow for PRs**
  ```yaml
  # .github/workflows/ci.yml
  name: CI
  on: [pull_request]
  jobs:
    test:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-python@v5
          with:
            python-version: "3.11"
        - run: pip install -r requirements.txt -r requirements-dev.txt
        - run: ruff check .
        - run: mypy etl.py notify.py
        - run: pytest -v
  ```

- [ ] **Update `requirements.txt`** (add PyYAML)
  ```
  requests>=2.31.0
  tenacity>=8.2.3
  pyyaml>=6.0.1
  ```

- [ ] **Create `requirements-dev.txt`**
  ```
  pytest>=7.4.0
  ruff>=0.1.0
  mypy>=1.7.0
  types-requests>=2.31.0
  ```

---

### Day 3 (Thursday): Enhanced Notifications 📣

**Goal:** Discord/Slack/Teams webhooks + configurable alerting thresholds.

#### Tasks

- [ ] **Add Discord webhook support** (Priority - already using with OpenClaw)
  ```python
  # notify.py additions
  def send_discord_alert(webhook_url: str, item: Dict[str, Any]) -> None:
      """Send a formatted Discord embed for a CVE finding."""
      priority = item.get('priority_label', 'ALERT')
      color = 0xFF0000 if 'CRITICAL' in priority else 0xFFA500 if 'WARNING' in priority else 0x3498DB
      
      payload = {
          "embeds": [{
              "title": f"🚨 {item['cve_id']}",
              "description": item.get('description', '')[:500],
              "color": color,
              "fields": [
                  {"name": "Priority", "value": priority, "inline": True},
                  {"name": "EPSS", "value": f"{item.get('probability_score', 0):.3f}", "inline": True},
                  {"name": "CVSS", "value": f"{item.get('cvss_score', 'N/A')}", "inline": True},
                  {"name": "KEV", "value": "✅" if item.get('active_threat') else "❌", "inline": True},
                  {"name": "PatchThis", "value": "✅" if item.get('in_patchthis') else "❌", "inline": True},
              ],
              "url": f"https://www.cve.org/CVERecord?id={item['cve_id']}",
              "footer": {"text": "VulnRadar Alert"}
          }]
      }
      requests.post(webhook_url, json=payload, timeout=30)
  ```

- [ ] **Add Slack webhook support**
  ```python
  # notify.py additions
  def send_slack_alert(webhook_url: str, item: Dict[str, Any]) -> None:
      """Send a formatted Slack message for a CVE finding."""
      payload = {
          "blocks": [
              {"type": "header", "text": {"type": "plain_text", "text": f"🚨 {item['cve_id']}"}},
              {"type": "section", "fields": [
                  {"type": "mrkdwn", "text": f"*Priority:* {item.get('priority_label', 'N/A')}"},
                  {"type": "mrkdwn", "text": f"*EPSS:* {item.get('probability_score', 'N/A'):.3f}"},
              ]},
          ]
      }
      requests.post(webhook_url, json=payload, timeout=30)
  ```

- [ ] **Add Microsoft Teams webhook support**

- [ ] **Create `config.yml` for notification settings**
  ```yaml
  notifications:
    github_issues:
      enabled: true
      max_per_run: 25
      labels: ["vulnradar", "alert"]
    
    discord:
      enabled: true  # Primary - matches OpenClaw setup
      webhook_url: ${DISCORD_WEBHOOK_URL}
    
    slack:
      enabled: false
      webhook_url: ${SLACK_WEBHOOK_URL}
      channels: ["#security-alerts"]
    
    teams:
      enabled: false
      webhook_url: ${TEAMS_WEBHOOK_URL}
  
  thresholds:
    critical_epss: 0.7
    critical_cvss: 9.0
    notify_kev: true
    notify_patchthis: true
  ```

- [ ] **Add workflow for Discord/Slack/Teams notifications**
  ```yaml
  # .github/workflows/notify-discord.yml
  name: VulnRadar Discord Notifications
  on:
    workflow_run:
      workflows: ["Update Vulnerability Radar Data"]
      types: [completed]
  jobs:
    notify:
      if: ${{ github.event.workflow_run.conclusion == 'success' }}
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
          with:
            ref: demo
        - uses: actions/setup-python@v5
          with:
            python-version: "3.11"
        - run: pip install -r requirements.txt
        - run: python notify.py --discord
          env:
            DISCORD_WEBHOOK_URL: ${{ secrets.DISCORD_WEBHOOK_URL }}
  ```

- [ ] **Document webhook setup in `docs/notifications.md`**
  - Discord: Server Settings → Integrations → Webhooks → New Webhook
  - Store as `DISCORD_WEBHOOK_URL` secret in repo

---

### Day 4 (Friday): Advanced Watchlist & Filtering 🎯

**Goal:** Make the watchlist user-friendly, self-documenting, and powerful.

#### Tasks

- [ ] **Migrate from JSON to YAML** (PyYAML already common, add to requirements)
  - YAML allows comments for documentation
  - More forgiving syntax (no trailing comma hell)
  - Inline examples users can uncomment
  - Rename: `watchlist.json` → `watchlist.yaml`
  - Keep backward compat: detect `.json` and auto-convert with deprecation warning

- [ ] **Create rich `watchlist.yaml` with extensive examples**
  ```yaml
  # VulnRadar Watchlist Configuration
  # ================================
  # Add vendors and products from YOUR tech stack.
  # Matching is case-insensitive and uses substring matching.
  #
  # HOW TO FIND VALID NAMES:
  #   1. Run: python etl.py --list-vendors    (shows all vendors in CVE data)
  #   2. Run: python etl.py --list-products   (shows all products)
  #   3. Run: python etl.py --search "apache" (fuzzy search)
  #   4. Check: https://cve.org and look at affected products
  #
  # VALIDATION:
  #   Run: python etl.py --validate-watchlist
  #   This checks your entries against real CVE data and warns about typos.
  
  # ============================================================================
  # VENDORS - Organizations that publish software
  # ============================================================================
  vendors:
    # --- Big Tech (comment out what you don't use) ---
    - microsoft       # Windows, Office, Azure, Exchange, etc.
    - google          # Chrome, Android, GCP, etc.
    - apple           # macOS, iOS, Safari, etc.
    # - amazon        # AWS services
    # - meta          # Facebook products
    
    # --- Linux/Open Source ---
    - linux           # Linux kernel
    - canonical       # Ubuntu
    # - redhat        # RHEL, Fedora
    # - debian        # Debian Linux
    
    # --- Web Infrastructure ---
    - apache          # httpd, Tomcat, Struts, Log4j, Kafka, etc.
    - nginx           # NGINX web server
    # - f5            # BIG-IP, NGINX Plus
    
    # --- Security & Networking ---
    # - paloaltonetworks  # Firewalls, GlobalProtect
    # - fortinet          # FortiGate, FortiOS
    # - cisco             # IOS, ASA, WebEx
    # - citrix            # NetScaler, Workspace
    
    # --- Databases ---
    # - oracle        # Oracle DB, Java, MySQL
    # - mongodb       # MongoDB
    # - postgresql    # PostgreSQL
    
    # --- Virtualization/Cloud ---
    # - vmware        # ESXi, vCenter, Horizon
    # - hashicorp     # Terraform, Vault, Consul
    # - docker        # Docker Engine
    # - kubernetes    # K8s (vendor varies)
  
  # ============================================================================
  # PRODUCTS - Specific software/libraries (more precise than vendors)
  # ============================================================================
  products:
    # --- Web Browsers ---
    - chrome
    - firefox
    # - edge
    # - safari
    
    # --- Famous Vulnerabilities (keep these!) ---
    - log4j           # Log4Shell - CVE-2021-44228
    - openssl         # Heartbleed, etc.
    # - struts        # Apache Struts - Equifax breach
    # - spring        # Spring4Shell
    
    # --- Common Infrastructure ---
    # - exchange      # Microsoft Exchange (ProxyLogon, etc.)
    # - sharepoint    # Microsoft SharePoint
    # - outlook       # Microsoft Outlook
    # - jenkins       # CI/CD server
    # - gitlab        # GitLab CE/EE
    # - jira          # Atlassian Jira
    # - confluence    # Atlassian Confluence
    
    # --- Containers & Orchestration ---
    # - docker        # Docker Engine
    # - containerd    # Container runtime
    # - kubernetes    # K8s
    # - helm          # K8s package manager
    
    # --- Programming Languages/Runtimes ---
    # - node.js       # Node runtime
    # - python        # Python interpreter
    # - java          # Java/JDK
    # - php           # PHP
  
  # ============================================================================
  # EXCLUSIONS - Filter out noise (optional)
  # ============================================================================
  exclude_vendors:
    - n/a
    - unknown
    - unspecified
  
  exclude_products:
    - n/a
    - unknown
  
  # ============================================================================
  # THRESHOLDS - Minimum severity to include (optional)
  # ============================================================================
  thresholds:
    min_cvss: 0.0         # 0.0 = include all, 7.0 = high+ only, 9.0 = critical only
    min_epss: 0.0         # 0.0 = include all, 0.1 = 10%+ exploit probability
  
  # ============================================================================
  # BEHAVIOR FLAGS (optional)
  # ============================================================================
  options:
    always_include_kev: true       # Always include CISA KEV even if not in watchlist
    always_include_patchthis: true # Always include PatchThis items
    case_sensitive: false          # Usually want false
    match_mode: substring          # 'substring', 'exact', or 'regex'
  
  # ============================================================================
  # NAMED GROUPS - Organize by category (optional, advanced)
  # ============================================================================
  # groups:
  #   web-stack:
  #     vendors: [apache, nginx]
  #     products: [httpd, tomcat, php]
  #   
  #   microsoft-365:
  #     vendors: [microsoft]
  #     products: [exchange, outlook, sharepoint, teams]
  #   
  #   security-tools:
  #     vendors: [paloaltonetworks, fortinet, cisco]
  #     products: [globalprotect, fortigate, asa]
  ```

- [ ] **Add discovery commands to ETL**
  ```bash
  # Find valid vendor names
  python etl.py --list-vendors
  python etl.py --list-vendors --filter "micro"  # Search vendors
  
  # Find valid product names  
  python etl.py --list-products
  python etl.py --list-products --filter "log4"  # Search products
  
  # Fuzzy search across both
  python etl.py --search "apache"  # Shows vendors AND products matching
  
  # Validate your watchlist against real data
  python etl.py --validate-watchlist
  # Output:
  # ✅ vendor 'microsoft' - found 1,234 CVEs
  # ✅ vendor 'apache' - found 567 CVEs  
  # ⚠️  vendor 'microsft' - no matches (did you mean 'microsoft'?)
  # ✅ product 'log4j' - found 45 CVEs
  # ❌ product 'log4shell' - no matches (try 'log4j' instead)
  ```

- [ ] **Add `--validate-watchlist` flag implementation**
  ```python
  def validate_watchlist(watchlist: Watchlist, cves_root: Path) -> ValidationReport:
      """Check watchlist entries against actual CVE data."""
      # Scan a sample of CVEs to build vendor/product index
      # Report matches, non-matches, and suggestions
      # Use fuzzy matching (difflib) for "did you mean?" suggestions
  ```

- [ ] **Create `watchlist.example.yaml`** - heavily commented reference
  - Ship this alongside a minimal `watchlist.yaml`
  - Users copy examples they want

- [ ] **Add schema validation with helpful errors**
  ```python
  def load_watchlist(path: Path) -> Watchlist:
      # Detect YAML vs JSON
      # Validate required fields
      # Warn on deprecated JSON format
      # Return helpful errors:
      #   "Line 15: 'vendrs' is not valid. Did you mean 'vendors'?"
      #   "Line 23: products must be a list, got string"
  ```

- [ ] **Add common mistakes documentation**
  ```markdown
  ## Common Watchlist Mistakes
  
  | Wrong | Right | Why |
  |-------|-------|-----|
  | `Microsoft` | `microsoft` | CVE data uses lowercase |
  | `apache software foundation` | `apache` | Substring match works |
  | `log4shell` | `log4j` | CVEs reference product, not vuln name |
  | `CVE-2021-44228` | `log4j` | Watchlist is for products, not CVE IDs |
  | `windows 10` | `windows` | Version is separate field |
  ```

---

### Day 5 (Saturday): Visual & Documentation Excellence 📊

**Goal:** Make the output stunning and the docs comprehensive.

#### Tasks

- [ ] **Add Mermaid diagrams to docs**
  
  ```mermaid
  flowchart LR
      A[CVE List V5] --> D[ETL]
      B[CISA KEV] --> D
      C[EPSS] --> D
      E[PatchThis] --> D
      F[watchlist.json] --> D
      D --> G[radar_data.json]
      D --> H[radar_report.md]
      G --> I[GitHub Issues]
      G --> J[Slack/Teams]
  ```

- [ ] **Enhance `radar_report.md` output**
  - Add summary statistics at top
  - Add severity distribution chart (ASCII or emoji-based)
  - Add "What changed since last run" section
  - Add links to each CVE's NVD/MITRE page

- [ ] **Create sample outputs in `examples/`**
  ```
  examples/
    sample_radar_report.md
    sample_radar_data.json
    sample_github_issue.png
  ```

- [ ] **Flesh out all doc stubs** (see detailed list below)

- [ ] **Add architecture diagram** to main README

- [ ] **Create `CHANGELOG.md`** for release tracking

---

### Day 6 (Sunday): Historical Trending & Analytics 📈

**Goal:** Track vulnerability trends over time.

#### Tasks

- [ ] **Add historical data storage**
  ```
  data/
    radar_data.json        # Current run
    history/
      2026-02-04.json      # Daily snapshots
      2026-02-05.json
  ```

- [ ] **Create `analyze.py` for trend analysis**
  - New CVEs since last run
  - Resolved CVEs (no longer in feeds)
  - EPSS score changes over time
  - KEV additions

- [ ] **Add trend section to `radar_report.md`**
  ```markdown
  ## Trends (Last 7 Days)
  - New CVEs matching watchlist: 12
  - Removed from feeds: 3
  - KEV additions: 2
  - Avg EPSS increase: +0.05
  ```

- [ ] **Add `--diff` flag to ETL**
  ```bash
  python etl.py --diff  # Shows what changed
  ```

---

### Day 7 (Monday): Demo Prep & Polish ✨

**Goal:** Everything ready for BSidesGalway demo.

#### Tasks

- [ ] **Test full flow on VulnRadar-Demo repo**
  - Fork from main
  - Enable Actions
  - Customize watchlist
  - Trigger manual run
  - Verify outputs

- [ ] **Create compelling demo watchlist**
  - Include currently-exploited CVEs
  - Include popular tech stacks
  - Show variety of matches

- [ ] **Record GIF/video of the workflow** for README

- [ ] **Write presentation notes** linking to repo features

- [ ] **Create GitHub Release v1.0.0**
  - Tag the commit
  - Write release notes
  - Highlight "Fork & Go" readiness

- [ ] **Final README polish**
  - Feature comparison table vs. other tools
  - "Why VulnRadar?" section
  - Testimonials/use cases (if any)

---

## Detailed Documentation Tasks

Flesh out these stub docs in `docs/`:

| Page | Current State | Target State |
|------|--------------|--------------|
| `getting-started.md` | Minimal | Full walkthrough with screenshots |
| `configuration.md` | Basic schema | Full schema + examples + validation |
| `data-sources.md` | URLs only | Explain each source, update cadence, reliability |
| `etl.md` | Brief | Algorithm explanation, performance tuning, examples |
| `data-schema.md` | Field list | Full schema with types, examples, JSON Schema |
| `automation.md` | Stub | Complete Actions guide with diagrams |
| `operations.md` | Stub | Runbook: monitoring, alerting, cost management |
| `troubleshooting.md` | 2 items | Comprehensive FAQ with solutions |
| `security.md` | Minimal | Threat model, token handling, supply chain |
| `contributing.md` | Stub | Full guide: setup, testing, PR process |
| `faq.md` | 2 questions | 15+ real questions |
| `notifications.md` | ❌ Missing | Full notification setup guide |

---

## New Files to Create

```
.github/
  workflows/
    ci.yml                    # PR checks (lint, test, type)
    notify-slack.yml          # Slack notifications (optional)
  ISSUE_TEMPLATE/
    bug_report.md
    feature_request.md
  PULL_REQUEST_TEMPLATE.md
  CODEOWNERS
  dependabot.yml              # Keep deps updated

tests/
  __init__.py
  test_etl.py
  test_notify.py
  conftest.py
  fixtures/
    sample_cve.json
    sample_kev.json
    sample_epss.csv
    sample_watchlist.json

examples/
  sample_radar_report.md
  sample_radar_data.json
  watchlists/
    enterprise.yaml       # Large org: Microsoft, Cisco, VMware, etc.
    startup.yaml          # Modern stack: AWS, K8s, Node, etc.
    devsecops.yaml        # CI/CD focused: Jenkins, GitLab, GitHub
    healthcare.yaml       # HIPAA-relevant vendors
    financial.yaml        # PCI-DSS relevant vendors

pyproject.toml               # Modern Python project config
requirements-dev.txt         # Dev dependencies
config.yml                   # Optional configuration
config.example.yml
CHANGELOG.md
SECURITY.md                  # Security policy
```

---

## Priority Matrix

| Task | Impact | Effort | Priority |
|------|--------|--------|----------|
| Badges + README polish | High | Low | **P0** |
| Fork & Go instructions | High | Low | **P0** |
| Unit tests | High | Medium | **P1** |
| CI workflow | High | Low | **P1** |
| Slack/Teams webhooks | High | Medium | **P1** |
| Extended watchlist | Medium | Medium | **P2** |
| Historical trending | Medium | High | **P2** |
| Documentation | Medium | Medium | **P2** |
| Mermaid diagrams | Low | Low | **P3** |
| Demo video/GIF | Medium | Low | **P1** |

---

## "Fork & Go" Checklist

For the main repo to truly be fork-friendly:

- [ ] Workflows don't auto-run on the main repo (use repo condition or disable)
- [ ] Clear "First 5 Minutes" guide
- [ ] `watchlist.json` has sensible defaults but is clearly meant to be customized
- [ ] `data/` folder has `.gitkeep` only (no stale data)
- [ ] All secrets are documented (just `GITHUB_TOKEN` ideally)
- [ ] License is clear (MIT ✅)
- [ ] No hardcoded paths or repo names in code

---

## Demo Script for BSidesGalway

1. **Show the problem** (2 min)
   - "Thousands of CVEs published weekly"
   - "Most tools need NVD API keys, Shodan, etc."

2. **Fork the repo live** (2 min)
   - Fork → Enable Actions → Edit watchlist → Trigger

3. **Show outputs** (3 min)
   - `radar_report.md` renders beautifully in GitHub
   - GitHub Issues for critical findings
   - Discord notification (using existing OpenClaw server)

4. **Explain the magic** (3 min)
   - KEV = actively exploited
   - EPSS = probability score
   - PatchThis = crowd-sourced intel

5. **Customize live** (2 min)
   - Add a vendor to watchlist
   - Show new matches

6. **Call to action** (1 min)
   - "Fork it now, secure your stack tonight"
   - QR code to repo

---

## Success Metrics

By talk day, the repo should have:

- [ ] 100% GitHub Actions passing on VulnRadar-Demo
- [ ] `< 5 min` fork-to-first-report experience documented
- [ ] `python etl.py --validate-watchlist` works with helpful output
- [ ] At least 10 unit tests passing
- [ ] Discord webhook working end-to-end (reuse OpenClaw server)
- [ ] Beautiful README with badges, GIF, and architecture diagram
- [ ] All doc stubs filled in
- [ ] v1.0.0 release tagged

---

## Questions to Resolve

1. **Branding:** Keep "VulnRadar" or rename? (VulnRadar is catchy ✅)
2. **Org:** Should this live under RogoLabs or personal account?
3. **Notifications:** Discord first ✅ (already using with OpenClaw)
4. **History:** Store in same repo or separate data repo?

---

## Notes

- The `VulnRadar-Demo` repo is your safe testing ground – break things there
- Main repo stays clean, docs-focused, ready to fork
- Consider adding a "Powered by VulnRadar" badge for users to show off

---

*Plan created: Feb 4, 2026*
*Target event: BSidesGalway 2026*
