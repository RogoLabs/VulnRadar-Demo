# VulnRadar Weekend Improvement Plan

> **Goal:** Fix workflow timing issues, surface threat intel clearly, and make issues "alive"
>
> **Timeline:** Saturday (Infrastructure) → Sunday (Intelligence & Alerting)

---

## Issues Found (The "Gotchas")

### 1. 🔴 The `[skip ci]` Trap (HIGH PRIORITY)
**File:** `.github/workflows/update.yml`

**Problem:** The ETL workflow commits with `[skip ci]`, which prevents `notify.yml` from triggering on push. Notifications only run on their backup cron schedule (`:15` after ETL at `:00`).

**Impact:**
- If ETL takes >15 minutes, notify runs with stale data
- No immediate alerting when new threats land
- 15-minute window where critical CVEs go unnotified

**Solution Options:**
1. **Remove `[skip ci]`** - Simple, but relies on path filter to prevent loops
2. **Use `workflow_run` trigger** - More robust, explicit dependency chain ✅ RECOMMENDED

### 2. 🟠 PoC Visibility Gap (MEDIUM PRIORITY)
**Problem:** "PatchThis" sounds like "patch available" (remediation) not "exploit available" (threat).

**Impact:** Users don't realize PatchThis = PoC/weaponized exploit intel

**Solution:** Rebrand throughout:
- "PatchThis" → "🔥 Exploit Intel" or "PoC Available"
- Make it visually distinct (red/fire emoji)

### 3. 🔴 Fire-and-Forget Issues (HIGH PRIORITY)
**Problem:** If a CVE already has an issue and gets added to KEV or PatchThis, the issue stays silent.

**Code:** `notify.py` line `if cve_id in existing: continue`

**Impact:** Users miss critical escalations on CVEs they're already tracking

**Solution:** Comment on existing issues when status changes:
- "⚠️ ESCALATION: This CVE was just added to CISA KEV!"
- Optionally reopen closed issues

### 4. 🟡 NVD Download Speed (LOW PRIORITY)
**Problem:** Downloading 5 years of NVD feeds every run is slow (~30MB compressed)

**Solution:** GitHub Actions cache with daily rotation

### 5. 🟢 Dynamic Labels (NICE TO HAVE)
**Problem:** No way to filter issues by vendor/product

**Solution:** Add labels like `vendor:microsoft`, `product:exchange`

---

## Saturday: Infrastructure & Speed

### Task 1: Fix Workflow Chain with `workflow_run`

Replace the `[skip ci]` hack with proper workflow chaining.

**File:** `.github/workflows/notify.yml`

```yaml
on:
  workflow_dispatch:
  workflow_run:
    workflows: ["Update Vulnerability Radar Data"]
    types: [completed]
    branches: [main]
  schedule:
    - cron: "15 */6 * * *"  # Backup if workflow_run fails
```

**File:** `.github/workflows/update.yml`

```yaml
# Keep [skip ci] to prevent push-triggered notify
# workflow_run will handle notification triggering
git commit -m "chore: update radar outputs [skip ci]"
```

**Logic:**
- ETL completes → `workflow_run` triggers notify
- `[skip ci]` stays to prevent BOTH push trigger AND workflow_run from firing
- Backup cron still runs in case workflow_run fails

**Add condition to notify.yml:**
```yaml
jobs:
  notify:
    # Only run on forks, skip if ETL failed
    if: |
      github.repository != 'RogoLabs/VulnRadar' &&
      (github.event_name != 'workflow_run' || github.event.workflow_run.conclusion == 'success')
```

### Task 2: Add NVD Caching

**File:** `.github/workflows/update.yml`

```yaml
- name: Get date for cache key
  id: date
  run: echo "date=$(date +'%Y-%m-%d')" >> $GITHUB_OUTPUT

- name: Cache NVD Data
  uses: actions/cache@v4
  with:
    path: .nvd_cache
    key: nvd-${{ runner.os }}-${{ steps.date.outputs.date }}
    restore-keys: |
      nvd-${{ runner.os }}-

- name: Run ETL
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    NVD_CACHE_DIR: .nvd_cache
  run: |
    python etl.py
```

**File:** `etl.py`

Add `--nvd-cache` argument and check cache before downloading.

### Task 3: Add Workflow Status Badge

**File:** `README.md`

```markdown
[![ETL Status](https://github.com/OWNER/REPO/actions/workflows/update.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/update.yml)
[![Notifications](https://github.com/OWNER/REPO/actions/workflows/notify.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/notify.yml)
```

---

## Sunday: Intelligence & Alerting

### Task 4: Rebrand "PatchThis" to "Exploit Intel"

**Files to update:**
- `etl.py` - Markdown report generation
- `notify.py` - Issue body, Discord/Slack/Teams messages
- `README.md` - Documentation

**Changes:**
| Old | New |
|-----|-----|
| "PatchThis" | "🔥 Exploit Intel" |
| "in_patchthis" | Keep field name (internal), change display |
| "PatchThis hits" | "Exploit/PoC Available" |

**In issue body:**
```markdown
| Signal | Status |
|--------|--------|
| 🔥 Exploit Intel | ✅ PoC/Weaponized code available |
| ⚠️ CISA KEV | ✅ Known Exploited Vulnerability |
```

### Task 5: Issue Escalation (Comment on Existing Issues)

**File:** `notify.py`

New function to comment on existing issues:

```python
def _escalate_existing_issue(
    session: requests.Session,
    repo: str,
    cve_id: str,
    issue_number: int,
    changes: List[Change],
) -> None:
    """Post escalation comment to existing issue."""
    
    lines = ["## ⚠️ ESCALATION ALERT", ""]
    
    for change in changes:
        if change.change_type == "NEW_KEV":
            lines.append("🔴 **This CVE was just added to CISA KEV!**")
            lines.append("")
            lines.append("This is now a Known Exploited Vulnerability with active exploitation in the wild.")
        elif change.change_type == "NEW_PATCHTHIS":
            lines.append("🔥 **Exploit/PoC code is now available!**")
            lines.append("")
            lines.append("This CVE has been added to exploit intelligence feeds.")
        elif change.change_type == "EPSS_SPIKE":
            old_pct = f"{float(change.old_value)*100:.1f}%"
            new_pct = f"{float(change.new_value)*100:.1f}%"
            lines.append(f"📈 **EPSS jumped from {old_pct} to {new_pct}**")
            lines.append("")
            lines.append("Exploitation probability has significantly increased.")
    
    lines.append("")
    lines.append("---")
    lines.append(f"_Escalation detected by VulnRadar at {datetime.now(timezone.utc).isoformat()}_")
    
    body = "\n".join(lines)
    
    url = f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments"
    r = session.post(url, json={"body": body}, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()
```

**Modified logic in main():**

```python
for cve_id, (item, changes) in changes_by_cve.items():
    if cve_id in existing_issues:
        # Check for escalation-worthy changes
        escalation_changes = [c for c in changes if c.change_type in ("NEW_KEV", "NEW_PATCHTHIS", "EPSS_SPIKE")]
        if escalation_changes:
            issue_number = existing_issues[cve_id]  # Need to store issue numbers
            _escalate_existing_issue(session, repo, cve_id, issue_number, escalation_changes)
            print(f"Posted escalation comment on issue #{issue_number} for {cve_id}")
    else:
        # Create new issue (existing logic)
        ...
```

### Task 6: Dynamic Labels (Vendor/Product)

**File:** `notify.py`

```python
def _extract_labels(item: Dict[str, Any]) -> List[str]:
    """Extract labels from item including vendor/product."""
    labels = ["vulnradar"]
    
    if bool(item.get("is_critical")):
        labels.append("critical")
    if bool(item.get("active_threat")):
        labels.append("kev")
    if bool(item.get("in_patchthis")):
        labels.append("exploit-available")
    
    # Add vendor label (sanitize for GitHub)
    vendor = str(item.get("vendor") or "").strip().lower()
    if vendor and vendor not in ("n/a", "unknown", ""):
        vendor_label = f"vendor:{vendor.replace(' ', '_')[:20]}"
        labels.append(vendor_label)
    
    # Add product label
    product = str(item.get("product") or "").strip().lower()
    if product and product not in ("n/a", "unknown", ""):
        product_label = f"product:{product.replace(' ', '_')[:20]}"
        labels.append(product_label)
    
    return labels[:10]  # GitHub has limits
```

---

## Testing Checklist

### Saturday Tests
- [ ] ETL completes → notify.yml starts immediately (check Actions tab)
- [ ] NVD cache hit on second run (check "Cache restored" in logs)
- [ ] No infinite workflow loops

### Sunday Tests
- [ ] New issue shows "Exploit Intel" not "PatchThis"
- [ ] Discord/Slack/Teams show "PoC Available" 
- [ ] Existing issue gets escalation comment when CVE added to KEV
- [ ] Labels appear on new issues (`vendor:microsoft`, etc.)

---

## Files Changed Summary

| File | Saturday | Sunday |
|------|----------|--------|
| `.github/workflows/update.yml` | ✏️ NVD cache | |
| `.github/workflows/notify.yml` | ✏️ workflow_run trigger | |
| `etl.py` | ✏️ NVD cache support | ✏️ "Exploit Intel" label |
| `notify.py` | | ✏️ Escalation, labels, rebrand |
| `README.md` | ✏️ Badges | ✏️ Rebrand docs |

---

## Estimated Effort

| Task | Effort | Priority |
|------|--------|----------|
| Fix workflow chain | 30 min | 🔴 HIGH |
| NVD caching | 1 hour | 🟡 MEDIUM |
| Rebrand PatchThis | 1 hour | 🟠 MEDIUM |
| Issue escalation | 2 hours | 🔴 HIGH |
| Dynamic labels | 30 min | 🟢 LOW |
| Testing | 1 hour | 🔴 HIGH |

**Total: ~6-7 hours**

---

## Open Questions

1. **Reopen closed issues?** When a CVE escalates, should we reopen closed issues?
   - **Pro:** Users see it in their open issues
   - **Con:** Might annoy users who intentionally closed it
   - **Recommendation:** Comment only, don't reopen (let users decide)

2. **Label limits?** GitHub allows 100 labels per repo, 20 per issue
   - **Recommendation:** Limit to 10 labels per issue, top vendors only

3. **Escalation cooldown?** Should we avoid commenting multiple times?
   - **Recommendation:** Track `escalated_at` in state to prevent spam
