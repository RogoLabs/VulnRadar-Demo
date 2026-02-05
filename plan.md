# VulnRadar State Memory System - Implementation Plan

> **Status:** ✅ COMPLETE - All phases implemented
>
> **Goal:** Stop alert spam by tracking what's been seen/alerted, only notify on meaningful changes.
>
> **Problem:** Currently every 6-hour run re-alerts on the same CVEs via Discord/Slack/Teams.
>
> **Solution:** Persistent state file that tracks seen CVEs and their attributes, diff-based alerting.

---

## Implementation Summary

### What Was Implemented

1. **StateManager class** in `notify.py` with:
   - State file loading/saving with atomic writes
   - Schema versioning for future upgrades
   - `is_new_cve()` - Check if CVE was ever seen
   - `detect_changes()` - Find what changed since last run
   - `update_snapshot()` - Store current state
   - `mark_alerted()` - Track which channels were notified
   - `prune_old_entries()` - Clean up CVEs not seen in 180 days
   - `get_stats()` - Usage statistics

2. **Change detection** for:
   - `NEW_CVE` - Brand new CVE
   - `NEW_KEV` - Added to CISA KEV
   - `NEW_PATCHTHIS` - Added to PatchThis
   - `BECAME_CRITICAL` - Became critical priority
   - `EPSS_SPIKE` - EPSS increased by ≥30%

3. **CLI arguments**:
   - `--state` - Path to state file (default: `data/state.json`)
   - `--force` - Ignore state, alert on everything (for testing)
   - `--no-state` - Disable state tracking entirely

4. **Workflow updates**:
   - `notify.yml` now commits state file after each run
   - Uses `[skip ci]` to prevent infinite loops

5. **Tests**: 13 new tests for StateManager and Change classes

---

## Current Behavior

| Channel | Has Memory? | Behavior |
|---------|-------------|----------|
| GitHub Issues | ✅ Yes | Checks existing issues, skips duplicates |
| Discord | ❌ No | Spams same alerts every run |
| Slack | ❌ No | Spams same alerts every run |
| Teams | ❌ No | Spams same alerts every run |

---

## Proposed Architecture

### State File: `data/state.json`

```json
{
  "schema_version": 1,
  "last_run": "2026-02-05T12:00:00Z",
  "last_full_scan": "2026-02-05T06:00:00Z",
  
  "seen_cves": {
    "CVE-2024-12345": {
      "first_seen": "2026-02-01T00:00:00Z",
      "last_seen": "2026-02-05T12:00:00Z",
      "alerted_at": "2026-02-01T00:05:00Z",
      "alerted_channels": ["discord", "github_issue"],
      "snapshot": {
        "is_critical": true,
        "active_threat": true,
        "in_patchthis": true,
        "probability_score": 0.85,
        "cvss_score": 9.8
      }
    }
  },
  
  "statistics": {
    "total_alerts_sent": 150,
    "alerts_by_channel": {
      "github_issue": 50,
      "discord": 100
    }
  }
}
```

### Change Detection Logic

Only alert when:

| Trigger | Description | Alert Level |
|---------|-------------|-------------|
| **New CVE** | CVE ID not in `seen_cves` | 🔴 Alert |
| **New KEV** | `active_threat` changed `false` → `true` | 🔴 Alert |
| **New PatchThis** | `in_patchthis` changed `false` → `true` | 🔴 Alert |
| **Became Critical** | `is_critical` changed `false` → `true` | 🔴 Alert |
| **EPSS Spike** | EPSS increased by ≥0.3 (30%) | 🟡 Optional Alert |
| **CVSS Change** | CVSS increased significantly | 🟡 Optional Alert |
| **Still Critical** | Already alerted, no changes | ⚪ Skip |

### Workflow Changes

```yaml
# .github/workflows/notify.yml changes
- name: Create alerts
  run: |
    python notify.py \
      --in data/radar_data.json \
      --state data/state.json \
      --max 25 \
      --discord-max 10

- name: Commit state
  run: |
    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git add data/state.json
    git diff --quiet --cached || git commit -m "Update notification state [skip ci]"
    git push
```

---

## Implementation Tasks

### Phase 1: State Infrastructure

- [ ] **Create `StateManager` class in `notify.py`**
  ```python
  class StateManager:
      def __init__(self, path: Path):
          self.path = path
          self.data = self._load()
      
      def _load(self) -> dict
      def save(self) -> None
      def is_new_cve(self, cve_id: str) -> bool
      def has_changed(self, cve_id: str, item: dict) -> dict  # Returns changes
      def mark_alerted(self, cve_id: str, channels: List[str]) -> None
      def get_snapshot(self, cve_id: str) -> Optional[dict]
      def update_snapshot(self, cve_id: str, item: dict) -> None
  ```

- [ ] **Add `--state` CLI argument**
  - Path to state file (default: `data/state.json`)
  - Create empty state if doesn't exist

- [ ] **Add `--force` flag for testing**
  - Ignore state, alert on everything (useful for testing)

### Phase 2: Change Detection

- [ ] **Implement `detect_changes()` function**
  ```python
  def detect_changes(item: dict, previous: Optional[dict]) -> List[Change]:
      """
      Returns list of changes that warrant alerting.
      
      Change types:
        - NEW_CVE: Never seen before
        - NEW_KEV: Added to CISA KEV
        - NEW_PATCHTHIS: Added to PatchThis
        - BECAME_CRITICAL: is_critical flipped to True
        - EPSS_SPIKE: EPSS increased significantly
      """
  ```

- [ ] **Define `Change` dataclass**
  ```python
  @dataclass
  class Change:
      cve_id: str
      change_type: str  # NEW_CVE, NEW_KEV, etc.
      old_value: Any
      new_value: Any
      severity: str  # "critical", "high", "medium"
  ```

### Phase 3: Notification Updates

- [ ] **Filter alerts by changes**
  - Only send Discord/Slack/Teams for items with changes
  - Include change reason in alert message

- [ ] **Enhanced alert messages**
  ```
  🆕 NEW: CVE-2024-12345
  vs
  ⚠️ NOW IN KEV: CVE-2024-12345 (was already on watchlist)
  vs  
  📈 EPSS SPIKE: CVE-2024-12345 (0.15 → 0.75)
  ```

- [ ] **Daily summary changes**
  - "3 new CVEs today, 1 added to KEV, 2 EPSS spikes"
  - vs "47 total CVEs matching watchlist" (current)

### Phase 4: Workflow Integration

- [ ] **Update `notify.yml` to commit state**
  - Commit `data/state.json` after each run
  - Use `[skip ci]` to prevent workflow loops

- [ ] **Handle merge conflicts**
  - State file could conflict if multiple runs overlap
  - Use atomic updates or lock file

- [ ] **Add state cleanup command**
  - `python notify.py --reset-state` to start fresh
  - `python notify.py --prune-state --days 90` to remove old entries

### Phase 5: Reporting

- [ ] **Add change history to markdown report**
  ```markdown
  ## Recent Changes (Last 7 Days)
  
  | Date | CVE | Change |
  |------|-----|--------|
  | Feb 5 | CVE-2024-12345 | Added to CISA KEV |
  | Feb 4 | CVE-2024-11111 | New (EPSS: 0.45) |
  ```

- [ ] **Statistics tracking**
  - Total alerts sent all-time
  - Alerts by channel
  - Most frequently updated CVEs

---

## Configuration Options

Add to CLI or future `config.yaml`:

```yaml
state:
  file: data/state.json
  prune_after_days: 180  # Remove CVEs not seen in 6 months

alerts:
  # What triggers an alert
  triggers:
    new_cve: true
    new_kev: true
    new_patchthis: true
    became_critical: true
    epss_spike:
      enabled: true
      threshold: 0.3  # 30% increase
    cvss_change:
      enabled: false
      threshold: 2.0  # Points increase
  
  # Cooldown to prevent re-alerting
  cooldown_hours: 24  # Don't re-alert same CVE within 24h even if changes
```

---

## Testing Plan

- [ ] **Unit tests for StateManager**
  - Load/save roundtrip
  - Empty state initialization
  - Concurrent access handling

- [ ] **Unit tests for change detection**
  - New CVE detection
  - KEV addition detection
  - EPSS spike detection
  - No-change detection (should not alert)

- [ ] **Integration test**
  - Run notify twice with same data → no alerts second time
  - Run notify with new CVE added → alerts only for new CVE
  - Run notify with KEV addition → alerts for KEV change

---

## Migration Path

1. **First run with state**: Creates `data/state.json`, marks all current CVEs as "seen but not alerted via new system"
2. **Subsequent runs**: Only alerts on genuine changes
3. **Optional**: `--backfill` flag to mark all current CVEs as already alerted (for existing deployments)

---

## Estimated Effort

| Phase | Effort | Priority |
|-------|--------|----------|
| Phase 1: State Infrastructure | 2-3 hours | 🔴 High |
| Phase 2: Change Detection | 2 hours | 🔴 High |
| Phase 3: Notification Updates | 2 hours | 🔴 High |
| Phase 4: Workflow Integration | 1 hour | 🔴 High |
| Phase 5: Reporting | 1-2 hours | 🟡 Medium |
| Testing | 2 hours | 🔴 High |

**Total: ~10-12 hours**

---

## Open Questions

1. **State storage location**: 
   - `data/state.json` in repo (committed by workflow)?
   - GitHub Actions cache (ephemeral, lost on cache eviction)?
   - External storage (adds complexity)?
   
   **Recommendation**: JSON file in repo, committed by workflow

2. **What about removed CVEs?**
   - CVE falls off watchlist (vendor removed)
   - CVE no longer in scan window (too old)
   - Should we alert on "CVE no longer critical"?
   
   **Recommendation**: Don't alert on removals, just update state silently

3. **Multiple forks with same state?**
   - Each fork maintains its own state
   - No cross-fork coordination needed
   
   **Recommendation**: This is fine, each fork is independent

---

## Success Criteria

- [ ] Running notify twice in a row produces alerts only on first run
- [ ] New CVE appearing triggers alert
- [ ] CVE added to KEV triggers "Now in KEV" alert
- [ ] State persists across workflow runs
- [ ] Daily summary shows "X new, Y changed" instead of "Z total"
