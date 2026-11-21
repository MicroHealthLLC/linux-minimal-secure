# Gap analysis: delivered vs. PLAN-CI-OPS (2026-11-21)

## Plan items

| ID | Planned | Delivered | Status |
|---|---|---|---|
| P1 | AIDE assertion accepts `[x]` and `[X]` | `grep -qi '^\[x\]'` in `tests/assertions.sh` (checked against AIDE 0.18.3 and 0.19.1 output) | done |
| P2 | Keep upstream `nice`/`ionice` | Moved into `aide_init_quiet` | done |
| P3 | `[STEP n/N]` + run time | `step()` and `fmt_dur`. N comes from the script's own step headers. CI asserts the final step number equals N | done |
| P4 | Heartbeat during long steps | `run_with_progress` (background command, status line every `PROGRESS_INTERVAL`) | done |
| P5 | AIDE %, time left, current file, log file, stdin closed | `aide_estimate_total` (disk in use minus the bulk excludes, each `du` limited to 20 s), `aide_progress` (`/proc/PID/io` rchar plus the open file), `/var/log/harden-and-audit-aideinit.log`, `</dev/null` | done |
| P6 | OpenSCAP n/N rules, %, time left | `scap_rule_count` (selected rules in the resolved profile: 507 for CIS L2 on 24.04, matching the 507 results oscap reports), `scap_progress`, `stdbuf -oL` | done |
| P7 | 14 rotated copies, 100M, hourly, own logs | `logrotate.conf` edits, `logrotate.timer.d/60-harden.conf`, `/etc/logrotate.d/harden-and-audit` | done |
| P8 | `/var/log` budget | `/usr/local/sbin/harden-log-budget` run by `ExecStartPost` after each logrotate and once during hardening. Tested against a fake log tree (oldest first, stops under the cap, live logs and journal kept) and by a CI assertion | done |
| P9 | Mandatory automatic updates | Unmask apt units, `enable --now`, `zz-harden-auto-upgrades`, `#clear` the blacklist, effective `APT::Periodic::*` check (fatal), timer `is-active` check (fatal on hosts). CI: effective config, timers active and not masked, no blacklist, `unattended-upgrade --dry-run` | done |
| P10 | Docs | README (config table, Updates row, logrotate row, Progress section), EXCEPTIONS | done |

## Deltas found and fixed

| # | Delta | Fix |
|---|---|---|
| Δ1 | First push failed shellcheck SC1010: a local variable named `done` | Renamed to `ndone`. CI's exact shellcheck command (`v0.11.0 -x --severity=warning`) now runs locally before every push |
| Δ2 | `PROGRESS_INTERVAL=0` or a non-number caused a division-by-zero in the progress loop | Checked at startup (exit 64) |
| Δ3 | Nothing in CI proved the progress lines print (P4–P6) | CI runs with `PROGRESS_INTERVAL=10`, and an assertion requires an `OpenSCAP cis_level2_server: … n/N rules (x%)` line |
| Δ4 | README didn't explain the progress output or its accuracy | New "Progress output" section |
| Δ5 | Upstream `6459cbe` (AIDE bulk excludes) landed while this work was in progress | Rebased. The AIDE size estimate subtracts the same excluded paths |
| Δ6 | `apt-config dump --format` is missing from older apt (jammy) | Effective-value checks use `apt-config shell`, which every apt has |

## Known limits (accepted)

* The AIDE percentage is a cautious estimate: AIDE's other exclusions make the real total smaller, so it reads low and the time left errs long. This is stated in the README and in the log line before AIDE starts.
* If live logs alone exceed `LOG_MAX_TOTAL`, the budget can't prune them. It logs `STILL OVER BUDGET` to syslog (shipped by tuericore) and hourly rotation shrinks them at the next run.

## CI results

Filled in once GitHub CI on `integration` finishes.
