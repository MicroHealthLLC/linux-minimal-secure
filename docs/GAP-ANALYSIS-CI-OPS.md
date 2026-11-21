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
| Δ3 | Nothing in CI proved the progress lines print (P4–P6) | Every long step ends with a `completed in …` closing line (a fast scan can finish inside the interval: 6 s on the GitHub jammy runner), and an assertion requires the OpenSCAP closing line with n/N rules |
| Δ4 | README didn't explain the progress output or its accuracy | New "Progress output" section |
| Δ5 | Upstream `6459cbe` (AIDE bulk excludes) landed while this work was in progress | Rebased. The AIDE size estimate subtracts the same excluded paths |
| Δ6 | `apt-config dump --format` is missing from older apt (jammy) | Effective-value checks use `apt-config shell`, which every apt has |

| Δ7 | Ubuntu images ship `docker-disable-periodic-update` (`APT::Periodic::Enable "0"`), which sorted after `99zz-…` and turned updates off. The new fatal check caught it on all three Ubuntu targets | Overrides that set 0/false are commented out (backed up first), and the file is now `zz-harden-auto-upgrades`. Assertion added |
| Δ8 | `/etc/logrotate.d/harden-and-audit` was rejected on Ubuntu (`parent directory has insecure permissions`; `/var/log` is `root:syslog 0775`) when evaluated without the global `su root adm` | Added `su root root` to the stanza |

## Known limits (accepted)

* The AIDE percentage is a cautious estimate: AIDE's other exclusions make the real total smaller, so it reads low and the time left errs long. This is stated in the README and in the log line before AIDE starts.
* If live logs alone exceed `LOG_MAX_TOTAL`, the budget can't prune them. It logs `STILL OVER BUDGET` to syslog (shipped by tuericore) and hourly rotation shrinks them at the next run.

## CI results

| Run | Commit | Result |
|---|---|---|
| 44939707227 | `b0de840` | shellcheck failed (Δ1) |
| 44939881952 | `0bc6b28` | Ubuntu ×3 failed (Δ7). Debian jobs cancelled by a later push |
| 44940680148, 44940930284, 44941001387 | `995e96a`, `3974cba`, `910c34a` | cancelled: a parallel session pushed AIDE scope commits (`3974cba`, `910c34a`), which were adopted |
| 44942277328 | `7c70f2e` | 5/6 green. Ubuntu 22.04: timing-dependent progress assertion (scan took 6 s, interval 10 s) |
| **44943941339** | **`991cb1d`** | **all green**: shellcheck, Debian 12, Debian 13, Ubuntu 22.04, 24.04, 26.04 |

Released as **v1.2.0** (VERSION bump; v1.1.0 was already published and the release workflow never overwrites one).
