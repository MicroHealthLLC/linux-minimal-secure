# Plan: CI fix + operational hardening (2026-11-21)

## 1. Analysis

### 1.1 GitHub CI failure (run 44936017656, commit `6459cbe`)

| Job | Result |
|---|---|
| shellcheck, debian 12, ubuntu 22.04, ubuntu 24.04 | pass |
| debian 13, ubuntu 26.04 | **fail**: 1 assertion, `AIDE still watches system binaries` |

**Source.** `6459cbe` added `aide -p f:/usr/bin/ls | grep -q '^\[X\]'`. AIDE 0.18
(bookworm, jammy, noble) prints `[X] f '/usr/bin/ls': selective rule...`. AIDE 0.19
(trixie, resolute) prints `[x] f:/usr/bin/ls: selective rule...`, with a lowercase marker
and a different path format. Verified against `debian:bookworm` (AIDE 0.18.3) and
`debian:trixie` (AIDE 0.19.1).

**Impact.** Only the test is affected. The two "negative rule" assertions pass on every
target, the SCAP gates pass (95.2% / 95.4%), and the hardening itself is correct.
`integration` is red, though, which blocks the release flow.

### 1.2 Operational problems reported from a production run

| # | Problem | Source | Impact |
|---|---|---|---|
| O1 | No progress output for more than an hour | `aideinit` output sent to `/dev/null`, oscap redirected to a file, no heartbeat | Operators can't tell a hang from slow work, and may abort a good run |
| O2 | `/var/log` grew to 24 GB | logrotate ran **daily** (so `maxsize` is only checked once a day), 30 generations × 200M per log, and nothing limited the total | Disk fills and the server stops. AIDE also checksums every byte of it |
| O3 | Automatic security updates could be silently off | `systemctl enable … \|\| true` on timers that may be **masked**, no check of the effective `APT::Periodic::*` values, later `apt.conf.d` files can override them | Hosts go unpatched. Owner policy: automatic updates are **mandatory** |

## 2. Plan

| ID | Change | Files |
|---|---|---|
| P1 | AIDE assertion matches `[x]` and `[X]` (case-insensitive) | `tests/assertions.sh` |
| P2 | Keep upstream `nice`/`ionice` for `aideinit` when merging with the progress wrapper | `harden-and-audit.sh` |
| P3 | Step counter `[STEP n/N]` plus total run time on every step header. N is computed from the script, and CI asserts the final step equals N | script, assertions |
| P4 | `run_with_progress`: a line every `PROGRESS_INTERVAL` (60s) during long steps | script |
| P5 | AIDE progress: % of estimated bytes (disk in use minus the bulk excludes), data read (`/proc/PID/io`), time left, current file. Output goes to `/var/log/harden-and-audit-aideinit.log`, stdin is `/dev/null` | script |
| P6 | OpenSCAP progress: rules done / rules in profile, %, time left, last rule (`stdbuf -oL`) | script |
| P7 | logrotate: `rotate 14`, `maxsize 100M`, **hourly** timer drop-in, and the script's own logs get a logrotate entry | script |
| P8 | `/var/log` budget: `harden-log-budget` runs after every logrotate and prunes the oldest **rotated** archives while usage is over `LOG_MAX_TOTAL` (4G) or disk free is under `LOG_MIN_FREE_PCT` (15%). It never touches live logs or the journal, and also runs once during hardening | script, assertions |
| P9 | Mandatory automatic updates: unmask the apt units, `enable --now`, add a last-read `99zz-harden-auto-upgrades`, `#clear` the package blacklist, verify the effective config and the active timers (fatal on hosts) | script, assertions (`unattended-upgrade --dry-run`) |
| P10 | Docs: README config table and controls, EXCEPTIONS compensating controls | docs |

**Acceptance.** All 6 GitHub CI jobs (shellcheck + 5 distro targets) green on
`origin/integration`, and no new assertion failures.
