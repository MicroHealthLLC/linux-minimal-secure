# Gap analysis: Ubuntu support delivered vs. plan

Compared against [PLAN-UBUNTU.md](PLAN-UBUNTU.md). Every delta found was fixed and re-verified. Nothing is marked delivered without a CI assertion, SCAP result, or recorded unit test behind it.

## 1. Deliverables

| ID | Planned | Status | Evidence |
|---|---|---|---|
| UD1 | `harden-and-audit.sh` 1.1.0 for Debian 12/13 + Ubuntu 22.04/24.04/26.04 | ✅ | ShellCheck clean; all five targets harden, pass assertions, re-run idempotently and pass the gate in CI |
| UD2 | Generalized `tests/Dockerfile` | ✅ | `BASE_IMAGE` arg; Ubuntu image with `linux-image-virtual`, GRUB, seeded GUI/legacy packages, a cloud-style GRUB drop-in |
| UD3 | `tests/run-ci.sh <distro> <version>` | ✅ | Backward compatible (`run-ci.sh 12`); per-OS informational profile; summary names the OS and content note |
| UD4 | Distro-aware assertions | ✅ | Repos, update origins, boot-time sysctl order, sudo provider, telemetry, headers, soname patterns, OpenSCAP packages, FIPS-only context, effective GRUB command line |
| UD5 | `ci.yml` 5-target matrix | ✅ | debian 12, 13; ubuntu 22.04, 24.04, 26.04 |
| UD6 | `release.yml` covers every OS | ✅ (exercised on the next merge to `main`) | Artifact pattern `scap-*`, ANSSI and STIG reports, notes cover both families |
| UD7 | README, EXCEPTIONS §8, plan, this document | ✅ | `README.md`, `docs/` |

## 2. Plan findings (U1–U24) → implementation

| # | Item | Status | Verified by |
|---|---|---|---|
| U1 | OS abstraction, Ubuntu ≥ 22.04 | ✅ | All three Ubuntu releases run; `os:` line in the summary |
| U2 | `ubuntu.sources`, mirror kept, third parties untouched | ✅ | Assertions (`-security`, `-updates`, components, no duplicate one-line entries); unit test with a PPA, Docker, Microsoft and cdrom entries (Δ3) |
| U3 | Ubuntu security/ESM origins | ✅ | `apt-config dump` assertion |
| U4 | Per-release OpenSCAP packages | ✅ | Package assertions (`libopenscap8` on 22.04; scanner/utils/`ssg-debderived` on 24.04+) |
| U5 | 26.04 retargeted content | ✅ | 26.04 scores the 24.04 CIS L2 benchmark; `content note:` assertion |
| U6 | STIG informational | ✅ | `scap-summary-stig.txt` in CI artifacts (22.04, 24.04; 26.04 evaluates the 24.04 STIG) |
| U7 | sudo-rs → classic sudo | ✅ | 26.04 assertion: `/etc/alternatives/sudo` → `sudo.ws`; logfile and I/O logging in `60-harden` |
| U8 | uutils coreutils | ✅ | The whole 26.04 run uses the image's default uutils |
| U9 | `ausyscall`-gated syscalls | ✅ | `augenrules --check` assertion on every OS; `fchmodat2` emitted only on 26.04/Debian 13 |
| U10 | sysctl conflicts | ✅ | Boot-time order assertions for `rp_filter`, `kernel.sysrq`, `fs.protected_fifos` on every OS |
| U11 | `ssh.socket` port detection | ✅ | Parser checked against real `systemctl show -p Listen` output (22) and a synthetic 2222 listener |
| U12 | Flavour headers, dracut | ✅ / ⚠ | `linux-headers-virtual` assertion. The dracut branch is not exercised (CI images use initramfs-tools) |
| U13 | Soname regex fallback | ✅ | Pattern assertions for x264, x265, vpx, dav1d, theora on every OS |
| U14 | Telemetry | ✅ | apport, whoopsie, motd-news assertions |
| U15 | Ubuntu Pro FIPS kept | ⚠ Not exercised | Needs a Pro subscription. The code path only skips steps, it never changes a Pro host |
| U16 | GRUB drop-in override, ZFS, EFI path | ✅ | Cloud-style drop-in in the CI image + effective command line assertion (Δ6); `10_linux_zfs` patched in the 24.04 container |
| U17 | AppArmor complain for vendor-disabled profiles | ✅ (code path) | `aa-complain` invoked; profile loading itself needs a real kernel (EXCEPTIONS §5) |
| U18 | `/var/log` ownership untouched | ✅ | rsyslog keeps writing; no new log-permission failures |
| U19 | CI generalized | ✅ | Matrix, artifacts, job summary |
| U20–U24 | Found during execution | ✅ | See [PLAN-UBUNTU.md §1.1](PLAN-UBUNTU.md) and Δ below |

## 3. Deltas found and fixed

| # | Delta | Root cause | Fix |
|---|---|---|---|
| Δ1 | Heredoc nesting broke the first scripted edit | An inner `EOF` closed the outer heredoc | Edits made through files and the Edit tool; nothing on the host was changed (verified) |
| Δ2 | Groups like `~^libx264-[0-9]+$` would silently vanish | Unquoted expansion + `nullglob` treats them as globs | Groups are split with `read -a` (no pathname expansion) |
| Δ3 | The first `sources.list` rewrite also disabled a Docker repository | URI matched on the substring `ubuntu` | Only `*.ubuntu.com` or the detected mirror are disabled; detection requires an archive path with `main`; PPAs excluded |
| Δ4 | Ubuntu 24.04 at 90.79%, 26.04 at 80.26% in the first local run | Ubuntu CIS content differs from Debian (U20–U22); audit 4.1 unit layout (U23) | Implemented per OVAL definition; 24.04 → 93.20%, 26.04 → 93.20% locally |
| Δ5 | 22.04 "MD5 refused under fips=yes" failed | OpenSSL 3.0.2 `dgst` ignores `-propquery`; the FIPS module was fine | Assertion uses a FIPS-only provider context (proves enforcement on every OpenSSL version) |
| Δ6 | The GRUB drop-in path (U16) was implemented but untested | The CI image had no cloud drop-in | Image now carries `50-cloudimg-settings.cfg`; effective command-line assertion on every OS; only the overridden variable is re-appended |
| Δ7 | Harness false failures | `apt-cache search` matches *Provides* (seeded `libavcodec-extra*`); `grep -q installed` matched `not-installed`; `grep -q` + `pipefail` SIGPIPE | Exact-name filter; `grep -qx`; full-read `grep >/dev/null` |
| Δ8 | 22.04 AIDE assertion failed | jammy's aide-common ships a cron job, not `dailyaidecheck.timer` | Assertion follows the timer that exists; the script already fell back to its own units |
| Δ9 | Cached retargeted datastream could go stale | Regenerated only when the source was newer | Regenerated on every scan (sub-second) |
| Δ10 | **First GitHub run: Debian 12 and 13 jobs failed** (scores unchanged at 94.46% / 95.22%) | The new AIDE assertion took the vendor-timer branch on Debian, whose aide-common also ships `dailyaidecheck.timer`; the script uses it on Ubuntu only | Assertion scoped to Ubuntu |
| Δ11 | `ufw_rules_for_open_ports` failed on every Ubuntu release | **Real defect:** rpcbind's socket kept port 111 open after the purge (package stop suppressed by `policy-rc.d`; `disable_service` skipped units without a unit file) | `disable_service` stops still-active orphaned units; CI image without `policy-rc.d`; port-111 assertion (applies to Debian too) |
| Δ12 | `service_timesyncd_configured` failed on 24.04/26.04; the first fix then broke it on 22.04 (CI run 2: 94.17% → 93.95%) | 24.04 approves `0-3.pool.ntp.org`; 22.04 approves the NIST list and matches only the **first** server of a line | `NTP=` pool servers, `FallbackNTP=time.nist.gov ntp.ubuntu.com` (configured fallback first) |

## 4. Remaining known gaps (accepted, documented)

* **U15 Ubuntu Pro FIPS** and the **dracut** branch are untested in CI (no Pro subscription; CI images use initramfs-tools).
* **Ubuntu 26.04** is scored with retargeted 24.04 content until ComplianceAsCode ships native 26.04 profiles.
* Rule-level exceptions are in [EXCEPTIONS.md §8](EXCEPTIONS.md#8-ubuntu).

## 5. Results

GitHub Actions, privileged systemd container (authoritative), run 44821211057, after the second (idempotence) run:

| Profile | Debian 12 | Debian 13 | Ubuntu 22.04 | Ubuntu 24.04 | Ubuntu 26.04 |
|---|---|---|---|---|---|
| **CIS L2 Server pass rate (gate ≥ 90%)** | **94.46%** (426/25) | **95.22%** (458/23) | **94.17%** (420/22) | **95.39%** (435/21) | **95.39%** (435/21)¹ |
| CIS L2 Server XCCDF score | 75.36 | 76.25 | 76.05 | 77.86 | 77.86 |
| Informational profile | ANSSI High 74.31% | ANSSI High 74.31% | STIG 71.77% | STIG 72.86% | STIG 71.90%¹ |
| Functional assertions (each run) | 133/133 | 133/133 | 138/138 | 141/141 | 143/143 |

¹ Ubuntu 24.04 content retargeted to 26.04 (no native SSG content exists).

**Debian non-regression:** both Debian scores are identical to the 1.0.0 baseline (94.46% / 95.22%); the Debian assertion set grew from 120 to 133 (boot-time sysctl order, FIPS-only context, effective GRUB command line, sudo logging, port 111).

**CI history for this change:** run 44813990055 failed on Debian 12/13 (Δ10, an assertion bug; scores unchanged); run 44818566714 green with a 22.04 regression of one rule (Δ12); run 44821211057 green on every target.
