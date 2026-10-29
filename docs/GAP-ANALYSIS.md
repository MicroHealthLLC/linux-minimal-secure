# Gap analysis: delivered vs. plan

Compared against [PLAN.md](PLAN.md) and the original requirement text. Each delta found was fixed and re-verified in CI. Nothing is marked delivered without a CI assertion or SCAP result backing it.

## 1. Deliverables

| ID | Planned | Status | Evidence |
|---|---|---|---|
| D1 | `harden-and-audit.sh` | ✅ Delivered | ShellCheck clean; runs twice without error on Debian 12 and 13 (idempotence) |
| D2 | systemd test image (12/13) | ✅ | `tests/Dockerfile`, `tests/container-init.sh` |
| D3 | `tests/run-ci.sh` | ✅ | Builds, boots, hardens, asserts, re-runs, gates, and exports reports. Privileged on GitHub, restricted locally |
| D4 | `tests/assertions.sh` | ✅ | 100+ functional checks, including the anti-lockout SSH key login and root refusal |
| D5 | `ci.yml` | ✅ | lint → Debian 12/13 matrix → artifacts + job-summary score table |
| D6 | `release.yml` | ✅ | `main` → full CI → GitHub Release `v<VERSION>` + `.sha256` + reports |
| D7 | README, EXCEPTIONS, GAP-ANALYSIS | ✅ | `README.md`, `docs/` |
| D8 | `integration` default + `main` release line | ✅ | Set through the GitHub API |

## 2. Requirement traceability

| Req | Item | Status | Verified by |
|---|---|---|---|
| R0.1 | root, `set -Eeuo pipefail`, noninteractive, named failing step | ✅ | ERR trap reports step, line and command |
| R0.2 | Debian 12/13 only | ✅ | `preflight_os` refuses anything else. "Headless" is enforced by the purge plus `multi-user.target`, not by refusing to run |
| R0.3 | anti-lockout preflight, SSH port detection, IPv6 RA safety | ✅ | assertion `ANTI-LOCKOUT: sudo admin can still SSH in with a key` |
| R0.4 | log + backups | ✅ (changed, see Δ3) | `/var/log/harden-and-audit.log`, `/var/backups/harden-and-audit/` |
| R1.1 | no recommends/suggests | ✅ | `apt-config dump` assertion + `apt_disable_weak_dependencies` pass |
| R1.2 | purge GUI/X11 (dependency-aware) + legacy daemons | ✅ | xserver/xterm/xauth/x11-utils gone, libavcodec kept, telnet/rpcbind gone |
| R2.1 | official stable / -updates / -security | ✅ | deb822 `debian.sources` assertions |
| R2.2 | base stack | ✅ | package assertions |
| R2.3 | daily unattended security upgrades | ✅ | `apt-config` + `apt-daily-upgrade.timer` assertions |
| R3 | auditd 20 / ROTATE / SYSLOG; never SUSPEND/SINGLE/HALT | ✅ | 7 auditd assertions; the script itself refuses forbidden values |
| R3.2 | full audit rule set, immutable | ✅ | `augenrules --check`, `-e 2`, `-f 1`, privileged rules |
| R4.1 | `fips=1` in GRUB + `update-grub` | ✅ (see Δ1) | assertions on `GRUB_CMDLINE_LINUX_DEFAULT` and `GRUB_CMDLINE_LINUX` |
| R4.2 | OpenSSL FIPS provider alongside default | ✅ (see Δ2) | FIPS 3.1.2 + default both `active`, SHA-2 via FIPS, MD5 refused under `fips=yes`, curl HTTPS works |
| R5.1 | passwd/group/shadow/gshadow ownership and modes | ✅ | stat assertions + SCAP `file_*` rules pass |
| R5.2 | sysctl network hardening | ✅ | file assertions; runtime values asserted in privileged CI |
| R5.3 | SSH lockdown | ✅ | `sshd -T` assertions (root, X11, MaxAuthTries, ClientAlive, FIPS ciphers/MACs) |
| R5.4 | UFW default deny inbound, SSH allowed, forced enable | ✅ | UFW assertions (active state asserted in privileged CI) |
| R5.5 | PAM, aging, banners, modules, mounts, logging, AIDE, AppArmor, fail2ban … | ✅ | SCAP rule results + assertions |
| R6.1 | CUDA build prerequisites | ✅ | libc6, libc6-dev, gcc, make, dkms, linux-headers-amd64, build-essential assertions |
| R6.2 | coturn/media libraries, no coturn, no X11 | ✅ | library assertions, `coturn` absent, no X server |
| R7.1 | libopenscap8 / openscap-utils / ssg-debian | ✅ (see Δ4) | package assertions |
| R7.2 | XML + HTML reports at the required paths | ✅ | `/var/log/scap-results.xml`, `/var/log/scap-report.html` assertions |
| R7.3 | pass/fail/score summary, ≥ 90% gate | ✅ | `/var/log/scap-summary.txt`; CI gate |
| R7.4 | recurring scan | ✅ | `scap-audit.timer` enabled assertion |

## 3. Deltas found and fixed

| # | Delta | Root cause | Fix |
|---|---|---|---|
| Δ1 | `fips=1` was only in `GRUB_CMDLINE_LINUX`; the requirement says the *default* command-line string | Interpretation | `fips=1` is now ensured in **both** `GRUB_CMDLINE_LINUX_DEFAULT` and `GRUB_CMDLINE_LINUX` (idempotent, no duplicates), with an assertion for each |
| Δ2 | On Debian 13, TLS broke (`curl: method not supported`) once FIPS was active | OpenSSL 3.5's ML-KEM fetched SHAKE from the older 3.1.2 FIPS module, which has no `squeeze` | Default provider listed before FIPS, system TLS groups limited to FIPS NIST/FFDHE groups, **loopback TLS handshake added to the pre-activation validation**, and a curl HTTPS assertion |
| Δ3 | `*.pre-harden` backups inside `logrotate.d`/`grub.d` were loaded or executed (a GRUB entry without `--unrestricted` could have locked boots) | Backups stored next to originals | Backups moved to `/var/backups/harden-and-audit/<path>`, plus a regression assertion |
| Δ4 | `libopenscap8` does not exist on Debian 12/13; `ssg-debian` on 12 has no Debian 12 content | Packaging | Install it where packaged, otherwise the scanner's own library. Scan with the SHA-512-pinned SSG 0.1.82, with packaged content as a fallback |
| Δ5 | `fipsinstall -verify` cannot verify 3.1.2's self-test-on-load config | FIPS 140-3 design | Verification by loading the module (integrity + KATs) in isolation |
| Δ6 | `sshd -t` failed before ssh.service had ever run | Missing `/run/sshd` | `sshd_test` creates the privilege-separation directory |
| Δ7 | `producer \| grep -q` under `pipefail` gave false failures | SIGPIPE | `qgrep` helper (reads all input) |
| Δ8 | ERR trap fired inside process substitutions | `set -E` inheritance | Trap reports only from the main shell |
| Δ9 | `findmnt -r -l` rejected by util-linux 2.41 (Debian 13), silently skipping setuid discovery | Option conflict | `findmnt -rn` |
| Δ11 | **UFW silently re-disabled martian logging at every start** (found in privileged CI) | `/etc/ufw/sysctl.conf` ships `log_martians=0` and is re-applied by UFW | UFW's sysctl file is aligned (`log_martians=1`), with assertions on the file and on the runtime value after UFW starts |
| Δ12 | `ufw.service` unit stayed inactive after `ufw --force enable` | `ufw enable` loads rules without starting the oneshot unit | `systemctl start ufw.service`, plus an assertion |
| Δ13 | `FAIL_DELAY` made every shadow tool print "configuration error" | Not a Debian `login.defs` key (Debian uses `pam_faildelay`) | Key removed, plus an assertion that `login.defs` has no unknown items |
| Δ14 | CI scored runner-owned files as "unowned" | Repo was bind-mounted with the runner's UID | Sources are copied into the test host as root |
| Δ15 | AIDE audit-tool rules were in `aide.conf.d`, and `aidecheck.service` was "static" | Scanner reads only `aide.conf`; the unit had no `[Install]` | Lines in `aide.conf` with the exact attribute set (validated with `aide --config-check`); the unit is enabled |
| Δ16 | First `main` push: the release workflow failed before any job started | In a called workflow `github.workflow` is the caller's name, so ci.yml shared release.yml's concurrency group (deadlock) | `ci-` prefix on ci.yml's group; the release run then executed the full CI and published |
| Δ10 | SCAP format mismatches (faillock order, `declare -xr TMOUT`, bashrc umask, journald main file, rsyslog FileCreateMode, audit rule shapes, Debian 13 extras) | Exact OVAL expectations | Each aligned to the OVAL definition. CIS L2 went from 86.5% to ≥ 91% |

## 4. Remaining known gaps (accepted, documented)

See [EXCEPTIONS.md](EXCEPTIONS.md): owner-mandated auditd actions, UFW-vs-nftables and timesyncd-vs-chrony profile conflicts, site-specific remote logging, install-time partitions, and CI-container-only limits. None of them is hidden by tailoring; all count against the score.

## 5. Results

GitHub Actions, privileged systemd container (authoritative), after the second (idempotence) run:

| Profile | Debian 12 | Debian 13 |
|---|---|---|
| **CIS Level 2 Server: pass rate (gate ≥ 90%)** | **94.46%** (426 pass / 25 fail) | **95.22%** (458 pass / 23 fail) |
| CIS Level 2 Server: XCCDF default score | 75.36 | 76.25 |
| ANSSI BP-028 High (informational) | 74.03% | 74.03% |
| Functional assertions | 120 / 120 | 120 / 120 |

Every remaining failure is listed with its reason in [EXCEPTIONS.md](EXCEPTIONS.md): 4 owner-mandated auditd actions, 4 install-time partitions, 3–5 profile-internal conflicts, 3–4 site-specific remote-logging settings, 2 SSG content defects, and the CI-container-only items, which pass on real hosts. On a physical or virtual host the container-only items (GRUB arguments, auditd, timesyncd, AppArmor, privileged-command count) also pass, so the expected host score is about 97–98%.

The XCCDF *default* score is lower than the pass rate because it is weighted hierarchically by rule groups. The pass rate (pass ÷ (pass + fail + error + unknown)) is the conventional "compliance percentage" and is what the gate enforces. Both are reported in `/var/log/scap-summary.txt` and the HTML report.
