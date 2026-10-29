# Implementation Plan — `harden-and-audit.sh`

Status: approved for execution (autonomous run, 2026-10-29).
Targets: Debian 12 (bookworm) and Debian 13 (trixie), amd64, headless.

## 1. Analysis summary (source & impact)

The repository was empty (no commits locally or on `origin`). This is a
greenfield build. These findings from probing real Debian 12/13 images drive the design:

| # | Finding | Impact on design |
|---|---------|------------------|
| A1 | `libopenscap8` does not exist on Debian 12 or 13 (library is `libopenscap25`/`t64`, pulled in by `openscap-scanner`). | Install `libopenscap8` only if apt has a candidate. Otherwise install the scanner, which brings the right library. |
| A2 | Debian 12's `ssg-debian` (0.1.65) ships **no Debian 12 datastream** (only 10/11). Debian 13's (0.1.76) predates the 0.1.82 CIS content. | Install `ssg-debian` as required, then scan with the pinned upstream ComplianceAsCode **0.1.82** datastream (SHA-512 verified). Fall back to the packaged content if offline. |
| A3 | DISA publishes **no STIG for Debian**. Upstream SSG ships `cis_level2_server` and `anssi_bp28_high` for Debian 12/13. | The gate is **CIS Debian Level 2 Server ≥ 90%** (the profile the prompt names). ANSSI BP-028 High is also scanned and reported, but not gated. STIG-derived controls (DoD banner, FIPS crypto, audit rules, faillock) are implemented natively. |
| A4 | Debian 12 ships **no OpenSSL FIPS provider**. Debian 13's `openssl-provider-fips` is a distro build, **not** CMVP-validated. OpenSSL's only FIPS 140-3 validated provider is **3.1.2 (cert #4985)**. 140-2 certs (3.0.x) went historical in Sept 2026. | Build the OpenSSL **3.1.2** FIPS provider from the pinned, SHA-256-verified tarball per its Security Policy (`enable-fips`, `install_fips`, `fipsinstall`). Install it into `/opt` so it never collides with dpkg, and load it alongside the default provider. |
| A5 | With `config_diagnostics = 1` in `openssl.cnf`, a broken provider include makes every OpenSSL consumer fail (sshd included), which is a **lockout**. | Validate the candidate `openssl.cnf` through `OPENSSL_CONF=<tmp>` (`openssl list -providers`, `sshd -t`) before installing it. Roll back automatically on failure. |
| A6 | `libavcodec*` hard-depends on X11 client libraries (`libx11-6`, `libva-x11-2`, …). | GUI purge is **dependency-aware**: a package is purged only if removing it takes nothing outside the graphical set. Media support uses X-free codec libraries. ffmpeg's libav* are not installed. |
| A7 | SSG treats a host as a container when `/.dockerenv` or `/run/.containerenv` exists, and gates ~150 rules on the `linux-base` package (`system_with_kernel`). | The CI image boots real systemd (PID 1), installs a kernel and GRUB like a netinst server, and removes the container markers. That way the full "machine" ruleset is scored, not a fake 96%. |
| A8 | `sshd_use_strong_ciphers` reads only `/etc/ssh/sshd_config` (not `sshd_config.d`). Debian puts `Include sshd_config.d/*.conf` first. | The SSH policy is written as a managed block at the **top** of `sshd_config` (first match wins) and validated with `sshd -t` before reload. |
| A9 | CIS L2 auditd values (`admin_space_left_action=halt`, `disk_full_action=halt\|single`, `space_left_action=email`, `max_log_file_action=keep_logs`) contradict the owner's no-lockout rule. `max_log_file` is checked as `>= 6`. | Implement the owner's policy exactly (`20`/`ROTATE`/`SYSLOG`). The four rules fail **by design** and are documented in `docs/EXCEPTIONS.md`. |
| A10 | Debian 13 renamed libraries (`t64` suffixes, new sonames such as `libvpx9`, `libx265-215`, `libdav1d7`, `libhiredis1.1.0`). | Library sets are resolved at runtime with "first available candidate" groups. Nothing is hard-coded per release. |

## 2. Deliverables

| ID | Deliverable |
|----|-------------|
| D1 | `harden-and-audit.sh`: single, self-contained, unattended, idempotent root script |
| D2 | `tests/Dockerfile`: systemd-PID-1 Debian test image (ARG for 12/13), kernel + GRUB installed, GUI packages pre-seeded to prove the purge |
| D3 | `tests/run-ci.sh`: builds, boots, runs the script, runs functional assertions, enforces the score gate, and exports reports |
| D4 | `tests/assertions.sh`: functional checks (auditd policy, sshd, FIPS provider, UFW, purge, libs) |
| D5 | `.github/workflows/ci.yml`: shellcheck + Debian 12/13 matrix, artifacts, job summary with scores |
| D6 | `.github/workflows/release.yml`: on `main`, run CI then publish a GitHub Release with the script and its SHA-256 |
| D7 | `README.md`, `docs/EXCEPTIONS.md` (POA&M-style deviations), `docs/GAP-ANALYSIS.md` |
| D8 | Branching: `integration` (default, all work) and `main` (release line) on GitHub |

## 3. Script requirements traceability

| Req | Item | Implementation |
|-----|------|----------------|
| R0.1 | root only, `set -Eeuo pipefail`, `DEBIAN_FRONTEND=noninteractive`, ERR trap naming the failing step | `main`, `on_error` |
| R0.2 | Debian 12/13 only, headless only | `preflight_os` |
| R0.3 | **Anti-lockout preflight**: require a non-root sudo-group admin with a key or password *before* any change. Detect the SSH port. Keep IPv6 RA when SSH arrives over SLAAC IPv6. | `preflight_admin`, `detect_ssh_port`, `preflight_ipv6` |
| R0.4 | Log everything to `/var/log/harden-and-audit.log`. Back up every file before overwriting it, under `/var/backups/harden-and-audit/` (never inside a `*.d` include directory). | `backup_file` |
| R1.1 | `APT::Install-Recommends "false"`, `APT::Install-Suggests "false"` | `/etc/apt/apt.conf.d/90-harden-no-recommends` |
| R1.2 | Purge DMs, DEs, X servers, toolkits, X11/Wayland/Mesa libs (dependency-aware), then `autoremove --purge`. Remove legacy insecure daemons. | `purge_graphical`, `purge_insecure_services` |
| R2.1 | Official repos: `<codename>`, `-updates`, `-security` (deb822), components `main contrib non-free non-free-firmware`, mirrors overridable | `configure_repositories` |
| R2.2 | Install openssh-server tmux curl git ufw fail2ban libpam-pwquality auditd unattended-upgrades (+ sudo, rsyslog, aide, apparmor, timesync, audispd-plugins) | `install_base_stack` |
| R2.3 | unattended-upgrades: daily, Debian-Security origins, conffile-safe, no surprise reboot | `configure_unattended_upgrades` |
| R3 | auditd.conf: `max_log_file = 20`, `max_log_file_action = ROTATE`, `space_left_action`/`admin_space_left_action`/`disk_full_action`/`disk_error_action = SYSLOG`. **Never** SUSPEND/SINGLE/HALT. Audit failure flag `-f 1` (never panic). A post-write assertion refuses forbidden values. | `configure_auditd` |
| R3.2 | Full CIS/STIG audit rule set (b64 + b32), privileged-command rules generated from on-disk setuid/setgid binaries, `-e 2` | `configure_audit_rules` |
| R4.1 | `fips=1` (+ `audit=1`, `audit_backlog_limit=8192`, `apparmor=1 security=apparmor`, safe ANSSI hardening args) in `GRUB_CMDLINE_LINUX_DEFAULT`, then `update-grub` | `configure_grub` |
| R4.2 | Build, verify, and install the validated OpenSSL 3.1.2 FIPS provider. `openssl.cnf` activates `fips` **and** `default` providers. Validate before install, roll back on failure. Optional `FIPS_STRICT=1` sets `default_properties = fips=yes`. | `install_fips_provider`, `configure_openssl_fips` |
| R5.1 | Ownership/mode for passwd/group/shadow/gshadow (+ backups, cron, sshd keys, logs, grub.cfg, audit files) | `harden_file_permissions` |
| R5.2 | sysctl network + kernel hardening in `/etc/sysctl.d/60-harden.conf` | `configure_sysctl` |
| R5.3 | SSH: no root, no X11, `MaxAuthTries 4`, `ClientAliveInterval 300`/`CountMax 3`, FIPS ciphers/MACs/KEX, banner, etc. `sshd -t` before reload. | `configure_sshd` |
| R5.4 | UFW: default deny incoming/routed, allow detected SSH port (rate-limited), loopback rules, `--force enable` | `configure_ufw` |
| R5.5 | PAM (pwquality, pwhistory, faillock, yescrypt, su→sugroup), login.defs aging, umask 027, TMOUT 900, sudo (use_pty, logfile), banners (DoD), kernel module blacklist, `/tmp` + `/dev/shm` mount options, core dumps, journald/rsyslog/logrotate, timesync, AppArmor, AIDE, cron/at, fail2ban, GRUB password (`--unrestricted` boot) | `configure_*` functions |
| R6.1 | CUDA prerequisites: libc6 libc6-dev gcc make linux-headers-amd64 (+ running-kernel headers) dkms build-essential pkg-config; nouveau blacklisted | `provision_cuda_prereqs` |
| R6.2 | coturn and media **libraries only** (no coturn, no X11): libevent*, hiredis, mariadb, pq, sqlite, ssl, systemd, opus, vpx, srtp2, x264, x265, aom, dav1d, ogg, vorbis, speex, webp, theora, flac, lame, usrsctp, jansson, websockets, microhttpd; UDP buffer sysctls | `provision_media_coturn_libs` |
| R7.1 | Install `libopenscap8` (if available), `openscap-utils`, `openscap-scanner`, `ssg-debian` | `install_openscap` |
| R7.2 | Evaluate the CIS L2 Server profile into `/var/log/scap-results.xml` and `/var/log/scap-report.html` | `run_scap_audit` |
| R7.3 | Print/save passes, failures, and final score (`/var/log/scap-summary.txt`). Non-zero exit if below `SCAP_MIN_SCORE` (90). | `summarize_scap` |
| R7.4 | Recurring scan: `scap-audit.timer` (weekly) re-runs the evaluation | `install_scap_timer` |

## 4. CI / test plan

1. `shellcheck` on every shell file.
2. Matrix `debian:12`, `debian:13`: build `tests/Dockerfile` and boot systemd. The runner is ephemeral, so `--privileged` is used there to make sysctl/UFW/auditd behave as on a host. Local runs use the narrower `CAP_SYS_ADMIN` + `NET_ADMIN` mode so the developer's kernel is never modified.
3. Run `harden-and-audit.sh` with `SCAP_EXTRA_PROFILES=anssi_bp28_high`.
4. Run `tests/assertions.sh` (functional checks of every owner requirement).
5. Gate: CIS L2 Server pass rate ≥ 90%. Publish the XML/HTML/summary as artifacts and a Markdown table in the job summary.
6. Re-run the script a second time to prove idempotence, then rescan.

## 5. Branching & release

* `integration` is the default branch. All commits land there, and CI runs on every push and PR.
* `main` is the release line. A push to `main` runs CI and then publishes `vX.Y.Z` from `VERSION` with `harden-and-audit.sh` and `harden-and-audit.sh.sha256`.

## 6. Known limits (to be documented, not hidden)

* Separate partitions (`/var`, `/var/log`, `/var/log/audit`, `/home`, `/var/tmp`) are an install-time decision. A script cannot repartition a running host. These rules fail unless the installer created them.
* The kernel's FIPS mode (`fips=1`) runs the Debian kernel's crypto self-tests. Debian's kernel crypto is **not** CMVP-validated. Only the OpenSSL user-space module is.
* ANSSI BP-028 High requires SELinux, a custom kernel config, `kernel.modules_disabled=1` (incompatible with NVIDIA/DKMS), and LDAP/SSSD. It is reported, not gated.
