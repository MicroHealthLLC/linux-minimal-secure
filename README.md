# debian-minimal-secure

`harden-and-audit.sh` is a single, unattended Bash script. It turns a stock **Debian 12 (bookworm)** or **Debian 13 (trixie)** install into a minimal, FIPS-ready, CIS Level 2 / STIG-aligned headless server, then audits itself with **OpenSCAP**. It writes a machine-readable XML result and a standalone HTML report.

| | |
|---|---|
| Gate profile | **CIS Debian Level 2 – Server** (ComplianceAsCode/SSG 0.1.82). Target pass rate ≥ 90%, enforced in CI on Debian 12 and 13 |
| Also reported | ANSSI BP-028 High (informational; see [docs/EXCEPTIONS.md](docs/EXCEPTIONS.md)) |
| FIPS | Kernel `fips=1` plus the **NIST CMVP validated OpenSSL 3.1.2 FIPS provider (FIPS 140-3, cert #4985)**, active alongside the default provider |
| Reports | `/var/log/scap-results.xml`, `/var/log/scap-report.html`, `/var/log/scap-summary.txt` |

> **About STIGs.** DISA does not publish a STIG for Debian, so no Debian STIG SCAP profile exists. This project gates on the CIS Level 2 Server benchmark and also implements the DoD-specific STIG controls natively: the DoD Notice & Consent banner, FIPS cryptography, FIPS-only SSH algorithms, the STIG audit rule set, account lockout, and session lock.

## Quick start

```bash
# Download a release from the "main" release line and verify it
curl -fsSLO https://github.com/MicroHealthLLC/debian-minimal-secure/releases/latest/download/harden-and-audit.sh
curl -fsSLO https://github.com/MicroHealthLLC/debian-minimal-secure/releases/latest/download/harden-and-audit.sh.sha256
sha256sum -c harden-and-audit.sh.sha256

# Prerequisite: a NON-ROOT administrator in the sudo group with an SSH key or password.
# The script refuses to run without one, because it disables root SSH login.
sudo bash harden-and-audit.sh
sudo reboot     # activates fips=1, audit=1 and the other kernel arguments
```

Re-run only the compliance scan at any time with `sudo harden-and-audit.sh --scan-only`. A weekly `scap-audit.timer` does the same thing automatically.

## Anti-lockout guarantees

The script is built so you cannot lose access to the server:

1. **Preflight before any change.** It aborts unless a non-root `sudo` member with an SSH key or password exists. It also detects the real SSH port(s), and detects IPv6 SLAAC so RA is not disabled when the host depends on it.
2. **auditd can never stop the box.** `max_log_file = 20`, `max_log_file_action = ROTATE`, and every space/disk action is `SYSLOG`. The script refuses to finish if `SUSPEND`, `SINGLE` or `HALT` appear anywhere in `auditd.conf`. The kernel audit failure mode is `-f 1` (log), never `-f 2` (panic).
3. **sshd is validated first.** The new `sshd_config` must pass `sshd -t` before it replaces the old one. sshd is *reloaded*, so existing sessions survive. All existing interactive users are added to `ssh-users` (`AllowGroups`).
4. **OpenSSL is validated first.** The new `openssl.cnf` is tested through `OPENSSL_CONF=<candidate>` (FIPS and default providers active, `sshd -t`) before activation. A broken FIPS include would otherwise break every TLS/SSH consumer.
5. **The firewall allows SSH before it is enabled.** UFW only defaults to deny *inbound*. Outbound stays open unless you opt in with `UFW_OUTBOUND_POLICY=deny`, which also adds a DHCP/DNS/NTP/HTTP(S) allow-list.
6. **Lockouts are temporary.** `pam_faillock` auto-unlocks after 15 minutes. Password aging is not applied to an account whose password is already older than `PASS_MAX_DAYS`, because that would expire it on the spot.
7. **GRUB password protects editing, not booting.** Menu entries are `--unrestricted`, so unattended reboots keep working.
8. **NOPASSWD sudo rules are reported, not removed.** On cloud images they are often the only working sudo path.

The CI proves #3: after hardening, the sudo admin must still log in over SSH with a key, and root must be refused.

## What the script does

| Area | Implementation |
|---|---|
| Minimalism | `APT::Install-Recommends/Suggests "false"`. Dependency-aware purge of display managers, desktops, X servers, toolkits, and X11/Wayland/Mesa libraries (never removes a non-graphical package that links to them). Removes telnet/rsh/tftp/NIS/inetd/avahi/cups/rpcbind/etc. |
| Repositories | deb822 `debian.sources` → `<codename>`, `-updates`, `-security` (`main contrib non-free non-free-firmware`), overridable mirrors |
| Base stack | openssh-server, tmux, curl, git, ufw, fail2ban, libpam-pwquality, auditd, unattended-upgrades (+ sudo, rsyslog, AIDE, AppArmor, timesyncd, vlock) |
| Updates | unattended-upgrades applies Debian-Security daily, keeps local conffiles, never auto-reboots |
| auditd | Owner policy above, plus the full CIS/STIG rule set (time, identity, network, MAC, logins, sessions, DAC, failed access, mounts, deletions, modules, setuid/setgid exec, sudoers, privileged commands generated from disk), immutable `-e 2` |
| FIPS | `fips=1` in `GRUB_CMDLINE_LINUX` + `update-grub`. OpenSSL 3.1.2 FIPS provider built from the SHA-256-pinned source per its Security Policy into `/opt/openssl-fips-3.1.2`. `openssl.cnf` activates `fips` **and** `default` (strict `fips=yes` is opt-in with `FIPS_STRICT=1`). TLS ≥ 1.2. |
| Kernel cmdline | `audit=1 audit_backlog_limit=8192 apparmor=1 security=apparmor slab_nomerge=yes pti=on page_alloc.shuffle=1 vsyscall=none init_on_alloc=1 spectre_v2=on spec_store_bypass_disable=seccomp rng_core.default_quality=500` |
| Files | passwd/group 0644 root:root, shadow/gshadow 0640 root:shadow, backups, cron, sshd keys, grub.cfg 0400, audit config, logs, home directories 0750, world-writable cleanup |
| sysctl | No forwarding, redirects, or source routing. rp_filter, martian logging, syncookies, RA off (when safe), ASLR, kptr/dmesg restrict, ptrace scope, BPF hardening, protected links/fifos, no setuid core dumps |
| SSH | No root, no X11/TCP/agent forwarding, `MaxAuthTries 4`, `ClientAliveInterval 300` × 3, `LoginGraceTime 60`, `AllowGroups ssh-users`, DoD banner, FIPS-approved ciphers/MACs/KEX only, moduli ≥ 3071 bits |
| Firewall | UFW default deny inbound/routed, SSH allowed, loopback rules, logging, enabled with `--force` |
| Accounts | pwquality (15 chars, 4 classes, dictcheck, enforce for root), history 24, faillock (4 tries / 15 min), yescrypt, aging, inactivity 45 days, umask 027, `TMOUT=900`, su limited to the empty `sugroup`, sudo `use_pty` + logfile + I/O logging |
| Other | DoD banner, kernel module blacklist (cramfs, udf, usb-storage, dccp, sctp, rds, tipc, overlay…), `/tmp` `/var/tmp` `/dev/shm` nodev/nosuid/noexec, no core dumps, journald persistent + bounded, rsyslog 0640 + no listeners, logrotate daily/30/compress/200M cap, NTP, AppArmor enforce, AIDE + daily timer, fail2ban, local-only MTA, Ctrl-Alt-Del masked, tmux lock |
| CUDA | `libc6 libc6-dev gcc make build-essential pkg-config dkms linux-headers-amd64` (+ running kernel headers), nouveau blacklisted. The NVIDIA driver itself is not installed. |
| coturn / media | Runtime libraries only, with **no coturn and no X11**: libevent (+openssl/pthreads/extra), hiredis, mariadb, pq, sqlite, ssl, systemd, microhttpd, opus, vpx, srtp2, x264, x265, aom, dav1d, ogg, vorbis, speex, webp, theora, flac, lame, sndfile, samplerate, soxr, gsm, usrsctp, jansson, libconfig, websockets, curl. Large UDP socket buffers via sysctl. |
| OpenSCAP | `openscap-scanner`, `openscap-utils`, `ssg-debian` (+ `libopenscap8` where packaged). Scans with the SHA-512-pinned SSG 0.1.82 datastream (Debian 12's own `ssg-debian` has no Debian 12 content), falling back to packaged content offline |

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `SCAP_PROFILE` | `cis_level2_server` | Gate profile |
| `SCAP_EXTRA_PROFILES` | *(empty)* | Additional profiles, e.g. `anssi_bp28_high standard` |
| `SCAP_MIN_SCORE` / `SCAP_ENFORCE_MIN` | `90` / `1` | Exit 3 when the gate profile's pass rate is below the threshold |
| `SSG_DOWNLOAD` / `SSG_DATASTREAM` | `1` / *(empty)* | Offline/air-gapped: set `SSG_DOWNLOAD=0` and point `SSG_DATASTREAM` at a staged `ssg-debian12-ds.xml` |
| `FIPS_OPENSSL_URL` | GitHub release URL | Point at an internal mirror; the SHA-256 pin is still enforced |
| `FIPS_STRICT` | `0` | `1` = `default_properties = fips=yes` (non-FIPS algorithms unavailable system-wide) |
| `DEBIAN_MIRROR` / `DEBIAN_SECURITY_MIRROR` | deb.debian.org / security.debian.org | Internal mirrors |
| `NTP_SERVERS` / `NTP_FALLBACK_SERVERS` | Debian pool / time.nist.gov | Use your enclave's time sources |
| `PASS_MAX_DAYS` | `365` | DoD sites commonly use `60` |
| `FAILLOCK_DENY` / `FAILLOCK_UNLOCK_TIME` | `4` / `900` | Temporary lockout |
| `SHELL_TMOUT` | `900` | Idle shell timeout and tmux lock (seconds) |
| `ALLOW_CONTAINERS` | `0` | `1` keeps overlayfs and IPv4 forwarding for Docker/Podman hosts |
| `KEEP_IPV6_RA` | `auto` | `auto` keeps RA when SLAAC is in use |
| `UFW_OUTBOUND_POLICY` / `UFW_EXTRA_OUT` | `allow` / *(empty)* | `deny` + allow-list for egress filtering |
| `FAIL2BAN_IGNOREIP` | *(empty)* | Jump hosts that must never be banned |
| `SSH_DISABLE_PASSWORD` | `0` | `1` = key-only SSH (verified for every sudo admin first) |
| `ENABLE_GRUB_PASSWORD` / `GRUB_PASSWORD_PBKDF2` | `1` / *(generated)* | Supply your own `grub.pbkdf2.sha512…` hash; otherwise one is generated into `/root/grub-superuser-password.txt` |
| `AIDE_INIT` | `1` | Build the AIDE baseline at the end |
| `BANNER_FILE` | *(DoD banner)* | Custom login banner text |

## CI and releases

* **`integration`** is the default branch. Every push and PR runs [`ci.yml`](.github/workflows/ci.yml):
  1. `bash -n` + ShellCheck.
  2. A Debian 12 / 13 matrix. The script runs inside a systemd-PID-1 container that looks like a netinst server (kernel, GRUB, an admin user, seeded GUI/legacy packages). The container markers are removed so OpenSCAP scores the full *machine* ruleset rather than skipping it as "container".
  3. `tests/assertions.sh` verifies every requirement functionally (auditd policy, FIPS provider, SSH key login still works, root refused, purge, libraries, reports …).
  4. The script runs a **second time** to prove idempotence.
  5. **Gate:** the CIS L2 Server pass rate must be ≥ 90%. The XML/HTML/summary reports are uploaded as build artifacts, and the score table is posted to the job summary.
* **`main`** is the release line. A merge to `main` re-runs the full CI and then [`release.yml`](.github/workflows/release.yml) publishes `v<VERSION>` with `harden-and-audit.sh`, its `.sha256`, and the CI compliance reports. Bump `VERSION` and `SCRIPT_VERSION` together to cut a new release.

Run the same test locally (Docker required). The local mode never uses `--privileged`, so your workstation's kernel is untouched:

```bash
tests/run-ci.sh 12
tests/run-ci.sh 13
```

## Documentation

* [docs/PLAN.md](docs/PLAN.md): analysis and implementation plan
* [docs/EXCEPTIONS.md](docs/EXCEPTIONS.md): deviations from CIS/ANSSI and the reason for each
* [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md): what was delivered against the plan
