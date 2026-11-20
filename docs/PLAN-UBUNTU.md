# Implementation Plan: Ubuntu 22.04 / 24.04 / 26.04 support

Status: approved for execution (autonomous run, 2026-11-20).
Scope: extend `harden-and-audit.sh` so it applies the **same** hardening, FIPS, audit, and OpenSCAP self-audit to Ubuntu LTS 22.04 (jammy), 24.04 (noble), and 26.04 (resolute), amd64 (arm64 best effort), headless. The Debian 12/13 behavior must not regress.

## 1. Analysis (source and impact)

The source is the existing single script (`harden-and-audit.sh`, 2,317 lines, ~60 functions) plus a Docker-based CI that hardens a systemd-booted container and gates on the CIS Level 2 Server pass rate. About 85% of it is distribution-neutral (auditd, PAM, sshd, UFW, sysctl, FIPS provider build, AIDE, logging, mounts). The rest is Debian-specific in ways that would break or mis-score on Ubuntu. Each finding below was measured in `ubuntu:22.04`, `ubuntu:24.04`, and `ubuntu:26.04` containers, not assumed.

| # | Finding (measured) | Impact on design |
|---|---|---|
| U1 | `preflight_os` refuses anything except `ID=debian`. Ubuntu versions are `22.04`-style, codenames jammy/noble/resolute. | Add an OS abstraction: `OS_ID`, `OS_VERSION`, `SSG_PRODUCT` (`debian12`, `ubuntu2404` …). Accept Ubuntu ≥ 22.04 (non-LTS interim releases are allowed with a warning). |
| U2 | Ubuntu archives differ: `archive.ubuntu.com` / `security.ubuntu.com` (amd64) or `ports.ubuntu.com` (arm64), components `main restricted universe multiverse`, keyring `ubuntu-archive-keyring.gpg`. 22.04 uses one-line `sources.list`, 24.04+ use deb822 `ubuntu.sources`. Cloud images use regional mirrors. | deb822 `ubuntu.sources` for all three. The mirror is **auto-detected from the existing config** (keeps cloud/private mirrors working) with `UBUNTU_MIRROR`/`UBUNTU_SECURITY_MIRROR` overrides. Universe and multiverse are required (fail2ban, OpenSCAP, codecs). |
| U3 | unattended-upgrades origins are `origin=Ubuntu,archive=<codename>-security` (+ ESM origins when Pro is attached). | Distribution-specific origin patterns and post-write check. |
| U4 | **OpenSCAP packaging:** 22.04 has only `libopenscap8` 1.2.17 (no `openscap-scanner`/`-utils`, no `ssg-*`). 24.04 has 1.3.9 + `ssg-debderived` 0.1.71. 26.04 has 1.4.3 + 0.1.79. | Install what exists per release (`libopenscap8` on 22.04 satisfies R7.1 literally; scanner/utils/`ssg-debderived` elsewhere). Verified: oscap 1.2.17 loads and evaluates the 0.1.82 Ubuntu 22.04 datastream with 0 errors. |
| U5 | **SCAP content:** pinned SSG 0.1.82 ships full CIS L1/L2 + STIG for `ubuntu2204` and `ubuntu2404`. `ssg-ubuntu2604-ds.xml` is an **empty skeleton (no profiles)**. The 24.04 datastream already carries the 26.04 CPE and its OVAL check (`installed_OS_is_ubuntu2604`). | On 22.04/24.04 scan native content. On 26.04 (or any release whose datastream lacks the profile), evaluate the newest older Ubuntu LTS content with the benchmark platform **retargeted** to the running release's CPE, and say so in the summary and docs. This is the only CIS content that exists for 26.04 today. |
| U6 | DISA **does** publish STIGs for Ubuntu 22.04 and 24.04 (unlike Debian); SSG ships them as profile `stig`. | Gate stays CIS L2 Server ≥ 90% on every OS. CI also scans and reports `stig` (informational) on Ubuntu, as it reports ANSSI on Debian. A requested extra profile that is missing is a warning, not a fatal error. |
| U7 | **26.04 `sudo` is sudo-rs** (alternatives priority). sudo-rs's `visudo` rejects `logfile`, `log_input`, `log_output`, `iolog_dir`, so the current sudo step would abort, and the CIS/STIG sudo logging controls cannot be met. Classic sudo is still installed as `sudo.ws`. | New tunable `SUDO_PROVIDER=classic` (default): validate the sudoers tree with `visudo.ws`, then select classic sudo through `update-alternatives`, then write the same fragment. `SUDO_PROVIDER=keep` keeps sudo-rs and writes only the settings its `visudo` accepts (validated line by line). |
| U8 | **26.04 uses uutils (Rust) coreutils** by default. | The script's coreutils usage must work unchanged under uutils. Proven by running the whole CI under the stock 26.04 image (no GNU swap). |
| U9 | `fchmodat2` is unknown to the audit userspace on 22.04/24.04 (known on 26.04 and Debian 13). `renameat2` is known everywhere. | New syscall rules are generated per syscall and per arch only when `ausyscall` knows them, replacing the `OS_MAJOR >= 13` test. |
| U10 | **sysctl conflicts:** Ubuntu ships `rp_filter=2`, `kernel.sysrq=176`, `protected_fifos=1` in `/etc/sysctl.d/10-*.conf` (22.04/24.04) or `/usr/lib/sysctl.d/55-*.conf` (26.04); `99-protect-links.conf` sorts **after** `60-harden.conf` and silently wins at runtime. SCAP reads every sysctl directory. | Generic neutralizer: any managed key with a different value is commented out in `/etc/sysctl.conf` and `/etc/sysctl.d/*.conf`, and vendor files in `/usr/lib/sysctl.d` are masked with an `/etc/sysctl.d` copy of the same name with the conflict commented out. Applies to Debian too (its `protect-links.conf` has the same ordering bug). |
| U11 | **SSH socket activation** on 24.04+ (`ssh.socket`, `Accept=no`, `sshd-socket-generator`). A port set in an `ssh.socket` drop-in is invisible to `sshd -T`. | Port detection also reads `systemctl show ssh.socket -p Listen` (anti-lockout: UFW must open the real port). Reload logic handles an idle socket-activated sshd. |
| U12 | Kernel metapackages are `linux-image-{generic,virtual,aws,azure,…}`; `linux-headers-amd64` does not exist. 26.04 can use **dracut** instead of initramfs-tools. | Headers follow each installed `linux-image-<flavour>` metapackage (fallback `linux-headers-generic`) plus the running kernel's. initramfs is regenerated with `update-initramfs`, or `dracut --regenerate-all -f`. |
| U13 | Media sonames differ per release (`libx264-163/164/165`, `libvpx7/9/12`, `libdav1d5/7`, `libflac8/12t64/14`, `libtheora0`→`libtheora1`, `libconfig9/11`). | Each library group may end in a `~regex` fallback that picks the newest available name. Debian keeps choosing exactly the same packages (explicit names are tried first). |
| U14 | Ubuntu-only telemetry/crash services: apport (sets `core_pattern` to a pipe), whoopsie, popularity-contest, motd-news (calls home). CIS has apport rules. | Purge where dependency-safe; otherwise disable and mask. motd-news disabled. snapd is **not** removed (Ubuntu AMIs ship the SSM agent as a snap; removing it can cut the only management path). |
| U15 | Ubuntu Pro FIPS (`pro enable fips-updates`) provides Canonical's own certified modules and kernel. | If Pro FIPS is active, keep it: skip the OpenSSL 3.1.2 build and the `openssl.cnf` rewrite (never stack two FIPS providers). Otherwise build 3.1.2 exactly as on Debian. Jammy's OpenSSL 3.0.2 must load the 3.1.2 provider; the existing pre-activation validation (providers, `sshd -t`, TLS loopback) is the safety net. |
| U16 | Cloud images put `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub.d/50-cloudimg-settings.cfg`, which is sourced after `/etc/default/grub` and drops `fips=1` from the default string. ZFS-root systems use `10_linux_zfs`, which `--unrestricted` patching does not cover. EFI path is `/boot/efi/EFI/ubuntu`. | If any `grub.d/*.cfg` overrides a command-line variable, write `99-harden-and-audit.cfg` that re-appends the hardening arguments. `10_linux_zfs` gets the same `--unrestricted` patch; if that cannot be verified, the GRUB password is skipped with a warning (never risk an unbootable host). |
| U17 | AppArmor: Ubuntu ships 100–150 profiles; some are deliberately disabled (`/etc/apparmor.d/disable`). | Same policy as Debian (enforce everything not flagged `unconfined`), except profiles the distribution disabled are loaded in **complain** mode, which satisfies the CIS "enforce or complain" rule without risking a service the vendor chose not to confine. |
| U18 | Ubuntu's rsyslog drops privileges to `syslog` and needs `/var/log` group-writable (`root:syslog 0775`). | Leave `/var/log` directory ownership/mode alone (the script already only removes `o+w`). |
| U19 | CI: the Docker harness, assertions, workflow matrix, artifact names, and release asset globs are Debian-only. `ubuntu:24.04+` images carry a default `ubuntu` account with no password and no key. | Generalize the harness to `<distro> <version>`. Assertions become distro-aware. CI matrix = Debian 12, 13 + Ubuntu 22.04, 24.04, 26.04. The image removes the docker-only `ubuntu` account so the host looks like a server install. |

### 1.1 Findings added during execution (first local test cycle)

| # | Finding | Resolution |
|---|---|---|
| U20 | The Ubuntu CIS content checks the vendor `dailyaidecheck.timer` (aide-common), not the `aidecheck.timer` the Debian content expects. | On Ubuntu the vendor timer is enabled and no second timer is installed. |
| U21 | Ubuntu's TMOUT check matches only the POSIX three-line form (`TMOUT=900` / `readonly TMOUT` / `export TMOUT`). | Distribution-specific `/etc/profile.d/60-harden.sh`, still guarded against re-sourcing. |
| U22 | Ubuntu expects `/etc/gshadow-` group `shadow`, `/etc/cron.allow` group `crontab`, xattr audit rules for `auid=0`, a `/etc/netplan/` watch even before netplan exists, and squashfs disabled. | Implemented; squashfs only when snapd is absent (snaps are squashfs images). |
| U23 | **audit 4.1 (26.04)** loads `rules.d` through `audit-rules.service`; `auditd.service` only `Wants=` it. The 24.04 checks detect "augenrules mode" by the audit 3.x `Requires=augenrules.service` line, so every audit rule failed on 26.04 although the rules were loaded. | The 26.04 retarget also teaches that one pattern the audit 4.1 layout (documented in EXCEPTIONS §8). |
| U24 | jammy's oscap 1.2.17 returns `error` for 4 rules (three UFW script checks, `no_files_unowned_by_user`) and `openssl dgst -propquery` is ignored by OpenSSL 3.0.2. | Errors documented; the FIPS assertion uses a FIPS-only provider context, which proves enforcement on every OpenSSL version. |

## 2. Architecture decision

**One script, distribution-aware**, not a fork. A second 2,300-line copy would drift; most fixes (auditd, PAM, sshd, FIPS) must reach both families. Distribution differences live in a small number of `case $OS_ID` branches and data tables. Debian code paths stay byte-for-byte equivalent in effect, which CI proves by re-running Debian 12/13 with the same ≥ 90% gate and 120 assertions.

`VERSION` / `SCRIPT_VERSION` → **1.1.0**.

## 3. Deliverables

| ID | Deliverable |
|---|---|
| UD1 | `harden-and-audit.sh` 1.1.0 supporting Debian 12/13 and Ubuntu 22.04/24.04/26.04 |
| UD2 | `tests/Dockerfile` generalized (`BASE_IMAGE` arg; Ubuntu kernel/GRUB/admin/seeded GUI + legacy packages) |
| UD3 | `tests/run-ci.sh <debian|ubuntu> <version>` (backward compatible with `run-ci.sh 12`) |
| UD4 | `tests/assertions.sh` distro-aware (repos, update origins, headers, media sonames, OpenSCAP packages, sudo provider, sysctl conflicts) |
| UD5 | `ci.yml` matrix: debian 12, 13; ubuntu 22.04, 24.04, 26.04. Extra informational profile: ANSSI on Debian, STIG on Ubuntu |
| UD6 | `release.yml`: asset globs and notes cover every OS |
| UD7 | `README.md`, `docs/EXCEPTIONS.md` (Ubuntu section), this plan, `docs/GAP-ANALYSIS-UBUNTU.md` |

## 4. Requirement traceability (Ubuntu)

Every Debian requirement R0–R7 in [PLAN.md](PLAN.md) applies unchanged in intent. Ubuntu-specific implementation:

| Req | Ubuntu implementation |
|---|---|
| R0.2 | Ubuntu ≥ 22.04 accepted (U1) |
| R0.3 | + `ssh.socket` port detection (U11) |
| R1.2 | + Ubuntu desktop metapackages in the purge set; + apport/whoopsie/popularity-contest/motd-news (U14) |
| R2.1 | `ubuntu.sources` with `<codename>`, `-updates`, `-security`, `main restricted universe multiverse`, mirror auto-detect (U2) |
| R2.3 | Ubuntu security (+ESM) origins (U3) |
| R3.2 | `ausyscall`-gated new syscalls (U9); `/etc/netplan` watched when present |
| R4.1 | GRUB drop-in override, `10_linux_zfs`, Ubuntu EFI path (U16) |
| R4.2 | OpenSSL 3.1.2 provider on OpenSSL 3.0.2 / 3.0.13 / 3.5.x, or Ubuntu Pro FIPS kept (U15) |
| R5.2 | sysctl conflict neutralizer (U10) |
| R5.5 | sudo provider (U7); AppArmor disabled→complain (U17) |
| R6.1 | flavour-matched headers; dracut (U12) |
| R6.2 | regex soname fallback (U13) |
| R7.1–R7.3 | per-release OpenSCAP packages (U4); native or retargeted content (U5); STIG informational (U6) |

## 5. CI / test plan

1. ShellCheck + `bash -n` on every shell file.
2. Matrix of 5 systemd-booted containers (Debian 12, 13; Ubuntu 22.04, 24.04, 26.04), privileged on GitHub, restricted locally.
3. Run the script, run functional assertions, run the script again (idempotence), assert again.
4. Gate: CIS L2 Server pass rate ≥ 90% on every OS. Publish XML/HTML/summary + an informational ANSSI (Debian) / STIG (Ubuntu) report.
5. Develop locally first (all three Ubuntu releases in parallel, unprivileged), then confirm on GitHub Actions (privileged, authoritative).

## 6. Known limits (documented, not hidden)

* Ubuntu 26.04 has no upstream CIS/STIG SCAP content yet; its score is the CIS Ubuntu 24.04 L2 benchmark evaluated on 26.04 (U5). Re-pin `SSG_VERSION` once native content ships.
* Kernel `fips=1` on a non-Pro Ubuntu kernel runs the kernel's FIPS self-tests, but the Ubuntu generic kernel crypto is not CMVP-validated; only the OpenSSL 3.1.2 module (or Ubuntu Pro FIPS) is.
* Same install-time partition and container limits as Debian.
