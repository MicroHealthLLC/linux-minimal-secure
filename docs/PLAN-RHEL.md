# Plan: RHEL-family support and the linux-minimal-secure rename (2026-11-23)

## 1. Analysis

### 1.1 Source

`harden-and-audit.sh` 1.2.0 is a single 3,240-line Bash script with about 90 functions. It assumes
Debian/Ubuntu in these places:

| Area | Debian/Ubuntu mechanism | RHEL-family equivalent |
|---|---|---|
| Detection | `ID=debian\|ubuntu`, codename required | `ID=rhel\|centos\|rocky\|almalinux\|ol` (or `ID_LIKE` ∋ `rhel`), major ≥ 8, no codename |
| Packages | `dpkg-query`, `apt-cache policy`, `apt-get`, `apt-mark` | `rpm -q`, `dnf repoquery`, `dnf`, `dnf mark` |
| Dependency-aware purge | `apt-get -s purge` simulation | `rpm -e --test` (fails whenever an outside package depends on the target) |
| Minimal installs | `APT::Install-Recommends "0"` | `dnf.conf`: `install_weak_deps=False`, `gpgcheck=1`, `localpkg_gpgcheck=1` |
| Repositories | deb822 `*.sources`, official mirrors | Vendor BaseOS/AppStream + CRB/PowerTools + EPEL (fail2ban, dkms, some codecs). RHEL: subscription-managed (fatal if no repo is enabled) |
| **Mandatory updates** | unattended-upgrades + apt timers | `dnf-automatic` (`apply_updates = yes`, `upgrade_type = security`. CentOS Stream publishes no errata, so `default`). Timer unmasked, enabled and active (fatal on hosts) |
| Admin group (anti-lockout) | `sudo` | `wheel` |
| FIPS | Validated OpenSSL 3.1.2 provider built from source (cert #4985) | The distribution's own module: `fips-mode-setup --enable` (EL8/9). EL10 has no `fips-mode-setup`, so `update-crypto-policies --set FIPS` + `fips=1` (+ `boot=`) |
| Kernel arguments | `/etc/default/grub` + `update-grub`, `apparmor=1 security=apparmor` | `grubby --update-kernel=ALL` + `/etc/default/grub` (`grub2-mkconfig`). **No AppArmor arguments**: `security=apparmor` would switch SELinux off |
| GRUB password | `/etc/grub.d/01_harden_password`, `--unrestricted` patch | `/boot/grub2/user.cfg` `GRUB2_PASSWORD=` (what `grub2-setpassword` writes). EL entries are already unrestricted |
| SSH crypto | Explicit FIPS `Ciphers/MACs/KexAlgorithms` | System crypto policy (CIS `configure_ssh_crypto_policy` fails if sshd_config overrides it). The unit is `sshd.service` |
| Firewall | UFW | firewalld (SSH ports first, drop `cockpit`, loopback anti-spoofing, optional egress allow-list via a policy object) |
| MAC | AppArmor enforce | SELinux `enforcing`/`targeted`. A host booted with SELinux **disabled** goes to `permissive` + `/.autorelabel` first (anti-lockout), and enforcing on the next run |
| PAM | `pam-auth-update` profiles | Custom authselect profile `custom/harden` (from `sssd`, or `local` on EL10) with `with-faillock with-pwhistory without-nullok`, `remember=24` |
| Password hashing | yescrypt | SHA512 (EL CIS default) |
| Shadow files | `root:shadow 0640` | `root:root 0000` |
| Shell rc | `/etc/bash.bashrc` | `/etc/bashrc` |
| Time | timesyncd (chrony kept) | chronyd (`/etc/chrony.conf`, `OPTIONS="-u chrony"`) |
| Cron unit | `cron.service` | `crond.service` |
| logrotate timer | shipped | EL8 has none, so the script ships `logrotate.{service,timer}` |
| AIDE | `/etc/aide/aide.conf` + `conf.d`, `aideinit`, `aide.db` | `/etc/aide.conf` (managed block, no conf.d), `aide --init`, `aide.db.gz`. EL8 AIDE 0.16 has no `-p` |
| Telemetry | apport/whoopsie/motd-news | abrt, setroubleshoot, mcstrans (CIS EL) |
| tmux lock | `vlock` package | `vlock` from `kbd` |
| CUDA prereqs | `linux-headers-*`, `build-essential` | `kernel-devel`, `kernel-headers`, `gcc`, `make`, `elfutils-libelf-devel`, `dkms` (EPEL) |
| Media libraries | Debian sonames | RPM names. `x264`/`x265` exist only in RPM Fusion (not enabled: third party), and `usrsctp` is missing on EL10. Missing ones are reported |
| SCAP content | pinned upstream SSG 0.1.82, Ubuntu retarget | Vendor-packaged `scap-security-guide`, matched to the platform: `ssg-rl{8,9,10}`, `ssg-almalinux{8,9,10}`, `ssg-cs{9,10}`, `ssg-rhel{8,9,10}`, `ssg-ol{8,9}`. Gate profile `cis` (CIS Level 2 Server), STIG informational |

Facts above were verified in `rockylinux/rockylinux:{8,9,10}`, `almalinux:{8,9,10}` and
`quay.io/centos/centos:stream{9,10}` (package availability, SSG content and profiles, AIDE version,
authselect features, logrotate timer, fips-mode-setup, shadow permissions, errata counts).

### 1.2 Impact

* **Debian/Ubuntu behaviour must not change.** Every EL path is behind `is_rhel`, and the 5 existing CI
  targets stay in the matrix as the regression net.
* The step counter's formula changes (a third repository step variant). CI asserts the counter is exact on every target.
* `SCAP_PROFILE` default becomes family-dependent (`cis_level2_server` / `cis`). An explicit value still wins.
* `UFW_OUTBOUND_POLICY` / `UFW_EXTRA_OUT` keep working. Generic aliases `FIREWALL_OUTBOUND_POLICY` / `FIREWALL_EXTRA_OUT` are added.
* RHEL itself can't run in public CI (subscription). Its code path is the clones' path plus subscription and
  EPEL bootstrap, and it is covered by the clones.
* Rename: the project and repository become **linux-minimal-secure**. The script keeps the name
  `harden-and-audit.sh`, so installed timers, `/usr/local/sbin/harden-and-audit.sh`, backups and logs stay valid.

## 2. Plan

| ID | Deliverable |
|---|---|
| R1 | Family detection (`OS_FAMILY`, `is_rhel`/`is_deb`), EL ID allow-list + `ID_LIKE`, `SSG_PRODUCT` map, `ADMIN_GROUP`, arch map, `SSH_UNIT` |
| R2 | Package abstraction for both families: installed, candidate (cached name list on dnf), first_available, install, refresh, upgrade, dependency-safe purge, mark-manual |
| R3 | EL repositories: CRB/PowerTools + EPEL (vendor `epel-release`, Fedora RPM on RHEL), gpgcheck enforced, fatal when no repo is enabled |
| R4 | EL mandatory automatic updates via dnf-automatic, with the same fatal checks as apt |
| R5 | EL minimalism: weak deps off, graphical/legacy/telemetry purge (rpm names) |
| R6 | EL FIPS (distribution module) + crypto policy FIPS + kernel arguments via grubby + GRUB2 password (`user.cfg`) |
| R7 | EL CIS controls: shadow perms, firewalld, authselect PAM, SHA512, SELinux, chronyd, crond, sshd unit/crypto policy, AIDE paths, logrotate timer on EL8, audit-rule paths (SELinux, sysconfig) |
| R8 | EL CUDA prerequisites + media libraries (RPM names) |
| R9 | EL OpenSCAP: packaged content per vendor, `cis` gate, `stig` informational |
| R10 | CI: `tests/Dockerfile.el`, `run-ci.sh` for `rocky\|almalinux\|centos`, family-aware `assertions.sh`, matrix +8 jobs (Rocky 8/9/10, Alma 8/9/10, CentOS Stream 9/10) |
| R11 | Rename to linux-minimal-secure (README, docs, workflows, release notes, GitHub repository), version **2.0.0** |
| R12 | Docs: README (both families), EXCEPTIONS (EL deviations), gap analysis |

**Acceptance.** shellcheck clean. All 13 GitHub CI jobs green on `integration` (shellcheck + 5 Debian/Ubuntu +
8 EL, each harden → assert → re-run → assert → CIS gate ≥ 90%). GitHub security findings cleared. Then merged to `main`.
