# Gap analysis: delivered vs. PLAN-RHEL (2026-11-23)

## Plan items

| ID | Planned | Delivered | Status |
|---|---|---|---|
| R1 | Family detection, SSG product map, admin group, arch, SSH unit | `OS_FAMILY` (ID allow-list `rhel centos rocky almalinux ol` + `ID_LIKE=rhel`), `SSG_PRODUCT` `rl*/almalinux*/cs*/ol*/rhel*`, `ADMIN_GROUP=wheel`, `SSH_UNIT=sshd`, x86_64/aarch64 → amd64/arm64 | done |
| R2 | Package abstraction | `pkg_installed/pkg_candidate/pkg_install/pkg_refresh/pkg_list_installed/pkg_mark_manual` for rpm/dnf (one cached `repoquery` for candidates), `safe_purge_rpm` via `rpm -e --test`, `first_available` prefers an installed alternative | done |
| R3 | EL repositories | Fatal if no repository is enabled (checked before any install). CRB/PowerTools + `epel-release` (Fedora RPM + key on RHEL/OL). `gpgcheck` enforced everywhere | done |
| R4 | Mandatory dnf-automatic | `/etc/dnf/automatic.conf` `apply_updates = yes`, `upgrade_type = security` (`default` on CentOS Stream), timer unmasked/enabled/active (fatal on hosts), competing timers off, `dnf.conf` excludes reported | done |
| R5 | EL minimalism | `install_weak_deps=False`, `localpkg_gpgcheck=1`. X11/desktop/Mesa and legacy service removal by RPM name, abrt/setroubleshoot/mcstrans | done |
| R6 | FIPS + kernel args + GRUB password | `fips-mode-setup --enable` (8/9), policy FIPS (10). grubby + `GRUB_CMDLINE_LINUX` without AppArmor, `selinux=0/enforcing=0` stripped, `boot=UUID=` for a separate /boot. `/boot/grub2/user.cfg` | done |
| R7 | EL CIS controls | shadow `0000`, firewalld, authselect `custom/harden`, SHA512, SELinux, chronyd `-u chrony`, crond, EL8 logrotate units, `/etc/aide.conf`, audit watches in syscall form, TMOUT `typeset -xr`, bashrc umask, sshd keepalive 1 / VERBOSE, host keys `root:ssh_keys 0640`, loopback rules in `trusted`, nftables.service off, journal-remote + postfix, AIDE cron | done |
| R8 | CUDA + media | `gcc make kernel-devel kernel-headers elfutils-libelf-devel pkgconf-pkg-config dkms`. 31 RPM media groups (x264/x265, and usrsctp on 10, reported missing) | done |
| R9 | EL OpenSCAP | `openscap-scanner scap-security-guide`, vendor datastream first, `cis` gate, `stig` informational | done |
| R10 | CI | `tests/Dockerfile.el`, `run-ci.sh rocky\|almalinux\|centos`, family-aware assertions (incl. PAM-module presence, root `su`, crypto policy, firewalld, SELinux config), +8 matrix jobs | done |
| R11 | Rename + 2.0.0 | README/workflows/release notes say linux-minimal-secure. `VERSION`/`SCRIPT_VERSION` 2.0.0. GitHub repository renamed after the merge to main | done (repo rename: see CI results) |
| R12 | Docs | README (RHEL section, config, CI), EXCEPTIONS §9, this file | done |

## Deltas found during execution and fixed

| # | Delta | Fix |
|---|---|---|
| Δ1 | **Fail-fast was silently off on every distribution**: `main "$@" \|\| rc=$?` disables errexit and the ERR trap for everything main runs (a failed `dnf install` went unnoticed; the same held for `apt-get` on Debian/Ubuntu) | `main` exits with its own status. Debian/Ubuntu re-verified green with fail-fast active |
| Δ2 | **SSH lockout on minimal EL hosts**: an `sssd`-based authselect profile references `pam_sss.so` (sssd-client), and without it PAM's account phase denies every login | Base profile `sssd` only if `pam_sss.so` exists, else `minimal` (8/9) / `local` (10). A guard verifies every module in `system-auth`/`password-auth` exists, otherwise restores the previous profile and dies. Asserted in CI |
| Δ3 | `su` broken for root on EL: `pam_wheel` was inserted before `pam_rootok` | Inserted after `pam_rootok`. "root can still su" asserted on every distro |
| Δ4 | `curl`/`libcurl` conflict with the images' `curl-minimal`/`libcurl-minimal` | Keep whichever is installed (`first_available` prefers installed alternatives) |
| Δ5 | `sshd -t` fails on EL before the first sshd start (no host keys yet) | `sshd_test` runs `ssh-keygen -A` when no host key exists |
| Δ6 | firewalld helper: `-q` silenced `--list-services` (cockpit stayed open), `--set-default-zone` is not a `--permanent` option, the helper was undefined on the second run | Listing without `-q`, default zone set at runtime/offline, helper defined per call |
| Δ7 | `chmod 0600` on aide.conf would break AIDE 0.19 (runs as `_aide`) on Debian 13 / Ubuntu | EL only |
| Δ8 | EL10's sandboxed `rsyslog.service` (and `rsyslogd -N1`'s capability drop) cannot run in any container | Container-only warning; fatal on hosts |
| Δ9 | Rocky 9 CIS 86.90% (< 90%): audit watches in `-w` form, TMOUT form, bashrc umask, keepalive/LogLevel, host-key group, loopback zone, nftables.service, journal-remote, postfix, AIDE cron, pwhistory | Each fixed from the content's own remediation scripts (`oscap xccdf generate fix`) |
| Δ10 | CI only: EL SSH login denied in privileged containers. The Ubuntu runner's AppArmor `unix-chkpwd` profile attaches by path to the EL helper and cannot read EL's `0000` shadow (strace: EACCES as root with all capabilities) | Profile unloaded on the ephemeral runner for EL jobs (a real EL host has no AppArmor). Local runs add `CAP_DAC_READ_SEARCH`, which EL's `unix_chkpwd` keeps |
| Δ11 | GitHub security: code scanning, Dependabot and secret scanning are disabled for this private repository (nothing to clear via the API) | Equivalent scans run locally and in CI on every push: gitleaks over the full history (no leaks), zizmor on the workflows. 3 medium `artipacked` (checkout credentials persisted) and 4 template-injection findings fixed (`persist-credentials: false`, version via env). zizmor clean |

## CI results

| Run | Commit | Result |
|---|---|---|
| 45273737522 | `9e944a2` | Debian/Ubuntu cancelled by the next push. EL: SSH anti-lockout failed (Δ10), EL10 rsyslog (Δ8) |
| 45275147763 | `26db042` | Debian 13, Ubuntu ×3 green with fail-fast active (Δ1). EL anti-lockout diagnostics captured |
| 45278056675 | `89b52b0` | strace: `unix_chkpwd` EACCES on shadow as root with all capabilities, no sysctl involved, pointing to the host AppArmor profile (Δ10) |
| 45279312988 | `17006a7` | EL anti-lockout **fixed** on all 8. EL9/10: outdated pwhistory assertion. EL8: CIS 89.76% |
| **45281242813** | **`ead2b5f`** | **all 14 green** |

| Target | CIS L2 Server | Informational |
|---|---|---|
| Debian 12 / 13 | 94.24% / 94.80% | ANSSI BP-028 High 74.03% / 74.03% |
| Ubuntu 22.04 / 24.04 / 26.04 | 94.17% / 95.18% / 95.18% | DISA STIG 71.77% / 72.86% / 71.90% |
| Rocky Linux 8 / 9 / 10 | 95.12% / 95.20% / 93.24% | DISA STIG 72.94% / 74.94% / 70.24% |
| AlmaLinux 8 / 9 / 10 | 94.88% / 95.20% / 93.48% | DISA STIG 72.75% / 74.77% / 70.88% |
| CentOS Stream 9 / 10 | 95.47% / 93.48% | DISA STIG 74.88% / 70.57% |

Released from `main` as **v2.0.0**; the GitHub repository is renamed to **linux-minimal-secure** (old URLs redirect).
