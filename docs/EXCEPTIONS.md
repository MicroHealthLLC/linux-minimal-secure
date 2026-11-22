# Documented deviations (POA&M input)

This file lists every SCAP rule that `harden-and-audit.sh` **intentionally** leaves failing or cannot satisfy, with the reason for each. Use it as the starting point for an RMF Plan of Action & Milestones or a risk-acceptance memo. CI gates on CIS Debian Level 2 Server ≥ 90% *with all of these counted as failures*. No tailoring file hides them.

## 1. Owner-mandated: never lose access because of auditing

The system owner requires that audit-log pressure must never suspend logging, drop the host to single-user mode, or halt it. CIS L2 asks for exactly those actions.

| Rule | CIS expects | Configured | Rationale |
|---|---|---|---|
| `auditd_data_retention_max_log_file_action` | `keep_logs` | `ROTATE` | `keep_logs` grows without bound until the disk fills |
| `auditd_data_retention_space_left_action` | `email` (or `exec`/`single`/`halt`) | `SYSLOG` | No MTA relay is assumed; the syslog alert is forwarded |
| `auditd_data_retention_admin_space_left_action` | `single` or `halt` | `SYSLOG` | `single`/`halt` remove remote access |
| `auditd_data_disk_full_action` | `halt` or `single` | `SYSLOG` | Same |

Compensating controls: `max_log_file = 20` (passes the CIS `>= 6` check), `num_logs = 10` (200 MB ceiling), the audit failure flag `-f 1` (printk, never panic), a 512 MB journald cap with 1 GB kept free, logrotate `maxsize 100M` checked hourly, a hard `/var/log` budget (`LOG_MAX_TOTAL`, default 4G, plus `LOG_MIN_FREE_PCT` disk free) enforced by pruning the oldest rotated archives, and syslog alerts that can be forwarded to the SIEM over TLS (`rsyslog-gnutls` is installed).

## 2. Conflicts inside the profile, or with mandated components

| Rule | Why it fails |
|---|---|
| `package_ufw_removed`, `package_iptables-persistent_installed` (Debian 12) | SSG's CIS Debian profile chooses **nftables** as the firewall. The owner requires **UFW**, so these "nftables path" checks fail by design. UFW rules, default deny inbound, and loopback rules are all in place. |
| `ufw_default_outgoing_rule` (Debian 13) | Requires outbound DROP. Real-time media and TURN relays send UDP to arbitrary peer ports, and DHCP lease renewal needs egress, so default-deny egress would break the server's purpose and risk a delayed lockout. Opt in with `UFW_OUTBOUND_POLICY=deny` (adds a DNS/DHCP/NTP/HTTP(S) allow-list plus `UFW_EXTRA_OUT`). |
| `package_chrony_installed` | The same profile sets `var_timesync_service = systemd-timesyncd`, and the two packages conflict. timesyncd is used; if chrony is already installed, the script keeps and configures chrony instead. |
| `journald_disable_forward_to_syslog` | Mutually exclusive with `journald_forward_to_syslog`. The rsyslog path is used (needed for the auditd `SYSLOG` alerts). |

## 3. Site-specific values the script cannot invent

| Rule | What is needed |
|---|---|
| `package_systemd-journal-remote_installed`, `systemd_journal_upload_url`, `systemd_journal_upload_server_tls`, `rsyslog_remote_tls` (Debian 13) | The address and CA of your enclave's log collector. Configure rsyslog (TLS via `rsyslog-gnutls`) or systemd-journal-upload once a collector is assigned. |
| `grub2_uefi_password` (UEFI hosts) | **SSG content defect for Debian:** the check reads `/boot/grub2/grub.cfg`, a RHEL path that never exists on Debian. The password *is* set (`/etc/grub.d/01_harden_password` → `/boot/grub/grub.cfg`, which the UEFI stub loads). This fails on every Debian UEFI host. |
| `aide_build_database` (Debian 12) | **SSG content defect for Debian 12:** the check parses the pre-0.17 key `database=` in `aide.conf`, while Debian 12's AIDE 0.18 uses `database_in=`. Rewriting the config to the deprecated key would add a deprecation warning to every AIDE run, so it is not done. The baseline database **is** built (`/var/lib/aide/aide.db`, asserted in CI), and Debian 13 passes. |
| `grub2_password` *(real hosts pass)* | A password is generated automatically, or you can supply `GRUB_PASSWORD_PBKDF2`. Only fails where GRUB cannot be regenerated (see §5). |

## 4. Install-time items (cannot be fixed on a running host)

| Rule | Note |
|---|---|
| `partition_for_home`, `partition_for_var`, `partition_for_var_log`, `partition_for_var_log_audit` | Separate filesystems must be created by the installer (Debian installer → "Separate /home, /var, and /tmp partitions" plus manual `/var/log` and `/var/log/audit`). |
| `/var/tmp` | Bind-mounted onto itself with `nodev,nosuid,noexec`, so the mount-option controls are genuinely enforced and `partition_for_var_tmp` passes. A bind mount does **not** provide space isolation. Create a real partition at install time to fully meet the intent. |

## 5. CI-environment limitations (pass on real hardware/VMs)

GitHub runners have no KVM, so CI hardens a systemd-booted container. These rules depend on a real kernel or bootloader and fail **only in CI**:

| Rule(s) | Reason in a container |
|---|---|
| `grub2_audit_argument`, `grub2_audit_backlog_limit_argument`, `grub2_enable_apparmor`, `grub2_password` | `update-grub` cannot probe an overlay root filesystem, so `/boot/grub/grub.cfg` is never generated. `/etc/default/grub` *is* correct, and the assertions verify it. |
| `service_auditd_enabled` | The kernel accepts only one audit daemon, in the initial PID namespace. |
| `service_timesyncd_enabled`, `ntp_single_service_active` | `systemd-timesyncd.service` has `ConditionVirtualization=!container`, so systemd skips it in any container. It is enabled and configured. |
| `all_apparmor_profiles_in_enforce_complain_mode` | AppArmor profiles cannot be loaded from inside a container. |
| `audit_rules_privileged_commands` | SSG enumerates setuid/setgid binaries only on "exec mount points" from the mount table. A container's overlay root `/` is not among them, so the scanner counts 0 binaries against the 18–19 generated rules. The rules exist and are compiled; the assertions verify sudo/su/passwd are covered. |
| `aide_*` (unprivileged local runs only) | AIDE ≥ 0.19 drops privileges with `capsh` and needs `CAP_SETPCAP`. |
| `sysctl_*` runtime values (unprivileged local runs only) | `/proc/sys` is read-only without `--privileged`. GitHub CI runs privileged. |

## 6. Hardening choices that are stricter than, or different from, a rule

| Topic | Choice |
|---|---|
| SSH key exchange | FIPS-approved only (ECDH NIST curves, DH group-exchange/14/16/18 SHA-2). The post-quantum hybrids `mlkem768x25519` and `sntrup761x25519` are excluded because they are not FIPS 140-3 approved. Revisit when CNSA 2.0 ML-KEM is validated. |
| SSH `LogLevel` | `INFO` (the value SSG checks). Set `SSH_LOGLEVEL=VERBOSE` to also log key fingerprints. |
| SSH passwords | Not disabled by default, because a host whose admins only have passwords would be locked out. `SSH_DISABLE_PASSWORD=1` verifies every sudo admin has a key first. |
| sudo `NOPASSWD` / `!authenticate` | Reported as warnings, never removed automatically, because on cloud images they are often the only sudo path. `sudo_require_authentication` fails until you remove them. |
| faillock | `deny=4`, `unlock_time=900`, including root. Lockouts expire; the STIG's permanent lock (`unlock_time=0`) is not used, because of the no-lockout policy. |
| OpenSSL | FIPS provider active **alongside** the default provider, as requested. Non-FIPS algorithms are still available to applications that ask for them. Set `FIPS_STRICT=1` for `default_properties = fips=yes`. System TLS is restricted to TLS ≥ 1.2 and NIST/FFDHE groups. |
| Kernel FIPS mode | `fips=1` enables the Debian kernel's FIPS self-tests and restrictions. Debian's kernel crypto API is **not** CMVP-validated; only the user-space OpenSSL 3.1.2 module (cert #4985) is. |
| `kernel.modules_disabled`, `lockdown=` | Not set: they would block DKMS/NVIDIA driver loading (requirement 6). Unneeded filesystems/protocols are blacklisted instead. |
| overlayfs | Disabled (CIS). Set `ALLOW_CONTAINERS=1` on Docker/Podman hosts. |
| IPv6 RA | Disabled unless the host relies on SLAAC/RA (auto-detected), in which case the `accept_ra` sysctls fail rather than cutting connectivity. |

## 7. ANSSI BP-028 High (informational profile)

ANSSI High is scanned and reported but **not gated**. Large parts of it assume a different platform:

* **SELinux** (Debian uses AppArmor), and **custom kernel build options** (`kernel_config_*`: GCC plugins, `MODULE_SIG_FORCE`, …) that only a self-built kernel can meet.
* **SSSD/LDAP** centralized identity, which is site-specific.
* Separate `/boot`, `/opt`, `/srv`, `/usr` partitions (install-time).
* `kernel.modules_disabled=1`, `mce=0`, `l1tf=full,force`, `mds=full,nosmt`. These are incompatible with NVIDIA/DKMS, or halve CPU capacity, or panic on machine checks (against the no-halt policy).
* `sudo` `noexec`/`requiretty`, which break package management and automation.

## 8. Ubuntu

Everything in sections 1–6 applies to Ubuntu as well (same owner-mandated auditd policy, install-time partitions, and CI-container limits). Ubuntu adds the following.

### 8.1 Content and platform decisions

| Topic | Decision |
|---|---|
| **Ubuntu 26.04 SCAP content** | SSG 0.1.82 (the newest ComplianceAsCode release, 2026-09-01) ships `ssg-ubuntu2604-ds.xml` as an empty skeleton with **no profiles**. The script therefore evaluates the **CIS Ubuntu 24.04 LTS Level 2 Server** benchmark on 26.04: a copy of the 24.04 datastream whose platform check (`DISTRIB_CODENAME` in `/etc/lsb-release`) accepts `resolute`. The summary says so (`content note:`), and the HTML report title still reads "Ubuntu 24.04". Disable with `SSG_CONTENT_FALLBACK=0`; re-pin `SSG_VERSION` when native 26.04 content is released. |
| **DISA STIG (Ubuntu)** | Reported for information only (`stig` profile, Canonical Ubuntu 22.04 STIG V2R7 / 24.04 STIG). It requires controls the owner rejected for availability (e.g. `admin_space_left_action = single`, permanent faillock lockout, auto-logout of every session) and site-specific items (SSSD/smart-card PKI, remote audit offload). The CIS L2 Server gate is the same on every OS. There is no 26.04 STIG. |
| **Ubuntu 22.04 OpenSCAP** | jammy packages only `libopenscap8` (oscap 1.2.17) and no `ssg-*`. That scanner is used with the pinned SSG 0.1.82 content (verified: 0 evaluation errors). |
| **sudo-rs (Ubuntu 25.10+)** | sudo-rs is the default `sudo` on 26.04, but it has no sudo log file and no I/O logging (`logfile`, `log_input`, `log_output` and `iolog_dir` are rejected). Classic sudo (`sudo.ws`, still installed) is selected through `update-alternatives` after the existing policy validates under it. `SUDO_PROVIDER=keep` keeps sudo-rs; then only the settings it accepts are written, and the sudo logging rules fail. |
| **snapd** | Not removed. Cloud management agents (e.g. the AWS SSM agent on Ubuntu AMIs) ship as snaps, so removing snapd can cut the only management path. Remove it manually where it is not needed. |
| **Ubuntu Pro FIPS** | If `pro status` shows `fips`/`fips-updates` enabled, Canonical's certified modules and kernel are kept and the OpenSSL 3.1.2 provider is not built or configured. Two FIPS providers are never stacked. |
| **AppArmor profiles shipped disabled** | Ubuntu disables some profiles on purpose (`/etc/apparmor.d/disable`). They are loaded in **complain** mode (confined and logged) rather than enforced, which satisfies "enforce or complain" without breaking a service the vendor chose not to enforce. |
| **apport** | Purged when no other installed package depends on it. If a metapackage depends on it, it is disabled and masked (`/etc/default/apport enabled=0`) instead; metapackages are never removed. |

### 8.2 Rules that remain failing on Ubuntu (CI, privileged)

All three releases fail the same core set. It falls into the categories already described for Debian:

| Rule(s) | 22.04 | 24.04 | 26.04 | Category |
|---|---|---|---|---|
| `auditd_data_disk_full_action`, `auditd_data_retention_{admin_space_left,max_log_file,space_left}_action` | ✗ | ✗ | ✗ | Owner-mandated (§1) |
| `partition_for_{home,var,var_log,var_log_audit}` | ✗ | ✗ | ✗ | Install-time (§4) |
| `package_ufw_removed` | ✗ | ✗ | ✗ | Profile conflict: the nftables path of the benchmark; UFW is mandated (§2) |
| `set_ufw_default_rule` | ✗ | ✗ | ✗ | Requires default-deny **outbound**: same decision as Debian's `ufw_default_outgoing_rule` (§2). Opt in with `UFW_OUTBOUND_POLICY=deny` |
| `ufw_rules_for_open_ports` | ✗→✓ | ✗→✓ | ✗→✓ | Fixed, see §8.3 |
| `aide_build_database` | ✗ | ✗ | ✗ | **SSG content defect** (as on Debian 12, §3): the check derives the database path from the pre-0.17 `database=` key; Ubuntu's AIDE uses `database_in=`. The baseline database is built (`/var/lib/aide/aide.db`) |
| `grub2_password`, `grub2_uefi_password`, `grub2_audit_argument`, `grub2_audit_backlog_limit_argument`, `grub2_enable_apparmor` | ✗ | ✗ | ✗ | CI container only: `/boot/grub/grub.cfg` is never generated (§5). `/etc/default/grub` and the password drop-in are asserted |
| `service_auditd_enabled`, `service_timesyncd_enabled`, `ntp_single_service_active`, `all_apparmor_profiles_in_enforce_complain_mode` | ✗ | ✗ | ✗ | CI container only (§5) |
| `service_timesyncd_configured` | ✓ | ✗→✓ | ✗→✓ | Fixed: on Ubuntu without `NTP_SERVERS`, timesyncd uses the pool servers the 24.04 benchmark lists as approved (`NTP=0-3.pool.ntp.org`), and `FallbackNTP` starts with `time.nist.gov` (the value the 22.04 profile approves), then `ntp.ubuntu.com`. When you set `NTP_SERVERS` to your enclave's servers, this rule reports them as unapproved unless the profile value is tailored |
| `ensure_root_access_controlled` | ✗ | ✓ | ✓ | 22.04 content requires a root **password hash**. Root stays locked and administrators use sudo, which is stricter; the 24.04 content accepts a locked root |
| `journald_disable_forward_to_syslog` | ✗ | – | – | Profile-internal conflict (§2) |
| `audit_rules_privileged_commands` | ✗ | ✓ | ✓ | CI container only (§5) |
| `set_ufw_loopback_traffic`, `no_files_unowned_by_user` (+ the two UFW rules above) | error | – | – | **Scanner limit**: jammy's oscap 1.2.17 cannot run these SCE/OVAL checks and reports `error`. The loopback rules are in place and asserted |

### 8.3 `ufw_rules_for_open_ports`: a real defect, fixed

The check requires a UFW rule for every non-loopback listener. Inspection of a hardened 24.04 host showed **rpcbind's socket (port 111) still listening** after the script had purged rpcbind. The package's own "stop" was suppressed (a `policy-rc.d`, present in container images and some image-build pipelines), and the script only disabled units whose unit file still existed. UFW kept blocking the port inbound, but a removed service must not keep a socket open. `disable_service` now also stops a unit that is still active after its unit file is gone, the CI image no longer carries `policy-rc.d`, and an assertion verifies nothing listens on port 111. The fix applies to Debian as well.

## 9. Workstation mode (`HARDEN_PROFILE=workstation`)

The gate is **CIS Ubuntu 24.04 Level 2 – Workstation** (`cis_level2_workstation`). In SSG 0.1.82 it selects the Server profile's rules except `package_gdm_removed`, `package_xorg` and `wireless_disable_interfaces`, so every exception in sections 1–8 applies unchanged. The workstation adds:

| Rule | Why it fails | Compensating control |
|---|---|---|
| `dconf_gnome_login_banner_text` | The CIS profile's check accepts exactly the text "Authorized uses only. All activity may be monitored and reported." The GDM login screen shows the same **DoD Notice and Consent banner** as `/etc/issue` (STIG), which that check does not accept. Set `BANNER_FILE` to the CIS sentence if your site requires the CIS wording instead. | The banner is enabled and locked (`dconf_gnome_banner_enabled` passes) |
| `service_bluetooth_disabled` *(only with `WORKSTATION_BLUETOOTH=on`)* | Bluetooth headsets are needed on some laptops. By default the service is disabled and the rule passes; `on` is the site's documented choice. | BlueZ only pairs with user consent; `usb-storage` stays blacklisted |

| `sshd_limit_user_access` *(only with `ADMIN_ACCESS=none`)* | **SSG content defect:** with `openssh-server` removed there is no `sshd_config` and every other `sshd_*` rule is `notapplicable`, but this one still evaluates and fails because it finds no `AllowUsers`/`AllowGroups` line in a file that does not exist. | There is no SSH server, no listener on port 22 and no UFW rule for it (asserted in CI) |

Measured locally (rootless Podman, unprivileged, Ubuntu 24.04, `HARDEN_PROFILE=workstation ADMIN_ACCESS=none`): **CIS L2 Workstation 93.10%** (432 pass, 32 fail, 43 not applicable; DISA STIG 73.52% informational). The unprivileged run also fails the runtime `sysctl_*` rules of §5, which pass in privileged CI, so CI's figure is higher. Every other failure is one of §1–§5 or the table above.
