# linux-minimal-secure

`harden-and-audit.sh` is a single, unattended Bash script. It turns a stock server install into a minimal, FIPS-ready, CIS Level 2 / STIG-aligned headless server, then audits itself with **OpenSCAP**. It writes a machine-readable XML result and a standalone HTML report. The distribution is **detected**; there is one script for all of them:

| Family | Releases |
|---|---|
| Debian | **Debian 12 (bookworm)**, **Debian 13 (trixie)**, **Ubuntu 22.04 / 24.04 / 26.04 LTS** |
| RHEL | **RHEL**, **CentOS Stream**, **Rocky Linux**, **AlmaLinux**, **Oracle Linux**: releases **8, 9 and 10** (any distribution with `ID_LIKE=rhel`), and **Fedora 41+** (server and Workstation) |
| Hypervisor | **Proxmox VE 8 (Debian 12) and 9 (Debian 13)**: detected automatically (see below) |

**Servers and desktops.** When a display manager is installed (GDM, SDDM, LightDM …), the script runs in **desktop mode**: it hardens the machine without breaking the desktop. The graphical session, printing, Bluetooth, USB drives, network discovery (mDNS) and toolbox/podman keep working; sshd stays off if it was off; terminals get no idle timeout (the screen lock covers that); the gate profile is CIS Level 2 **Workstation**. Force it with `DESKTOP_MODE=1`, or harden a desktop as a server with `DESKTOP_MODE=0`.

**Proxmox VE nodes.** When `pve-manager` is installed the script runs in **Proxmox mode** and keeps everything a node and its cluster need:

* **Root stays usable.** Root keeps SSH: cluster join, live and secure migration, replication and the node shell all run as root over SSH. With a non-root sudo admin present it is `PermitRootLogin prohibit-password` (keys only); otherwise `yes`. Root keeps TCP and unix-socket forwarding for migration tunnels; other users don't. Root's password is exempt from expiry and inactivity locking, because an expired root password breaks key-based cluster logins and `root@pam` in the web UI.
* **Firewall.** pve-firewall stays the firewall and UFW is never installed. With `PVE_FIREWALL_ENABLE=1` the datacenter firewall is turned on, with SSH and port 8006 allowed first and existing rules kept.
* **Repositories.** Without a subscription, the enterprise repositories (which return HTTP 401) are swapped for the no-subscription ones, so updates keep working.
* **Kernel, boot and banner.** IP forwarding is left to the node's network setup. rpcbind (NFS storage), dnsmasq (SDN DHCP), postfix and overlayfs stay. No kernel `fips=1` (Proxmox doesn't support it; user-space FIPS stays). `/etc/kernel/cmdline` and `proxmox-boot-tool refresh` are handled. `pvebanner` no longer overwrites the login banner.
* **Hands off guest data.** VM disks, container subvolumes, backup and NFS storage and the volatile parts of `/etc/pve` are never scanned, chmod-ed or checksummed. Failed web UI logins get a fail2ban jail, and cluster peers are never banned.

**Container and Kubernetes hosts (every distribution).** Docker, containerd, rootful Podman and Kubernetes (kubeadm, k3s, RKE2, k0s, MicroK8s) are detected **before** anything changes, so hardening never breaks them:

* **Networking.** IP forwarding stays on, overlayfs stays loaded, and routed container traffic and container/CNI interfaces are allowed through UFW/firewalld.
* **Kubernetes.** Nodes also get the cluster and CNI ports (API server, etcd, kubelet, NodePorts, VXLAN/Geneve/WireGuard/BGP), trusted pod/service networks, loose `rp_filter`, and gratuitous ARP for floating VIPs. SELinux is never raised from permissive on a Kubernetes node.
* **Container storage.** Image layers, container root filesystems and etcd are never scanned, chmod-ed or checksummed.

Set `K8S_TRUSTED_CIDRS` to restrict the cluster ports to your node network.

| | |
|---|---|
| Gate profile | **CIS Level 2 – Server** for the running OS (`cis_level2_server` on Debian/Ubuntu, `cis` on the RHEL family). Target pass rate ≥ 90%, enforced in CI on every target below |
| Measured in CI (v2.1.0) | Debian 12: **94.24%** · Debian 13: **94.80%** · Ubuntu 22.04: **94.17%** · 24.04: **95.18%** · 26.04: **95.18%** · Rocky 8: **95.12%** · 9: **95.73%** · 10: **94.69%** · AlmaLinux 8: **95.12%** · 9: **95.73%** · 10: **94.93%** · CentOS Stream 9: **95.73%** · 10: **94.69%** · Fedora 44: **93.95%** · 45: **93.95%** · Fedora 45 GNOME desktop (Workstation profile): **92.40%** (every remaining failure is explained in [docs/EXCEPTIONS.md](docs/EXCEPTIONS.md)) |
| Also reported | Debian: ANSSI BP-028 High. Ubuntu and RHEL family: **DISA STIG**. Informational; see [docs/EXCEPTIONS.md](docs/EXCEPTIONS.md) |
| FIPS | Debian family: kernel `fips=1` plus the **NIST CMVP validated OpenSSL 3.1.2 FIPS provider (FIPS 140-3, cert #4985)**, active alongside the default provider. RHEL family: the distribution's own FIPS module (`fips-mode-setup` on 8/9; crypto policy `FIPS` + `fips=1` on 10) |
| Reports | `/var/log/scap-results.xml`, `/var/log/scap-report.html`, `/var/log/scap-summary.txt` |

> **About STIGs.** DISA does not publish a STIG for Debian, so no Debian STIG SCAP profile exists. DISA does publish STIGs for Ubuntu 22.04 and 24.04; CI scans and reports them. On every OS the gate is the CIS Level 2 Server benchmark, and the DoD-specific STIG controls are implemented natively: the DoD Notice & Consent banner (opt-in, `BANNER_STYLE=dod`), FIPS cryptography, FIPS-only SSH algorithms, the STIG audit rule set, account lockout, and session lock.
>
> **About RHEL.** Red Hat Enterprise Linux needs a subscription, so public CI tests its rebuilds (Rocky Linux and AlmaLinux 8/9/10, CentOS Stream 9/10), which take the identical code path. On RHEL the script additionally checks that a repository is enabled (register with `subscription-manager` first) and installs EPEL from the Fedora project.
>
> **About Ubuntu 26.04.** SSG 0.1.82 (the newest ComplianceAsCode release) ships only an empty Ubuntu 26.04 datastream. On 26.04 the script scans with the CIS Ubuntu 24.04 L2 content, retargeted to 26.04, and says so in the summary. See [docs/EXCEPTIONS.md](docs/EXCEPTIONS.md#8-ubuntu).

## Quick start

```bash
# Download a release from the "main" release line and verify it
curl -fsSLO https://github.com/MicroHealthLLC/linux-minimal-secure/releases/latest/download/harden-and-audit.sh
curl -fsSLO https://github.com/MicroHealthLLC/linux-minimal-secure/releases/latest/download/harden-and-audit.sh.sha256
sha256sum -c harden-and-audit.sh.sha256

# Prerequisite: a NON-ROOT administrator in the sudo group (Debian/Ubuntu) or the
# wheel group (RHEL family) with an SSH key or password. The script refuses to
# run without one, because it disables root SSH login. (Proxmox VE nodes keep
# root SSH for the cluster, so there it is recommended, not required.)
sudo bash harden-and-audit.sh
sudo reboot     # activates fips=1, audit=1, SELinux enforcing (EL) and the other kernel arguments
```

Re-run only the compliance scan at any time with `sudo harden-and-audit.sh --scan-only`. A weekly `scap-audit.timer` does the same thing automatically.

## Anti-lockout guarantees

The script is built so you cannot lose access to the server:

1. **Preflight before any change.** It aborts unless a non-root `sudo` (Debian family) or `wheel` (RHEL family) member with an SSH key or password exists. It also detects the real SSH port(s), and detects IPv6 SLAAC so RA is not disabled when the host depends on it.
2. **auditd can never stop the box.** `max_log_file = 20`, `max_log_file_action = ROTATE`, and every space/disk action is `SYSLOG`. The script refuses to finish if `SUSPEND`, `SINGLE` or `HALT` appear anywhere in `auditd.conf`. The kernel audit failure mode is `-f 1` (log), never `-f 2` (panic).
3. **sshd is validated first.** The new `sshd_config` must pass `sshd -t` before it replaces the old one. sshd is *reloaded*, so existing sessions survive. All existing interactive users are added to `ssh-users` (`AllowGroups`).
4. **OpenSSL is validated first.** The new `openssl.cnf` is tested through `OPENSSL_CONF=<candidate>` (FIPS and default providers active, `sshd -t`) before activation. A broken FIPS include would otherwise break every TLS/SSH consumer.
5. **The firewall allows SSH before it is enabled.** UFW / firewalld only default to deny *inbound*. Outbound stays open unless you opt in with `FIREWALL_OUTBOUND_POLICY=deny`, which also adds a DHCP/DNS/NTP/HTTP(S) allow-list.
6. **Lockouts are temporary.** `pam_faillock` auto-unlocks after 15 minutes. Password aging is not applied to an account whose password is already older than `PASS_MAX_DAYS`, because that would expire it on the spot.
7. **GRUB password protects editing, not booting.** Menu entries are `--unrestricted`, so unattended reboots keep working.
8. **NOPASSWD sudo rules are reported, not removed.** On cloud images they are often the only working sudo path.
9. **SELinux is never enforced on an unlabelled system.** A RHEL-family host that booted with SELinux *disabled* is set to `permissive` with a full relabel at the next boot; re-running the script after that reboot switches it to `enforcing`.
10. **Nothing stops, hangs or reboots the machine** (these are console-less cloud VMs). auditd only alerts on full or failing disks, audit failure mode is `-f 1` (never panic), audit logs rotate at 20 MB × 10, a full kernel audit backlog drops records instead of blocking processes (`--backlog_wait_time 0`), every fstab line the script adds carries `nofail` (no emergency mode at boot), `/var/log` has a hard budget, and automatic updates never reboot.

The CI proves #3: after hardening, the sudo admin must still log in over SSH with a key, and root must be refused.

## What the script does

The table describes the Debian family; the RHEL-family equivalents follow it.

| Area | Implementation |
|---|---|
| Minimalism | `APT::Install-Recommends/Suggests "false"`. Dependency-aware purge of display managers, desktops, X servers, toolkits, and X11/Wayland/Mesa libraries (never removes a non-graphical package that links to them). Removes telnet/rsh/tftp/NIS/inetd/avahi/cups/rpcbind/etc. |
| Repositories | Debian: deb822 `debian.sources` → `<codename>`, `-updates`, `-security` (`main contrib non-free non-free-firmware`). Ubuntu: deb822 `ubuntu.sources` → `<codename>`, `-updates`, `-security` (`main restricted universe multiverse`); the configured (cloud/regional/private) mirror is kept. Third-party repositories are never touched |
| Base stack | openssh-server, tmux, curl, git, ufw, fail2ban, libpam-pwquality, auditd, unattended-upgrades (+ sudo, rsyslog, AIDE, AppArmor, timesyncd, vlock) |
| Updates | **Mandatory, no opt-out.** unattended-upgrades applies Debian-Security / Ubuntu `-security` (+ ESM when Pro-attached) daily, keeps local conffiles, never auto-reboots. The apt timers are unmasked and enabled, a last-read `zz-harden-auto-upgrades` stops other `apt.conf.d` files from turning updates off, and the run fails on a host where the effective config or the timers are not active |
| auditd | Owner policy above, plus the full CIS/STIG rule set (time, identity, network, MAC, logins, sessions, DAC, failed access, mounts, deletions, modules, setuid/setgid exec, sudoers, privileged commands generated from disk), immutable `-e 2` |
| FIPS | `fips=1` in `GRUB_CMDLINE_LINUX` + `update-grub`. OpenSSL 3.1.2 FIPS provider built from the SHA-256-pinned source per its Security Policy into `/opt/openssl-fips-3.1.2`. `openssl.cnf` activates `fips` **and** `default` (strict `fips=yes` is opt-in with `FIPS_STRICT=1`). TLS ≥ 1.2. On Ubuntu with **Ubuntu Pro FIPS** enabled, Canonical's certified modules are kept and the 3.1.2 build is skipped |
| Kernel cmdline | `audit=1 audit_backlog_limit=8192 apparmor=1 security=apparmor slab_nomerge=yes pti=on page_alloc.shuffle=1 vsyscall=none init_on_alloc=1 spectre_v2=on spec_store_bypass_disable=seccomp rng_core.default_quality=500` |
| Files | passwd/group 0644 root:root, shadow/gshadow 0640 root:shadow, backups, cron, sshd keys, grub.cfg 0400, audit config, logs, home directories 0750, world-writable cleanup |
| sysctl | No forwarding, redirects, or source routing. rp_filter, martian logging, syncookies, RA off (when safe), ASLR, kptr/dmesg restrict, ptrace scope, BPF hardening, protected links/fifos, no setuid core dumps. Conflicting vendor values (Ubuntu `rp_filter=2`, `sysrq=176`, `protect-links` ordering) are neutralised so they cannot win at boot |
| SSH | No root, no X11/TCP/agent forwarding, `MaxAuthTries 4`, `ClientAliveInterval 300` × 3, `LoginGraceTime 60`, `AllowGroups ssh-users`, login banner, FIPS-approved ciphers/MACs/KEX only, moduli ≥ 3071 bits |
| Firewall | UFW default deny inbound/routed, SSH allowed, loopback rules, logging, enabled with `--force` |
| Accounts | pwquality (15 chars, 4 classes, dictcheck, enforce for root), history 24, faillock (4 tries / 15 min), yescrypt, aging, inactivity 45 days, umask 027, `TMOUT=900`, su limited to the empty `sugroup`, sudo `use_pty` + logfile + I/O logging (Ubuntu 26.04: classic sudo is selected over sudo-rs, which has no log file or I/O logging) |
| Ubuntu extras | apport / whoopsie / popularity-contest removed (or disabled where a metapackage depends on them), motd-news off, `/etc/netplan` audited, distro-disabled AppArmor profiles loaded in complain mode, socket-activated sshd handled. snapd is kept (cloud agents ship as snaps) |
| Other | Login warning banner (generic; DoD text opt-in), kernel module blacklist (cramfs, udf, usb-storage, dccp, sctp, rds, tipc, overlay…), `/tmp` `/var/tmp` `/dev/shm` nodev/nosuid/noexec, no core dumps, journald persistent + bounded, rsyslog 0640 + no listeners, logrotate hourly (daily/14/compress/100M cap) + hard `/var/log` budget (4G, 15% disk free) that prunes the oldest rotated archives, NTP, AppArmor enforce, AIDE + daily timer, fail2ban, local-only MTA, Ctrl-Alt-Del masked, tmux lock |
| CUDA | `libc6 libc6-dev gcc make build-essential pkg-config dkms` + kernel headers (`linux-headers-amd64` on Debian; on Ubuntu the headers of every installed kernel flavour, e.g. `linux-headers-generic`/`-virtual`/`-aws`) + running kernel headers, nouveau blacklisted, initramfs (or dracut) regenerated. The NVIDIA driver itself is not installed. |
| coturn / media | Runtime libraries only, with **no coturn and no X11**: libevent (+openssl/pthreads/extra), hiredis, mariadb, pq, sqlite, ssl, systemd, microhttpd, opus, vpx, srtp2, x264, x265, aom, dav1d, ogg, vorbis, speex, webp, theora, flac, lame, sndfile, samplerate, soxr, gsm, usrsctp, jansson, libconfig, websockets, curl. Large UDP socket buffers via sysctl. |
| OpenSCAP | Debian: `openscap-scanner`, `openscap-utils`, `ssg-debian`. Ubuntu 24.04/26.04: `openscap-scanner`, `openscap-utils`, `ssg-debderived`. Ubuntu 22.04: `libopenscap8` (the only OpenSCAP jammy packages). Scans with the SHA-512-pinned SSG 0.1.82 datastream (the distro packages are older or lack the content), falling back to packaged content offline |

### RHEL family (RHEL, CentOS Stream, Rocky Linux, AlmaLinux, Oracle Linux 8/9/10)

| Area | Implementation |
|---|---|
| Minimalism | `dnf.conf`: `install_weak_deps=False`, `gpgcheck=1`, `localpkg_gpgcheck=1`, and `gpgcheck=0` is turned on in every repository. Dependency-aware removal of X11/desktop/Mesa packages (`rpm -e --test`: a package another one requires is kept), legacy services, abrt, setroubleshoot, mcstrans |
| Repositories | Vendor BaseOS/AppStream kept as configured, CRB/PowerTools + EPEL enabled (`EPEL_ENABLE=0` stays vendor-only; fail2ban and dkms then are skipped). Fatal if no repository is enabled |
| Updates | **Mandatory, no opt-out.** `dnf-automatic` with `apply_updates = yes` and `upgrade_type = security` (CentOS Stream publishes no errata, so all updates there). `dnf-automatic.timer` is unmasked, enabled and must be active |
| FIPS | The distribution's module: `fips-mode-setup --enable` (8/9), crypto policy `FIPS` + `fips=1` (10). No second, self-built provider |
| Kernel cmdline | `grubby --update-kernel=ALL` + `GRUB_CMDLINE_LINUX`: the same hardening arguments **without** AppArmor (`security=apparmor` would disable SELinux), `selinux=0`/`enforcing=0` removed, `boot=UUID=` for FIPS with a separate `/boot`. GRUB 2 password in `/boot/grub2/user.cfg` |
| MAC | SELinux `enforcing` / `targeted` |
| Firewall | firewalld: default zone `public` with only SSH (and DHCPv6 client), cockpit closed, loopback anti-spoofing rich rules; optional egress allow-list (policy object) |
| SSH | Same settings, `sshd.service`; ciphers/MACs/KEX come from the system crypto policy (CIS requires sshd_config not to override it) |
| Accounts | authselect profile `custom/harden` (from `sssd`, or `local` on EL10) with faillock, password history 24, no nullok; SHA512 hashing; shadow files `0000 root:root` |
| Time / cron / logs | chronyd (`-u chrony`), crond, logrotate hourly (EL8: the script ships `logrotate.{service,timer}`) + the same `/var/log` budget |
| AIDE | `/etc/aide.conf` (audit tools, bulk excludes in a managed block), `aide --init` → `aide.db.gz`, daily `aidecheck.timer` |
| CUDA | `gcc make kernel-devel kernel-headers elfutils-libelf-devel pkgconf-pkg-config dkms` |
| coturn / media | RPM names from vendor + EPEL. x264/x265 (RPM Fusion only) and usrsctp on 10 are reported as unavailable |
| OpenSCAP | `openscap-scanner` + the vendor's `scap-security-guide`: `ssg-rl*` (Rocky), `ssg-almalinux*`, `ssg-cs*` (CentOS Stream), `ssg-rhel*`, `ssg-ol*` |

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `SCAP_PROFILE` | `cis_level2_server` (Debian family) / `cis` (RHEL family) | Gate profile |
| `SCAP_EXTRA_PROFILES` | *(empty)* | Additional profiles, e.g. `anssi_bp28_high standard` |
| `SCAP_MIN_SCORE` / `SCAP_ENFORCE_MIN` | `90` / `1` | Exit 3 when the gate profile's pass rate is below the threshold |
| `SSG_DOWNLOAD` / `SSG_DATASTREAM` | `1` / *(empty)* | Offline/air-gapped: set `SSG_DOWNLOAD=0` and point `SSG_DATASTREAM` at a staged `ssg-debian12-ds.xml` / `ssg-ubuntu2404-ds.xml` |
| `FIPS_OPENSSL_URL` | GitHub release URL | Point at an internal mirror; the SHA-256 pin is still enforced |
| `FIPS_STRICT` | `0` | `1` = `default_properties = fips=yes` (non-FIPS algorithms unavailable system-wide) |
| `DEBIAN_MIRROR` / `DEBIAN_SECURITY_MIRROR` | deb.debian.org / security.debian.org | Internal mirrors (Debian) |
| `UBUNTU_MIRROR` / `UBUNTU_SECURITY_MIRROR` | *(the mirror already configured)*, else archive/security (amd64) or ports.ubuntu.com | Internal mirrors (Ubuntu) |
| `NTP_SERVERS` / `NTP_FALLBACK_SERVERS` | Debian pool / time.nist.gov. Ubuntu: vendor chrony sources (NTS), or for timesyncd `0-3.pool.ntp.org` with `time.nist.gov ntp.ubuntu.com` fallback | Use your enclave's time sources |
| `SUDO_PROVIDER` | `classic` | Ubuntu 25.10+: `classic` selects `sudo.ws` (log file + I/O logging), `keep` leaves sudo-rs and writes only the settings it accepts |
| `SSG_CONTENT_FALLBACK` | `1` | Scan a release that has no native SSG content (Ubuntu 26.04) with the newest older Ubuntu LTS content, retargeted |
| `PASS_MAX_DAYS` | `365` | DoD sites commonly use `60` |
| `FAILLOCK_DENY` / `FAILLOCK_UNLOCK_TIME` | `4` / `900` | Temporary lockout |
| `SHELL_TMOUT` | `900` | Idle shell timeout and tmux lock (seconds) |
| `ALLOW_CONTAINERS` | `auto` | `auto` = on when Docker, containerd, rootful Podman or Kubernetes is found: keeps overlayfs, IP forwarding, routed container traffic and container/CNI interfaces. `1` force (set it **before** installing a runtime on an already-hardened host), `0` off |
| `KUBERNETES_MODE` | `auto` | `auto` = on when kubelet, k3s, RKE2, k0s or MicroK8s is found: cluster/CNI ports, trusted pod/service networks, loose rp_filter, SELinux mode not raised. `1` force, `0` off |
| `K8S_TRUSTED_CIDRS` | *(empty)* | Node/management networks allowed to reach the cluster ports (API server, etcd, kubelet, CNI). Empty = any source (a warning is printed) |
| `K8S_EXTRA_PORTS` | *(empty)* | More inbound ports on Kubernetes nodes, e.g. `"9100/tcp 7946/tcp 7946/udp"` (node exporter, MetalLB) |
| `PROXMOX_MODE` | `auto` | `auto` = Proxmox mode when `pve-manager` is installed; `1` force; `0` treat the node as plain Debian (not recommended) |
| `PVE_ROOT_SSH` | `auto` | Proxmox: `auto` = `prohibit-password` when a non-root sudo admin exists, else `yes`; or set `yes` / `prohibit-password` |
| `PVE_ROOT_PASSWORD_FROM` | *(empty)* | Proxmox: CIDRs (comma or space separated, e.g. `192.168.0.0/16`) root may still SSH from with a password (`Match User root Address …` → `PermitRootLogin yes`). Everywhere else root stays key-only. Empty = no exception, and the run warns when root ends up key-only |
| `PVE_REPO` | `auto` | Proxmox: `auto` = enterprise repositories with an active subscription, otherwise no-subscription; `enterprise`, `no-subscription` or `keep` (leave the repositories alone) |
| `PVE_FIREWALL_ENABLE` | `0` | Proxmox: `1` turns the datacenter firewall on (SSH and 8006 accept rules first, existing rules kept). **Cluster-wide** setting |
| `PVE_FIREWALL_MGMT_SOURCE` | *(empty)* | Proxmox: source CIDR(s) for those SSH/8006 rules (empty = any) |
| `PVE_KERNEL_FIPS` | `0` | Proxmox: `1` also boots the node with `fips=1` (unsupported by Proxmox; may keep corosync out of quorum) |
| `KEEP_IPV6_RA` | `auto` | `auto` keeps RA when SLAAC is in use |
| `FIREWALL_OUTBOUND_POLICY` / `FIREWALL_EXTRA_OUT` | `allow` / *(empty)* | `deny` + allow-list for egress filtering (UFW or firewalld). The old names `UFW_OUTBOUND_POLICY` / `UFW_EXTRA_OUT` still work |
| `EPEL_ENABLE` | `1` | RHEL family: enable CRB/PowerTools + EPEL (fail2ban, dkms, some media libraries). Not used on Fedora |
| `DESKTOP_MODE` | `auto` | `auto` = desktop mode when a display manager is installed; `1` force; `0` harden as a server |
| `FAIL2BAN_IGNOREIP` | *(empty)* | Jump hosts that must never be banned |
| `SSH_DISABLE_PASSWORD` | `0` | `1` = key-only SSH (verified for every sudo admin first) |
| `ENABLE_GRUB_PASSWORD` / `GRUB_PASSWORD_PBKDF2` | `1` / *(generated)* | Supply your own `grub.pbkdf2.sha512…` hash; otherwise one is generated into `/root/grub-superuser-password.txt` |
| `AIDE_INIT` | `1` | Build the AIDE baseline at the end |
| `PROGRESS_INTERVAL` | `60` | Seconds between progress lines during the AIDE and OpenSCAP steps |
| `LOG_MAX_TOTAL` | `4G` | Hard cap for `/var/log`: after every hourly logrotate run, the oldest *rotated* archives are pruned (never live logs; the journal is capped at 512M by journald). Logs are expected to be shipped off-host |
| `LOG_MIN_FREE_PCT` | `15` | Also prune while the `/var/log` filesystem has less free space than this, so logs can never fill the disk |
| `LOG_ROTATE_KEEP` / `LOG_MAXSIZE` | `14` / `100M` | Rotated generations per log / size that triggers rotation at the next hourly run |
| `BANNER_STYLE` | `generic` | `generic` = authorized-use / monitoring / no-privacy notice suitable for any company or agency; `dod` = DoD Notice and Consent banner (USG systems only, matches the DISA STIG check text) |
| `BANNER_ORG` | *(empty)* | Organization named in the generic notice, e.g. `BANNER_ORG="Example Corp"` (empty = "the owner of this system") |
| `BANNER_FILE` | *(empty)* | Path to your own banner text; overrides `BANNER_STYLE` |

## Progress output

Every step header shows where the run is and how long it has taken:

```
2026-11-21T17:28:24Z [STEP 41/44] ===== AIDE baseline database (final state) ===== (run time 38m12s)
```

The two long steps print a status line every `PROGRESS_INTERVAL` seconds (60 by default):

```
[INFO ] AIDE baseline: 6m00s elapsed - ~41% (3.2G of ~7.8G read), ~8m37s left, reading /usr/lib/x86_64-linux-gnu/libLLVM.so.19
[INFO ] OpenSCAP cis_level2_server: 3m00s elapsed - 214/507 rules (42%), ~4m06s left, last: Ensure auditd Collects ...
```

AIDE's percentage compares data read against disk space in use, minus the bulk paths AIDE skips (container, VM and snap storage, caches, and home directories apart from the shell/login dotfiles, `.gitconfig`, `.ssh`, `.config/autostart`, systemd user units and `.local/bin`). AIDE has other exclusions too, so the estimate reads low and the time left errs long. AIDE's full output is in `/var/log/harden-and-audit-aideinit.log`.

## CI and releases

* **`integration`** is the default branch. Every push and PR runs [`ci.yml`](.github/workflows/ci.yml):
  1. `bash -n` + ShellCheck.
  2. A Debian 12 / 13, Ubuntu 22.04 / 24.04 / 26.04, Rocky Linux 8 / 9 / 10, AlmaLinux 8 / 9 / 10, CentOS Stream 9 / 10, Fedora 44 / 45 and Fedora 45 GNOME desktop matrix. The script runs inside a systemd-PID-1 container that looks like a netinst server (kernel, GRUB, an admin user, seeded GUI/legacy packages). The container markers are removed so OpenSCAP scores the full *machine* ruleset rather than skipping it as "container". Ubuntu 26.04 runs on its default uutils (Rust) coreutils.
  3. `tests/assertions.sh` verifies every requirement functionally (auditd policy, FIPS provider, SSH key login still works, root refused, purge, libraries, reports …).
  4. The script runs a **second time** to prove idempotence.
  5. **Gate:** the CIS L2 Server pass rate must be ≥ 90%. The XML/HTML/summary reports are uploaded as build artifacts, and the score table is posted to the job summary.
* **`main`** is the release line. A merge to `main` re-runs the full CI and then [`release.yml`](.github/workflows/release.yml) publishes `v<VERSION>` with `harden-and-audit.sh`, its `.sha256`, and the CI compliance reports. Bump `VERSION` and `SCRIPT_VERSION` together to cut a new release.

Run the same test locally (Docker required). The local mode never uses `--privileged`, so your workstation's kernel is untouched:

```bash
tests/run-ci.sh debian 12
tests/run-ci.sh debian 13
tests/run-ci.sh ubuntu 22.04
tests/run-ci.sh ubuntu 24.04
tests/run-ci.sh ubuntu 26.04
tests/run-ci.sh rocky 9          # also: rocky 8|10, almalinux 8|9|10, centos 9|10 (Stream), fedora 44|45
tests/run-ci.sh fedora 45 desktop   # GNOME desktop: proves desktop mode keeps the desktop
tests/run-ci.sh debian 12 proxmox   # Proxmox VE 8 look-alike (also: debian 13 proxmox = PVE 9)
tests/run-ci.sh ubuntu 24.04 k8s    # Docker + kubeadm node: containers must still run (privileged CI only)
tests/run-ci.sh rocky 9 k8s         # Podman + kubeadm node on the RHEL family
```

## Documentation

* [docs/PLAN.md](docs/PLAN.md): analysis and implementation plan (Debian)
* [docs/PLAN-UBUNTU.md](docs/PLAN-UBUNTU.md): analysis and implementation plan for Ubuntu 22.04 / 24.04 / 26.04
* [docs/PLAN-RHEL.md](docs/PLAN-RHEL.md): analysis and implementation plan for the RHEL family and the linux-minimal-secure rename
* [docs/PLAN-PROXMOX-CONTAINERS.md](docs/PLAN-PROXMOX-CONTAINERS.md) / [docs/GAP-ANALYSIS-PROXMOX-CONTAINERS.md](docs/GAP-ANALYSIS-PROXMOX-CONTAINERS.md): Proxmox VE nodes, container and Kubernetes hosts (plan and delivery)
* [docs/EXCEPTIONS.md](docs/EXCEPTIONS.md): deviations from CIS/ANSSI/STIG and the reason for each
* [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md) / [docs/GAP-ANALYSIS-UBUNTU.md](docs/GAP-ANALYSIS-UBUNTU.md) / [docs/GAP-ANALYSIS-RHEL.md](docs/GAP-ANALYSIS-RHEL.md): what was delivered against each plan
