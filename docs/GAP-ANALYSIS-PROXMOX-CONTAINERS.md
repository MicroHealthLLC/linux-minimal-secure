# Gap analysis: Proxmox VE, container and Kubernetes hosts (v2.2.0)

This compares what was delivered against [PLAN-PROXMOX-CONTAINERS.md](PLAN-PROXMOX-CONTAINERS.md).

## 1. Delivered against the plan

| ID | Planned | Status | Evidence (CI) |
|---|---|---|---|
| P1 | Root keeps SSH; admin preflight relaxed on PVE | ✅ | `permitrootlogin without-password` with a sudo admin; root key login works; root is in `ssh-users` |
| P2 | Root-only forwarding for migration tunnels | ✅ | `sshd -T` for root: `disableforwarding no`, TCP and streamlocal yes. An SSH login carried through root's `-L` tunnel works. Other users keep `disableforwarding yes` |
| P3 | Root exempt from aging | ✅ | `chage -l root`: max 99999, inactive never |
| P4 | pve-firewall, no UFW, opt-in datacenter firewall | ✅ | UFW not installed; `cluster.fw` has `enable: 1` once, SSH and 8006 first, the admin rule, ipset and `policy_in` kept, no duplicates after the second run |
| P5 | Enterprise to no-subscription | ✅ | `apt-get update` succeeds on both PVE 8 (one-line) and PVE 9 (deb822); Ceph no-subscription is kept on re-runs (Δ3) |
| P6–P8 | Forwarding, rpcbind/dnsmasq, no autoremove | ✅ | Admin `ip_forward=1` survives at boot; rpcbind installed, not masked, listening; proxmox-ve, postfix and nfs-common intact |
| P9–P10 | No kernel `fips=1`; systemd-boot cmdline; boot refresh | ✅ | No `fips=1` in GRUB or `/etc/kernel/cmdline`; `audit=1`/`apparmor=1` merged without duplicates; original `root=ZFS=` kept; refresh recorded |
| P11 | overlay kept; SCTP when corosync uses it | ✅ (overlay asserted; the SCTP branch is a static check) | |
| P12 | Guest storage excluded from sweeps, setuid discovery and AIDE | ✅ | AIDE path checks: VM disk, `subvol-*`, `/mnt/pve`, `dir` storage from `storage.cfg`, `/etc/pve` dot files and auth keys skipped; `storage.cfg` still watched |
| P13–P15 | GARP, pvebanner, fail2ban | ✅ | `drop_gratuitous_arp` not set; pvebanner masked; P15 superseded: fail2ban removed (TueriCore HIDS) |
| C1 | `ALLOW_CONTAINERS=auto` | ✅ | Docker (Ubuntu) and rootful Podman (Rocky) detected; overlay kept; boot-time `ip_forward=1` |
| C2 | Firewall for containers and Kubernetes | ✅ | UFW: routed ACCEPT, CNI/docker interfaces in `before.rules` and `before6.rules`, 6443/10250/8472/NodePorts and pod CIDR in `user.rules`, no duplicates. firewalld: ports in public, pod CIDR in trusted |
| C3–C5 | rp_filter 2, GARP, SELinux not raised | ✅ | Boot-time rp_filter 2; SELinux stays permissive on the Kubernetes node |
| C6 | Container storage excluded | ✅ | AIDE skips etcd and docker storage |
| — | Containers still run after hardening (both runs) | ✅ | Container start, egress through host NAT, published port (Docker on Ubuntu 24.04, Podman on Rocky 9) |

## 2. Deltas found and fixed

| # | Delta | Root cause | Fix |
|---|---|---|---|
| Δ1 | UFW failed to start on container/Kubernetes hosts (`ip6tables-restore: No chain/target/match`) | `before6.rules` names its chains `ufw6-*`; the interface block used the IPv4 names. CI only warned (UFW start is container-tolerant); a real host would have stopped the run | The chain prefix is chosen per file |
| Δ2 | Ubuntu 22.04: GitHub answered 403 for the OpenSSL source tarball | Intermittent GitHub release CDN error; curl `--retry` does not retry 4xx | `--retry-all-errors` (curl ≥ 7.71) for the OpenSSL and SSG downloads, detected at download time |
| Δ3 | Proxmox VE 8, second run: Ceph no-subscription repository dropped | Ceph releases were read only from **active** one-line enterprise entries, which the first run had commented out | Releases are read from every enterprise line, active or disabled |
| Δ4 | Docker 29 could not create containers in the test container | Docker 29 keeps layers in containerd's snapshotter (`/var/lib/containerd`), which sat on the test container's overlay root (overlay on overlay). Test harness only | `/var/lib/containerd` is a volume in the `k8s` variant |
| Δ6 | **Field report (2.2.0, Proxmox VE):** step 5.14 stopped the run with `ERROR: /etc/apparmor.d/lxc-containers doesn't contain a valid profile` | Every file in `/etc/apparmor.d` went to a single `aa-enforce` call, which fails as a whole on LXC's include-only file; on a real host that failure is fatal | Only files that declare a profile are passed; a failing batch falls back to file-by-file with a warning naming the profiles the parser rejects; AppArmor is reloaded (not restarted) so running containers keep their profiles. The CI Proxmox stub ships the include-only file |
| Δ7 | **Field report:** no `apt autoremove` after cleanup | Autoremove ran only inside `purge_graphical`, never in desktop mode, never on Proxmox VE (2.2.0), and not right after the legacy-service / telemetry purges | `apt_autoremove` runs after every purge, after the dist-upgrade and after the last package installation, on every Debian-family host. Leftover `rc` configuration is purged. On Proxmox VE, kernels are kept and the rest goes through `safe_purge`. RHEL family unchanged: `clean_requirements_on_remove=True` removes orphaned dependencies with every `dnf remove`. Asserted: `apt-get -s autoremove` has nothing to do and no `rc` packages remain |
| Δ5 | Assertions contradicted the new modes (port 111 on PVE, SELinux enforcing on Kubernetes) | Pre-existing checks were written for plain servers | Made mode-aware |

## 3. Field finding

The owner's Docker workstation, hardened by v2.1.x with the old `ALLOW_CONTAINERS=0` default, could not start any container: overlayfs was blacklisted (`/etc/modprobe.d/60-harden-blacklist.conf`), forwarding was off at boot, and UFW forwarding was set to DROP. v2.2.0 detects the runtime and keeps all three. Hosts hardened earlier recover when the script is re-run (2.2.0 rewrites the blacklist, sysctl and UFW settings), or immediately with a one-off fix that removes the overlay lines, sets `ip_forward=1` and runs `ufw default allow routed`.
