# Plan: Proxmox VE nodes, container hosts and Kubernetes nodes (v2.2.0)

## 1. Analysis

The script assumed every host is a standalone server: root disabled, UFW or firewalld with default-deny, no forwarding, overlayfs blacklisted, and every local filesystem scanned. Three kinds of host break under those assumptions:

* **Proxmox VE**: Debian plus a cluster and hypervisor stack.
* **Container hosts**: Docker, containerd or Podman on any distribution.
* **Kubernetes nodes**: kubeadm, k3s, RKE2, k0s or MicroK8s.

The container-host failure is confirmed in the field. A Docker workstation hardened by v2.1.x with `ALLOW_CONTAINERS=0` could not start any container: overlay was blacklisted, forwarding was turned off at boot, and UFW was set to forward DROP.

### 1.1 Proxmox VE: what breaks and why

| # | Hardening step | Effect on a PVE node | Decision |
|---|---|---|---|
| P1 | `PermitRootLogin no`, `AllowGroups ssh-users` (root not a member) | Cluster join, migration, replication, node shell and the cross-node console all use root SSH: the cluster breaks | Root keeps SSH: `prohibit-password` when a non-root sudo admin exists, otherwise `yes` (`PVE_ROOT_SSH`). Root is added to `ssh-users`. The admin preflight no longer dies on PVE |
| P2 | `DisableForwarding yes` | Secure live migration and storage migration tunnel through `ssh -L` (TCP and unix sockets) | `Match User root` at the end of `sshd_config` re-allows TCP and stream-local forwarding for root only |
| P3 | Password aging and inactivity on every account | After 365 days root's password expires. PAM then rejects root's non-interactive key logins (migration), and `root@pam` cannot log in to the web UI | Root is exempt (`chage -M 99999 -I -1 -E -1 root`) on PVE |
| P4 | UFW installed and enabled | Fights pve-firewall over netfilter | UFW is never installed on PVE (disabled if present). pve-firewall is kept enabled. `PVE_FIREWALL_ENABLE=1` merges `enable: 1` plus SSH and 8006 accept rules into `cluster.fw` without touching existing rules, and restores the file if it does not compile |
| P5 | `apt-get update` with the enterprise repository and no subscription | HTTP 401: the run dies and the node gets no updates at all | `PVE_REPO=auto`: keep enterprise with an active subscription. Otherwise disable the enterprise PVE/Ceph entries (one-line and deb822) and add the matching no-subscription repositories, signed by the same Proxmox keyring |
| P6 | `ip_forward=0` (and v6) | Breaks NAT, routed and SDN guests | Not set on PVE; the node's own config decides |
| P7 | Purge or mask rpcbind and dnsmasq | NFSv3 storage, SDN DHCP | Kept |
| P8 | `apt-get autoremove` | Can remove kernels pinned with `proxmox-boot-tool` | Skipped on PVE |
| P9 | Kernel `fips=1` | Unsupported by Proxmox. corosync/knet (NSS) in FIPS mode can lose quorum, and HA then fences the node | Off on PVE (`PVE_KERNEL_FIPS=1` opts in). User-space FIPS provider stays |
| P10 | GRUB only | ZFS/UEFI nodes boot systemd-boot from `/etc/kernel/cmdline` through `proxmox-boot-tool` | Arguments are merged into `/etc/kernel/cmdline`, then `proxmox-boot-tool refresh` (also after `update-grub` on GRUB+ESP nodes) |
| P11 | Overlay/SCTP blacklist | Docker in LXC; corosync `knet_transport: sctp` | overlay kept on PVE; SCTP kept when corosync uses it |
| P12 | World-writable sweep, setuid audit discovery and AIDE across every local mount | Would chmod files inside guest container filesystems (ZFS `subvol-*`), add audit rules for guest binaries, and checksum VM disks, backups and the constantly changing `/etc/pve` | Guest storage is excluded everywhere (`PVE_GUEST_PATH_RE` plus `dir`/NFS paths from `storage.cfg`); volatile `/etc/pve` entries are excluded from AIDE |
| P13 | `drop_gratuitous_arp=1` | Stale ARP after VM live migration and HA IP moves | Not set on PVE |
| P14 | `/etc/issue` banner | `pvebanner.service` rewrites it at every boot | `pvebanner` masked |
| P15 | fail2ban | Cluster peers could be banned; the web UI (8006) had no brute-force protection | Superseded 2026-11-27: fail2ban is removed; the TueriCore agent's HIDS answers brute force and white-lists the internal networks |

### 1.2 Containers and Kubernetes (all distributions)

| # | Hardening step | Effect | Decision |
|---|---|---|---|
| C1 | `ALLOW_CONTAINERS=0` default | overlay blacklisted, forwarding 0, UFW forward DROP: no container can run | `ALLOW_CONTAINERS=auto`, detected in preflight before any change (dockerd/containerd binaries or storage; rootful Podman = podman.socket, rootful containers or Quadlets; any Kubernetes) |
| C2 | Default-deny inbound | Pods cannot reach node services; Kubernetes control-plane and CNI traffic is dropped | UFW: a managed `before.rules` block accepts input and forwarding on container/CNI interfaces (`cni0`, `cali+`, `cilium_+`, `flannel.1`, `docker0`, `br-+` …). Kubernetes ports by role. Pod/service CIDRs trusted (from kubeadm manifests, k3s/rke2 config or defaults, flannel, CNI routes). firewalld: ports in the default zone, pod CIDRs and CNI links in `trusted`. `K8S_TRUSTED_CIDRS` restricts the sources |
| C3 | `rp_filter=1` | Asymmetric CNI paths dropped (Cilium, Calico eBPF, multi-NIC) | 2 (loose) on Kubernetes nodes |
| C4 | `drop_gratuitous_arp=1` | kube-vip / MetalLB L2 VIP failover | Not set on Kubernetes nodes |
| C5 | SELinux raised to enforcing (EL) | kubelet, CNI or hostPath pods stop after reboot | Never raised on Kubernetes nodes; enforcing is kept where it already is |
| C6 | Sweeps, setuid discovery, AIDE | Would modify container root filesystems and audit their binaries | `CONTAINER_PATH_RE` excluded (docker, containerd, containers, kubelet, rancher, k0s, etcd, longhorn, openebs, microk8s) |

## 2. Implementation

* Single script, no new steps (the step counter is unchanged). New helpers: `is_pve`, `is_k8s`, `containers_on`, `host_fs_mounts`, `configure_repositories_pve`, `configure_pve_firewall`, `pve_firewall_enable`, `pve_kernel_cmdline`, `pve_boot_refresh`, `ufw_kubernetes_rules`, `ufw_container_ifaces`, `k8s_ports`, `k8s_cluster_cidrs`. (`fail2ban_cluster_peers` was removed with fail2ban, 2026-11-27.)
* New knobs: `PROXMOX_MODE`, `PVE_ROOT_SSH`, `PVE_REPO`, `PVE_FIREWALL_ENABLE`, `PVE_FIREWALL_MGMT_SOURCE`, `PVE_KERNEL_FIPS`, `KUBERNETES_MODE`, `K8S_TRUSTED_CIDRS`, `K8S_EXTRA_PORTS`. `ALLOW_CONTAINERS` defaults to `auto`.

## 3. Verification

| Target | How |
|---|---|
| `debian 12 proxmox`, `debian 13 proxmox` | `tests/pve-stub.sh`: stub `proxmox-ve`, `pve-manager` and `pve-firewall` packages with the real dependencies (postfix, nfs-common → rpcbind, chrony, iptables). Also the real enterprise repositories and Proxmox keyring, plus `/etc/pve` (corosync.conf, storage.cfg, cluster.fw with admin rules), systemd-boot cmdline, a proxmox-boot-tool stub, pvebanner, an admin `ip_forward=1` and a root password. Assertions: root key SSH works; a unix-socket `-L` forward works for root; forwarding stays disabled for others; root never expires; no UFW; `cluster.fw` merged without duplicates on re-run; the no-subscription repo makes `apt-get update` succeed; stack and rpcbind intact; forwarding untouched; no `fips=1`; cmdline merged and refresh ran; AIDE skips guest storage; fail2ban jail and peers |
| `ubuntu 24.04 k8s` (Docker) and `rocky 9 k8s` (Podman) | `tests/k8s-stub.sh`: a real runtime plus a stub kubeadm control-plane layout and a `cni0` bridge. Assertions after **both** runs: a container starts, reaches the internet through the host, and a published port answers. Forwarding at boot, overlay allowed, routed traffic and CNI interfaces allowed, Kubernetes ports and pod CIDR present without duplicates, rp_filter 2, SELinux not raised, AIDE skips etcd and docker storage |
| All existing targets | Unchanged behaviour (no runtime is detected in their images) |
