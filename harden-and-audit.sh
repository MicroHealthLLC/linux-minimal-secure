#!/usr/bin/env bash
# =============================================================================
# harden-and-audit.sh - linux-minimal-secure
#
# Transforms a stock server installation into a minimal, FIPS-ready,
# SCAP/CIS-Level-2-hardened headless server, then audits itself with OpenSCAP
# and writes XML + HTML compliance reports. The distribution is detected:
#   Debian family: Debian 12 (bookworm) / 13 (trixie), Ubuntu 22.04 / 24.04 / 26.04
#   RHEL family:   RHEL, CentOS Stream, Rocky Linux, AlmaLinux, Oracle Linux 8 / 9 / 10,
#                  Fedora 41+ (server and desktop)
# Desktops (a display manager is installed) keep their graphical session,
# printing, Bluetooth, USB storage and network discovery: DESKTOP_MODE.
# Proxmox VE 8/9 nodes keep root SSH, pve-firewall, guest storage and their
# repositories working (PROXMOX_MODE). Docker/containerd/Podman hosts and
# Kubernetes nodes keep container networking and cluster traffic working
# (ALLOW_CONTAINERS, KUBERNETES_MODE); all three are detected automatically.
#
# Design rules (in priority order):
#   1. Never lock the operator out. Anti-lockout checks run BEFORE anything
#      changes, risky configuration (sshd, OpenSSL) is validated before it is
#      activated, and auditd may never SUSPEND / SINGLE / HALT the host.
#   2. Fail fast and safe: any unexpected error stops the run (set -Eeuo
#      pipefail) and names the failing step.
#   3. Run unattended and idempotently; every overwritten file is backed up
#      once under /var/backups/harden-and-audit/<original path>.
#
# Usage:   sudo ./harden-and-audit.sh [--scan-only] [--help] [--version]
# Docs:    README.md, docs/EXCEPTIONS.md, docs/PLAN-UBUNTU.md, docs/PLAN-RHEL.md
# =============================================================================
set -Eeuo pipefail
shopt -s nullglob

readonly SCRIPT_VERSION="2.2.2"
readonly SCRIPT_NAME="harden-and-audit.sh"
readonly LOG_FILE="/var/log/harden-and-audit.log"
readonly STATE_DIR="/var/lib/harden-and-audit"
readonly CACHE_DIR="/var/cache/harden-and-audit"
readonly MARK="harden-and-audit"
# Backups live outside every *.d include directory: a copy left next to the
# original would be loaded too (logrotate.d, apt.conf.d) or even executed
# (grub.d) - e.g. a GRUB menu entry without --unrestricted.
readonly BACKUP_DIR="/var/backups/harden-and-audit"

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
export NEEDRESTART_MODE=a
export LC_ALL=C.UTF-8
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# ----------------------------------------------------------------------------
# Tunables (override through the environment)
# ----------------------------------------------------------------------------
: "${DEBIAN_MIRROR:=https://deb.debian.org/debian}"
: "${DEBIAN_SECURITY_MIRROR:=https://security.debian.org/debian-security}"
: "${UBUNTU_MIRROR:=}"                # empty = keep the configured Ubuntu mirror (cloud/regional), else archive/ports
: "${UBUNTU_SECURITY_MIRROR:=}"       # empty = keep the configured security mirror, else security/ports
: "${NTP_SERVERS:=}"                  # empty = distribution default (Debian pool / ntp.ubuntu.com)
: "${NTP_FALLBACK_SERVERS:=time.nist.gov}"
: "${SUDO_PROVIDER:=classic}"         # Ubuntu 25.10+: classic = select sudo.ws (full logging); keep = leave sudo-rs
: "${SSG_CONTENT_FALLBACK:=1}"        # 1 = scan a release without native SSG content with the newest older LTS content
: "${PASS_MAX_DAYS:=365}"            # DoD sites commonly set 60
: "${PASS_MIN_DAYS:=1}"
: "${PASS_WARN_AGE:=7}"
: "${ACCOUNT_INACTIVE_DAYS:=}"      # empty = 45 (30 on Fedora, its CIS value)
: "${SHELL_TMOUT:=900}"
: "${SSH_LOGLEVEL:=}"                # empty = INFO (Debian family CIS) / VERBOSE (EL CIS: logs key fingerprints)
: "${FAILLOCK_DENY:=4}"
: "${FAILLOCK_UNLOCK_TIME:=900}"
: "${ALLOW_CONTAINERS:=auto}"        # auto|0|1 - keep overlayfs, IP forwarding and routed traffic for containers (auto: Docker/containerd/Podman/Kubernetes found)
: "${KUBERNETES_MODE:=auto}"        # auto|0|1 - Kubernetes node: open cluster/CNI ports, trust pod networks (auto: kubelet/k3s/rke2/k0s/microk8s found)
: "${K8S_TRUSTED_CIDRS:=}"          # node/pod/service CIDRs allowed to reach the cluster ports (empty = cluster ports open to any source)
: "${K8S_EXTRA_PORTS:=}"            # extra inbound ports on Kubernetes nodes, e.g. "9100/tcp 7946/udp"
: "${KEEP_IPV6_RA:=auto}"            # auto|0|1 - keep IPv6 router advertisements (SLAAC)
: "${UFW_OUTBOUND_POLICY:=allow}"    # allow|deny (deny adds an explicit egress allow-list)
: "${UFW_EXTRA_OUT:=}"               # extra egress rules for deny mode, e.g. "514/tcp 636/tcp"
: "${FIREWALL_OUTBOUND_POLICY:=${UFW_OUTBOUND_POLICY}}"  # generic name (UFW and firewalld)
: "${FIREWALL_EXTRA_OUT:=${UFW_EXTRA_OUT}}"
: "${DESKTOP_MODE:=auto}"           # auto|0|1 - 1 keeps the desktop experience (auto: a display manager is installed)
: "${PROXMOX_MODE:=auto}"           # auto|0|1 - Proxmox VE node (auto: pve-manager is installed)
: "${PVE_ROOT_SSH:=auto}"           # auto|yes|prohibit-password - root SSH on Proxmox VE (auto: keys only if a sudo admin exists)
: "${PVE_ROOT_PASSWORD_FROM:=}"     # Proxmox VE: CIDR(s) root may still SSH from with a password, e.g. 192.168.0.0/16 (empty = keys only)
: "${PVE_REPO:=auto}"               # auto|enterprise|no-subscription|keep - Proxmox repositories (auto: by subscription status)
: "${PVE_FIREWALL_ENABLE:=0}"       # 1 = turn the Proxmox datacenter firewall on (SSH + web UI allowed first)
: "${PVE_FIREWALL_MGMT_SOURCE:=}"   # source CIDR(s) allowed to SSH/8006 when enabling (empty = any)
: "${PBS_FIREWALL_EXTRA_IN:=}"      # Proxmox Backup Server (UFW): extra inbound rules, e.g. "9100/tcp 8443/tcp"
: "${PVE_KERNEL_FIPS:=0}"           # 1 = also boot a Proxmox VE kernel with fips=1 (not supported by Proxmox)
: "${EPEL_ENABLE:=1}"                # RHEL family: EPEL provides fail2ban, dkms and some media libraries
: "${FAIL2BAN_IGNOREIP:=}"           # space separated CIDRs never banned (jump hosts)
: "${SSH_DISABLE_PASSWORD:=0}"       # 1 forces key-only SSH (only if every admin has a key)
: "${ENABLE_GRUB_PASSWORD:=1}"
: "${GRUB_SUPERUSER:=grubadmin}"
: "${GRUB_PASSWORD_PBKDF2:=}"        # pre-computed grub.pbkdf2.sha512... hash (preferred)
: "${FIPS_STRICT:=0}"                # 1 sets default_properties = fips=yes system-wide
: "${FIPS_OPENSSL_VERSION:=3.1.2}"   # OpenSSL FIPS provider, FIPS 140-3 cert #4985
: "${FIPS_OPENSSL_SHA256:=a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539}"
: "${FIPS_OPENSSL_URL:=https://github.com/openssl/openssl/releases/download/openssl-${FIPS_OPENSSL_VERSION}/openssl-${FIPS_OPENSSL_VERSION}.tar.gz}"
: "${AIDE_INIT:=1}"
: "${LOG_MAX_TOTAL:=4G}"             # hard cap for /var/log; oldest rotated archives are pruned past it
: "${LOG_MIN_FREE_PCT:=15}"          # also prune while the /var/log filesystem has less free space than this
: "${LOG_ROTATE_KEEP:=14}"           # rotated generations kept per log (logs are shipped off-host)
: "${LOG_MAXSIZE:=100M}"             # a log larger than this rotates at the next hourly logrotate run
: "${BANNER_STYLE:=generic}"        # generic|dod - generic notice for any organization; dod = DoD Notice and Consent (USG systems only)
: "${BANNER_ORG:=}"                  # organization named in the generic notice (empty = "the owner of this system")
: "${BANNER_FILE:=}"                 # path to custom banner text; overrides BANNER_STYLE
: "${PROGRESS_INTERVAL:=60}"         # seconds between progress lines during long steps (AIDE, OpenSCAP)
: "${SSG_VERSION:=0.1.82}"
: "${SSG_SHA512:=1caea418f0a5aaef7025e1655ca45a80942ea87ee832b943644ba6f9991b14a6ac5b35dddcd04b754e1fc8fbdee7b7f394507d24b123e821cca0354dc4e03cfd}"
: "${SSG_URL:=https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip}"
: "${SSG_DOWNLOAD:=1}"               # 0 = offline; use SSG_DATASTREAM or packaged content
: "${SSG_DATASTREAM:=}"              # explicit path to an ssg-<product>-ds.xml
: "${SCAP_PROFILE:=}"                # empty = cis_level2_server (Debian/Ubuntu) or cis (RHEL family: CIS L2 Server)
: "${SCAP_EXTRA_PROFILES:=}"         # e.g. "anssi_bp28_high standard"
: "${SCAP_MIN_SCORE:=90}"
: "${SCAP_ENFORCE_MIN:=1}"           # non-zero exit when the gate profile scores below SCAP_MIN_SCORE
: "${SCAP_RESULTS:=/var/log/scap-results.xml}"
: "${SCAP_REPORT:=/var/log/scap-report.html}"
: "${SCAP_SUMMARY:=/var/log/scap-summary.txt}"
: "${HARDEN_SKIP_ADMIN_CHECK:=0}"    # 1 skips the anti-lockout admin preflight (NOT recommended)

# ----------------------------------------------------------------------------
# Runtime state
# ----------------------------------------------------------------------------
CURRENT_STEP="startup"
OS_ID=""            # debian | ubuntu | rhel | centos | rocky | almalinux | ol
OS_FAMILY=""        # deb | rhel
OS_VERSION=""       # 12, 13, 22.04, 24.04, 26.04, 8.10, 9.6, 10 ...
OS_CODENAME=""      # Debian/Ubuntu only
OS_MAJOR=""         # Debian 12/13; Ubuntu 22/24/26; EL 8/9/10
OS_NUM=0            # comparable number: Debian 12 -> 12, Ubuntu 24.04 -> 2404, EL 9 -> 9
OS_NAME=""          # "Debian 12", "Ubuntu 24.04", "Rocky Linux 9.6"
SSG_PRODUCT=""      # debian12, ubuntu2404, rl9, almalinux9, cs10, rhel9 ...
DEB_ARCH=""         # amd64 | arm64 ... (dpkg names, also used on the RHEL family)
ADMIN_GROUP=sudo    # sudo (Debian family) | wheel (RHEL family)
DESKTOP=0           # 1 = desktop mode (resolved from DESKTOP_MODE in preflight)
PVE=0               # 1 = Proxmox VE node (resolved from PROXMOX_MODE in preflight)
PBS=0               # 1 = Proxmox Backup Server (implies PVE=1 handling, see pbs_detected)
PVE_VERSION=""      # e.g. 8.4.1
ROOT_SSH=no         # effective PermitRootLogin (yes|prohibit-password on Proxmox VE)
K8S=0               # 1 = Kubernetes node (resolved from KUBERNETES_MODE in preflight)
K8S_DISTRO=""       # kubeadm | k3s | rke2 | k0s | microk8s
K8S_CONTROL=0       # 1 = control-plane node (API server / etcd run here)
CONTAINER_RUNTIMES=""
DNF5=0              # 1 = dnf is dnf5 (Fedora 41+)
SSH_UNIT=ssh        # ssh (Debian family) | sshd (RHEL family)
SSH_PORTS=()
KEEP_RA=0
UID_MIN_VALUE=1000
SCAN_ONLY=0
WARNINGS=()

# ----------------------------------------------------------------------------
# Logging & error handling
# ----------------------------------------------------------------------------
ts()   { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
log()  { printf '%s [INFO ] %s\n' "$(ts)" "$*"; }
warn() { printf '%s [WARN ] %s\n' "$(ts)" "$*" >&2; WARNINGS+=("$*"); }
die()  { printf '%s [FATAL] %s\n' "$(ts)" "$*" >&2; exit 1; }
# fmt_dur SECONDS - "42s", "7m05s", "1h12m"
fmt_dur() {
    local t=$1
    if (( t < 60 )); then printf '%ss' "$t"
    elif (( t < 3600 )); then printf '%dm%02ds' $(( t / 60 )) $(( t % 60 ))
    else printf '%dh%02dm' $(( t / 3600 )) $(( t % 3600 / 60 )); fi
}
STEP_NO=0
STEP_TOTAL=0    # set in main; 0 = unknown (step numbers shown without a total)
step() {
    CURRENT_STEP="$1"
    STEP_NO=$(( STEP_NO + 1 ))
    if (( STEP_TOTAL > 0 && STEP_NO > STEP_TOTAL )); then STEP_TOTAL=$STEP_NO; fi
    local n=$STEP_NO
    if (( STEP_TOTAL > 0 )); then n+="/${STEP_TOTAL}"; fi
    printf '\n%s [STEP %s] ===== %s ===== (run time %s)\n' "$(ts)" "$n" "$1" "$(fmt_dur "$SECONDS")"
}

# shellcheck disable=SC2329  # invoked through the ERR trap
on_error() {
    local rc=$1 line=$2 cmd=$3
    # set -E propagates the trap into subshells and process substitutions;
    # only the main shell reports (a failing subshell surfaces there anyway).
    [[ $BASHPID -eq $$ ]] || exit "$rc"
    printf '%s [FATAL] step "%s" failed (exit %s) at line %s: %s\n' "$(ts)" "$CURRENT_STEP" "$rc" "$line" "$cmd" >&2
    printf '%s [FATAL] Original copies of modified files: %s/<path>. Log: %s\n' "$(ts)" "$BACKUP_DIR" "$LOG_FILE" >&2
    exit "$rc"
}
trap 'on_error $? $LINENO "$BASH_COMMAND"' ERR

usage() {
    cat <<'EOF'
Usage: harden-and-audit.sh [--scan-only] [--help] [--version]

  (no option)   Harden this host (Debian 12/13, Ubuntu 22.04/24.04/26.04,
                RHEL / CentOS Stream / Rocky / AlmaLinux / Oracle Linux 8-10,
                or Fedora 41+; desktops keep their desktop experience),
                then run the OpenSCAP audit.
  --scan-only   Only run the OpenSCAP audit and regenerate the reports.
  --version     Print the script version.

Every tunable is an environment variable documented at the top of the script
and in README.md (for example SCAP_PROFILE, PASS_MAX_DAYS, ALLOW_CONTAINERS).
EOF
}

# ----------------------------------------------------------------------------
# Generic helpers
# ----------------------------------------------------------------------------
in_container() { systemd-detect-virt --container --quiet 2>/dev/null; }

# sshd -t needs its privilege-separation directory, which normally only
# exists once ssh.service has started (RuntimeDirectory=sshd).
sshd_test() {
    install -d -m 0755 -o root -g root /run/sshd
    # EL creates host keys on the first sshd.service start (sshd-keygen@);
    # until then "sshd -t" fails with "no hostkeys available".
    local k=(/etc/ssh/ssh_host_*_key)
    [[ ${#k[@]} -gt 0 ]] || ssh-keygen -A >/dev/null
    sshd -t "$@"
}

# Run a command that legitimately cannot succeed inside a container (kernel,
# bootloader, audit netlink). On real hosts a failure is fatal.
host_only() {
    local desc=$1; shift
    if "$@"; then
        return 0
    fi
    if in_container; then
        warn "container: '${desc}' could not be applied here (it applies on a real host)"
        return 0
    fi
    die "${desc} failed"
}

PROGRESS_ELAPSED=0   # seconds the current run_with_progress command has run (for probes)

# eta DONE TOTAL - "~12m left" from PROGRESS_ELAPSED, or nothing if unknown
eta() {
    local d=$1 t=$2
    (( d > 0 && t > d && PROGRESS_ELAPSED > 0 )) || return 0
    printf '~%s left' "$(fmt_dur $(( PROGRESS_ELAPSED * (t - d) / d )))"
}

# run_with_progress DESC PROBE CMD... - run CMD in the background and log
# elapsed time every PROGRESS_INTERVAL seconds, plus a one-line status from
# PROBE (a function given CMD's PID; "-" for none). Returns CMD's status.
run_with_progress() {
    local desc=$1 probe=$2; shift 2
    local start=$SECONDS n=0 pid rc=0 el msg
    "$@" &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1
        (( ++n % PROGRESS_INTERVAL == 0 )) || continue
        el=$(( SECONDS - start ))
        PROGRESS_ELAPSED=$el
        msg=""
        [[ $probe == - ]] || msg=$("$probe" "$pid" 2>/dev/null || true)
        log "${desc}: $(fmt_dur "$el") elapsed${msg:+ - ${msg}}"
    done
    wait "$pid" || rc=$?
    # Closing line, so even a step shorter than the interval reports its result.
    el=$(( SECONDS - start ))
    PROGRESS_ELAPSED=$el
    msg=""
    [[ $probe == - ]] || msg=$("$probe" "" 2>/dev/null || true)
    log "${desc}: completed in $(fmt_dur "$el") (exit ${rc})${msg:+ - ${msg}}"
    return "$rc"
}

backup_file() {
    local f=$1 dest
    dest="${BACKUP_DIR}${f}"
    # -L: a backed-up relative symlink dangles inside BACKUP_DIR (-e is false).
    if [[ ( -e $f || -L $f ) && ! -e $dest && ! -L $dest ]]; then
        install -d -m 0700 "$(dirname "$dest")"
        cp -a -- "$f" "$dest"
    fi
}

# write_file MODE PATH  (content on stdin) - backs up, writes atomically.
write_file() {
    local mode=$1 path=$2 tmp
    backup_file "$path"
    install -d -m 0755 -o root -g root "$(dirname "$path")"
    tmp=$(mktemp "${path}.XXXXXX")
    cat >"$tmp"
    chown root:root "$tmp"
    chmod "$mode" "$tmp"
    mv -f -- "$tmp" "$path"
}

# set_kv FILE KEY VALUE [SEPARATOR] - replace or append "KEY<sep>VALUE".
set_kv() {
    local file=$1 key=$2 value=$3 sep=${4:- }
    backup_file "$file"
    touch "$file"
    if grep -qE "^[[:space:]]*${key}([[:space:]]|=|$)" "$file"; then
        sed -i -E "0,/^[[:space:]]*${key}([[:space:]]|=|$).*/s||${key}${sep}${value}|" "$file"
        # drop any later duplicates of the same key
        awk -v k="$key" 'BEGIN{seen=0} { if ($0 ~ "^[[:space:]]*"k"([[:space:]]|=|$)") { if (seen) next; seen=1 } print }' "$file" >"${file}.tmp.$$"
        cat "${file}.tmp.$$" >"$file"
        rm -f "${file}.tmp.$$"
    else
        printf '%s%s%s\n' "$key" "$sep" "$value" >>"$file"
    fi
}

# qgrep: quiet match that still reads all input. 'producer | grep -q' can
# SIGPIPE the producer and, under pipefail, report a false failure.
qgrep() { grep "$@" >/dev/null; }

is_ubuntu() { [[ $OS_ID == ubuntu ]]; }
is_debian() { [[ $OS_ID == debian ]]; }
is_rhel()   { [[ $OS_FAMILY == rhel ]]; }
is_fedora() { [[ $OS_ID == fedora ]]; }
is_desktop() { [[ $DESKTOP == 1 ]]; }
is_pve()     { [[ $PVE == 1 ]]; }
is_pbs()     { [[ $PBS == 1 ]]; }
is_k8s()     { [[ $K8S == 1 ]]; }
containers_on() { [[ $ALLOW_CONTAINERS == 1 ]]; }

# Container runtimes in use (space separated): docker, containerd, podman.
# Podman counts only when it runs rootful containers or its API socket is on
# (rootless Podman needs neither forwarding nor routed firewall traffic).
container_runtimes_detected() {
    local -a rt=()
    { command -v dockerd || [[ -e /var/lib/docker ]]; } >/dev/null 2>&1 && rt+=(docker)
    { command -v containerd || [[ -e /var/lib/containerd ]]; } >/dev/null 2>&1 && rt+=(containerd)
    if command -v podman >/dev/null 2>&1; then
        if systemctl is-enabled --quiet podman.socket 2>/dev/null \
            || [[ -n $(podman ps -aq 2>/dev/null) ]] \
            || compgen -G '/etc/containers/systemd/*.container' >/dev/null; then
            rt+=(podman)
        fi
    fi
    echo "${rt[*]}"
}

# Kubernetes distribution on this node (empty = none).
k8s_detected() {
    if command -v k3s >/dev/null 2>&1 || [[ -d /etc/rancher/k3s ]]; then echo k3s; return; fi
    if command -v rke2 >/dev/null 2>&1 || [[ -d /etc/rancher/rke2 ]]; then echo rke2; return; fi
    if command -v k0s >/dev/null 2>&1 || [[ -d /etc/k0s ]]; then echo k0s; return; fi
    if [[ -d /var/snap/microk8s ]]; then echo microk8s; return; fi
    if command -v kubelet >/dev/null 2>&1 || [[ -f /var/lib/kubelet/config.yaml || -f /etc/kubernetes/kubelet.conf ]]; then
        echo kubeadm; return
    fi
}

k8s_control_plane_detected() {
    [[ -f /etc/kubernetes/manifests/kube-apiserver.yaml ]] && return 0
    systemctl list-unit-files --no-legend k3s.service rke2-server.service k0scontroller.service 2>/dev/null | qgrep . && return 0
    [[ -d /var/snap/microk8s ]] && return 0
    return 1
}

# Network interfaces created by container runtimes and CNI plugins (iptables
# wildcard form): pods and containers reach node services through them.
CNI_IFACES=(cni0 flannel.1 flannel-wg cali+ vxlan.calico tunl0 cilium_+ lxc+ weave vxlan-+ kube-bridge kube-ipvs0 genev_sys_+ docker0 br-+ podman+)

# Pod and service CIDRs of the local cluster (best effort): kubeadm manifests,
# k3s/rke2 configuration (or their defaults), flannel, routes over CNI links.
k8s_cluster_cidrs() {
    local f
    {
        for f in /etc/kubernetes/manifests/kube-controller-manager.yaml /etc/kubernetes/manifests/kube-apiserver.yaml; do
            [[ -f $f ]] && sed -n -E 's/.*--(cluster-cidr|service-cluster-ip-range)=([^"[:space:]]+).*/\2/p' "$f" | tr ',' '\n'
        done
        for f in /etc/rancher/k3s/config.yaml /etc/rancher/rke2/config.yaml; do
            [[ -f $f ]] && sed -n -E 's/^[[:space:]]*(cluster-cidr|service-cidr):[[:space:]]*"?([^"[:space:]]+)"?.*/\2/p' "$f" | tr ',' '\n'
        done
        case $K8S_DISTRO in
            k3s|rke2) printf '10.42.0.0/16\n10.43.0.0/16\n' ;;
            k0s) printf '10.244.0.0/16\n10.96.0.0/12\n' ;;
            microk8s) printf '10.1.0.0/16\n10.152.183.0/24\n' ;;
        esac
        [[ -f /run/flannel/subnet.env ]] && sed -n 's/^FLANNEL_NETWORK=//p' /run/flannel/subnet.env
        ip -4 route show 2>/dev/null | awk '$1 ~ /^[0-9.]+\/[0-9]+$/ && $0 ~ / dev (cni0|flannel\.1|cali|vxlan\.calico|tunl0|cilium_|weave|kube-bridge)/ {print $1}'
    } | awk 'NF' | sort -u
}

# Proxmox Backup Server: proxmox-backup-server is installed (no pve-manager).
# It runs in Proxmox mode (root SSH like a PVE node, root exempt from
# faillock/expiry because root@pam logs into the web UI, Proxmox kernel) plus
# PBS-specific care (repositories kept, NFS exports and datastores respected,
# UFW as the host firewall unless pve-firewall is installed - pbs_uses_ufw).
pbs_detected() {
    pkg_installed proxmox-backup-server
}

# /etc/exports (or exports.d) defines at least one NFS export.
pbs_nfs_exports() {
    grep -qsvE '^[[:space:]]*(#|$)' /etc/exports /etc/exports.d/*.exports
}

# A Proxmox Backup Server without pve-firewall (the usual case: PBS ships no
# host firewall and pve-firewall needs the PVE cluster stack) uses UFW, with
# rules for what PBS serves. A PBS that has pve-firewall keeps the PVE path.
pbs_uses_ufw() {
    is_pbs && ! pkg_installed pve-firewall
}

# Proxmox VE: pve-manager (the node's management stack) is installed.
pve_detected() {
    pkg_installed pve-manager || [[ -x /usr/bin/pveversion && -d /etc/pve ]]
}

# Guest storage on a Proxmox VE node: container root filesystems, VM disks,
# backups, ISO/template stores and Ceph data belong to the guests, not to
# this host - permission sweeps, setuid discovery and AIDE stay out of them.
PVE_GUEST_PATH_RE='^(/var/lib/(vz|lxc|ceph)|/mnt/pve)(/|$)|/(subvol|basevol)-[0-9]+-disk-[0-9]+(/|$)'

# pve_storage_paths - directory-backed storage paths from storage.cfg.
pve_storage_paths() {
    [[ -r /etc/pve/storage.cfg ]] || return 0
    awk '/^[a-z0-9]+:/ { t = $1 } /^[[:space:]]+path[[:space:]]/ && t ~ /^(dir|btrfs|nfs|cifs|cephfs|glusterfs):$/ && $2 != "/" { print $2 }' \
        /etc/pve/storage.cfg
}

# Container runtime storage: image layers and running containers' root
# filesystems (overlay mounts) belong to the workloads, never to the host.
CONTAINER_PATH_RE='^(/var/lib/(docker|containerd|containers|kubelet|rancher|k0s|longhorn|etcd)|/run/(containerd|k3s|docker|netns)|/var/snap/microk8s|/var/openebs)(/|$)'

# host_fs_mounts FSTYPE_REGEX - local mount points to scan: never container
# storage, and on Proxmox VE never guest storage.
host_fs_mounts() {
    local -a m=() all
    local t
    mapfile -t all < <(findmnt -rn -o TARGET,FSTYPE | awk -v re="$1" '$2 ~ re {print $1}' | sort -u)
    for t in "${all[@]}"; do
        [[ $t =~ $CONTAINER_PATH_RE ]] || m+=("$t")
    done
    if is_pve; then
        local p skip
        local -a paths
        mapfile -t paths < <(pve_storage_paths)
        for p in "${m[@]}"; do
            [[ $p =~ $PVE_GUEST_PATH_RE ]] && continue
            skip=0
            local s
            for s in "${paths[@]}"; do [[ $p == "$s" || $p == "$s"/* ]] && skip=1; done
            [[ $skip == 1 ]] || printf '%s\n' "$p"
        done
    else
        [[ ${#m[@]} -gt 0 ]] && printf '%s\n' "${m[@]}"
    fi
    return 0
}

# A display manager (GDM, SDDM, LightDM, ...) is installed or configured.
desktop_detected() {
    local p
    [[ -e /etc/systemd/system/display-manager.service ]] && return 0
    for p in gdm gdm3 sddm lightdm lxdm xdm slim greetd; do
        pkg_installed "$p" && return 0
    done
    return 1
}
is_deb()    { [[ $OS_FAMILY == deb ]]; }

# --- package layer (dpkg/apt on the Debian family, rpm/dnf on the RHEL family)
# GitHub release downloads intermittently answer 403/5xx; plain --retry only
# retries transient errors. --retry-all-errors needs curl 7.71+ (not EL8).
# set_curl_retry - fill CURL_RETRY_ALL (call right before downloading: curl
# may only be installed by the base stack).
CURL_RETRY_ALL=()
set_curl_retry() {
    CURL_RETRY_ALL=()
    if curl --help all 2>/dev/null | qgrep -- '--retry-all-errors'; then CURL_RETRY_ALL=(--retry-all-errors --retry-delay 5); fi
    return 0
}

pkg_installed() {
    if is_rhel; then
        rpm -q --quiet "$1" 2>/dev/null
    else
        [[ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null || true)" == installed ]]
    fi
}

# Names of every package dnf can install, cached per repository state (one
# repoquery instead of one per package: ~60 lookups for the media libraries).
DNF_NAMES=""
dnf_names() {
    if [[ -z $DNF_NAMES || ! -s $DNF_NAMES ]]; then
        DNF_NAMES=${CACHE_DIR}/dnf-names
        # dnf5 needs the newline in --qf; dnf4 adds one (blank lines dropped).
        dnf -q repoquery --qf '%{name}\n' 2>/dev/null | awk 'NF' | sort -u >"$DNF_NAMES" || true
        rpm -qa --qf '%{NAME}\n' >>"$DNF_NAMES" 2>/dev/null || true
        sort -u -o "$DNF_NAMES" "$DNF_NAMES"
    fi
    cat "$DNF_NAMES"
}

pkg_candidate() {
    if is_rhel; then
        dnf_names | qgrep -Fx -- "$1"
        return
    fi
    local c
    c=$(apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')
    [[ -n $c && $c != "(none)" ]]
}

# Every installable package name (for "~REGEX" lookups).
pkg_all_names() {
    if is_rhel; then dnf_names; else apt-cache pkgnames 2>/dev/null; fi
}

# Installed package names, one per line.
pkg_list_installed() {
    if is_rhel; then
        rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort -u
    else
        dpkg-query -W -f='${db:Status-Status} ${Package}\n' 2>/dev/null | awk '$1=="installed"{print $2}'
    fi
}

dnf_install() {
    dnf -y -q --setopt=install_weak_deps=False install "$@"
}

# pkg_install PKG... - install with the family's package manager.
pkg_install() {
    if is_rhel; then dnf_install "$@"; else apt_install "$@"; fi
}

# pkg_refresh - refresh repository metadata.
pkg_refresh() {
    if is_rhel; then
        DNF_NAMES=""
        rm -f "${CACHE_DIR}/dnf-names"
        dnf -q -y makecache >/dev/null
    else
        apt_update
    fi
}

pkg_mark_manual() {
    if is_rhel; then
        if [[ $DNF5 == 1 ]]; then dnf -q -y mark user "$@" >/dev/null 2>&1 || true; else dnf -q -y mark install "$@" >/dev/null 2>&1 || true; fi
    else
        apt-mark "${APT_LOCK_WAIT[@]}" manual "$@" >/dev/null
    fi
}

# first_available PKG... - print the first package that has an apt candidate.
# An entry "~REGEX" matches package names instead; the newest name (version
# sort) with a candidate wins - this tracks soname bumps across releases.
first_available() {
    local p m
    # An alternative that is already installed wins (EL images ship
    # libcurl-minimal, which conflicts with libcurl).
    for p in "$@"; do
        if [[ $p != "~"* ]] && pkg_installed "$p"; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    for p in "$@"; do
        if [[ $p == "~"* ]]; then
            while read -r m; do
                if pkg_candidate "$m"; then
                    printf '%s\n' "$m"
                    return 0
                fi
            done < <(pkg_all_names | grep -E "${p#\~}" | sort -rV || true)
        elif pkg_candidate "$p"; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    return 1
}

# apt-daily / unattended-upgrades (enabled with --now in step 1) can hold the
# dpkg lock for a long time: wait for it instead of failing (apt >= 1.9.11).
APT_LOCK_WAIT=(-o DPkg::Lock::Timeout=1800)

apt_install() {
    apt-get "${APT_LOCK_WAIT[@]}" install -y -q --no-install-recommends \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
}

apt_update() {
    apt-get "${APT_LOCK_WAIT[@]}" update -q -o Acquire::Retries=5
}

# Purge PACKAGES only when apt would not remove anything outside the given
# set (dependency-aware - protects packages that merely link to X11 libs).
safe_purge() {
    local -a wanted=("$@") keep=() removed=()
    local pkg
    [[ ${#wanted[@]} -eq 0 ]] && return 0
    if is_rhel; then
        safe_purge_rpm "${wanted[@]}"
        return 0
    fi
    local set=" ${wanted[*]} "
    mapfile -t removed < <(apt-get -s purge "${wanted[@]}" 2>/dev/null | awk '/^Purg /{print $2}')
    local collateral=0
    for pkg in "${removed[@]}"; do
        [[ $set == *" ${pkg%%:*} "* ]] || collateral=1
    done
    if [[ $collateral -eq 0 ]]; then
        keep=("${wanted[@]}")
    else
        for pkg in "${wanted[@]}"; do
            mapfile -t removed < <(apt-get -s purge "$pkg" 2>/dev/null | awk '/^Purg /{print $2}')
            local ok=1 r
            [[ ${#removed[@]} -eq 0 ]] && ok=0
            for r in "${removed[@]}"; do
                [[ $set == *" ${r%%:*} "* ]] || ok=0
            done
            if [[ $ok -eq 1 ]]; then
                keep+=("$pkg")
            else
                log "keeping ${pkg}: removing it would also remove non-target packages"
            fi
        done
    fi
    if [[ ${#keep[@]} -gt 0 ]]; then
        log "purging: ${keep[*]}"
        apt-get "${APT_LOCK_WAIT[@]}" purge -y -q "${keep[@]}"
    fi
}

# RHEL family: "rpm -e --test" fails whenever a package outside the set
# requires one of the targets, which is exactly the collateral check.
safe_purge_rpm() {
    local -a wanted=("$@") keep=()
    local pkg
    if rpm -e --test "${wanted[@]}" >/dev/null 2>&1; then
        keep=("${wanted[@]}")
    else
        for pkg in "${wanted[@]}"; do
            if rpm -e --test "$pkg" >/dev/null 2>&1; then
                keep+=("$pkg")
            else
                log "keeping ${pkg}: removing it would also remove non-target packages"
            fi
        done
        # Packages that only depend on each other (xterm + its libs) pass as a set.
        if [[ ${#keep[@]} -gt 0 ]] && ! rpm -e --test "${keep[@]}" >/dev/null 2>&1; then
            keep=()
        fi
    fi
    if [[ ${#keep[@]} -gt 0 ]]; then
        log "removing: ${keep[*]}"
        dnf -y -q remove "${keep[@]}" >/dev/null
    fi
}

# apt_autoremove - after packages were removed or upgraded: remove what no
# installed package needs any more, then purge the configuration left behind
# by removed packages ("rc" state). Debian family only; on the RHEL family
# clean_requirements_on_remove=True (configure_dnf_minimal) removes orphaned
# dependencies as part of every "dnf remove", and a blanket "dnf autoremove"
# is avoided (installer-placed packages are often marked as dependencies).
# Proxmox VE: kernels are never auto-removed - one pinned with
# proxmox-boot-tool can be marked automatic, and removing it changes what the
# node boots. Everything else goes through safe_purge, which refuses any
# removal that would take a kept kernel with it.
apt_autoremove() {
    is_deb || return 0
    local -a autorm=() rest=() residual=()
    local p
    mapfile -t autorm < <(apt-get -s autoremove --purge 2>/dev/null | awk '/^Purg /{print $2}')
    if [[ ${#autorm[@]} -gt 0 ]]; then
        if is_pve; then
            for p in "${autorm[@]}"; do
                if [[ ${p%%:*} =~ ^(proxmox-kernel-|pve-kernel-|proxmox-headers-|pve-headers-|linux-image-|linux-headers-) ]]; then
                    log "Proxmox VE: kernel package ${p} kept (kernels are never auto-removed on a node)"
                else
                    rest+=("$p")
                fi
            done
            if [[ ${#rest[@]} -gt 0 ]]; then
                log "autoremove: ${#rest[@]} unneeded package(s)"
                safe_purge "${rest[@]}"
            fi
        else
            log "autoremove: ${#autorm[@]} unneeded package(s): ${autorm[*]}"
            apt-get "${APT_LOCK_WAIT[@]}" autoremove --purge -y -q
        fi
    fi
    mapfile -t residual < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1=="rc"{print $2}')
    if [[ ${#residual[@]} -gt 0 ]]; then
        log "purging leftover configuration of ${#residual[@]} removed package(s)"
        apt-get "${APT_LOCK_WAIT[@]}" purge -y -q "${residual[@]}" >/dev/null
    fi
    return 0
}

svc_exists() { systemctl list-unit-files --no-legend "$1" 2>/dev/null | qgrep .; }

disable_service() {
    local u
    for u in "$@"; do
        if svc_exists "$u"; then
            systemctl disable --now "$u" >/dev/null 2>&1 || true
            systemctl mask "$u" >/dev/null 2>&1 || true
            log "disabled and masked ${u}"
        elif systemctl is-active --quiet "$u" 2>/dev/null; then
            # Purged package whose unit is still running (its prerm "stop"
            # was suppressed, e.g. by a policy-rc.d): the socket stays open
            # until reboot unless it is stopped here.
            systemctl stop "$u" >/dev/null 2>&1 || true
            log "stopped ${u} (left running after its package was removed)"
        fi
    done
}

# ============================================================================
# 0. Preflight (no changes are made in this section)
# ============================================================================
preflight_root() {
    step "preflight: privileges"
    [[ ${EUID} -eq 0 ]] || die "${SCRIPT_NAME} must be run as root"
    install -d -m 0700 -o root -g root "$STATE_DIR" "$CACHE_DIR"
}

preflight_os() {
    step "preflight: operating system"
    [[ -r /etc/os-release ]] || die "/etc/os-release missing"
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID=${ID:-unknown}
    OS_VERSION=${VERSION_ID:-}
    OS_MAJOR=${OS_VERSION%%.*}
    OS_CODENAME=${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}
    [[ -n $OS_MAJOR && $OS_MAJOR =~ ^[0-9]+$ ]] || die "cannot determine the ${OS_ID} release"
    case $OS_ID in
        debian|ubuntu) OS_FAMILY=deb ;;
        rhel|centos|rocky|almalinux|ol|fedora) OS_FAMILY=rhel ;;
        *)
            if [[ " ${ID_LIKE:-} " == *" rhel "* ]]; then
                OS_FAMILY=rhel
            else
                die "unsupported distribution '${OS_ID}' (Debian 12/13, Ubuntu 22.04/24.04/26.04, RHEL/CentOS Stream/Rocky/AlmaLinux/Oracle Linux 8-10 or Fedora 41+ required)"
            fi
            ;;
    esac
    if is_deb; then
        [[ -n $OS_CODENAME ]] || die "cannot determine the ${OS_ID} codename"
    fi
    case $OS_ID in
        debian)
            (( OS_MAJOR >= 12 )) || die "Debian ${OS_MAJOR} is not supported (Debian 12 or newer required)"
            OS_NUM=$OS_MAJOR
            OS_NAME="Debian ${OS_MAJOR}"
            SSG_PRODUCT="debian${OS_MAJOR}"
            : "${NTP_SERVERS:=0.debian.pool.ntp.org 1.debian.pool.ntp.org 2.debian.pool.ntp.org 3.debian.pool.ntp.org}"
            ;;
        ubuntu)
            [[ $OS_VERSION =~ ^[0-9]+\.[0-9]+$ ]] || die "cannot parse Ubuntu version '${OS_VERSION}'"
            OS_NUM=$(( 10#${OS_VERSION%%.*} * 100 + 10#${OS_VERSION#*.} ))
            (( OS_NUM >= 2204 )) || die "Ubuntu ${OS_VERSION} is not supported (Ubuntu 22.04 or newer required)"
            OS_NAME="Ubuntu ${OS_VERSION}"
            SSG_PRODUCT="ubuntu${OS_VERSION/./}"
            if [[ ${VERSION:-} != *LTS* ]]; then
                warn "Ubuntu ${OS_VERSION} is an interim (non-LTS) release: supported on a best-effort basis"
            fi
            # Empty NTP_SERVERS keeps the vendor chrony sources (NTS on 25.10+).
            ;;
        *)
            # RHEL family (ID allow-list or ID_LIKE=rhel), Fedora.
            if [[ $OS_ID == fedora ]]; then
                (( OS_MAJOR >= 41 )) || die "Fedora ${OS_VERSION} is not supported (Fedora 41 or newer required)"
            else
                (( OS_MAJOR >= 8 )) || die "${NAME:-$OS_ID} ${OS_VERSION} is not supported (release 8 or newer required)"
            fi
            OS_NUM=$OS_MAJOR
            OS_NAME="${NAME:-$OS_ID} ${OS_VERSION}"
            case $OS_ID in
                rocky)     SSG_PRODUCT="rl${OS_MAJOR}" ;;
                almalinux) SSG_PRODUCT="almalinux${OS_MAJOR}" ;;
                centos)    SSG_PRODUCT="cs${OS_MAJOR}" ;;
                ol)        SSG_PRODUCT="ol${OS_MAJOR}" ;;
                fedora)    SSG_PRODUCT="fedora" ;;
                *)         SSG_PRODUCT="rhel${OS_MAJOR}" ;;
            esac
            ADMIN_GROUP=wheel
            SSH_UNIT=sshd
            ;;
    esac
    case $DESKTOP_MODE in
        1) DESKTOP=1 ;;
        0) DESKTOP=0 ;;
        *) if desktop_detected; then DESKTOP=1; fi ;;
    esac
    if [[ $OS_ID == debian ]]; then
        case $PROXMOX_MODE in
            1) PVE=1 ;;
            0) PVE=0 ;;
            *) if pve_detected; then PVE=1; fi ;;
        esac
        if [[ $PROXMOX_MODE != 0 ]] && ! pve_detected && pbs_detected; then
            PVE=1; PBS=1
            # PBS ships its own repositories (pbs-enterprise/no-subscription);
            # the PVE repository logic must not add pve/ceph sources here.
            PVE_REPO=keep
        fi
    elif [[ $PROXMOX_MODE == 1 ]]; then
        die "PROXMOX_MODE=1 but this is ${OS_ID}: Proxmox VE runs on Debian only"
    fi
    if is_pbs; then
        OS_NAME="Proxmox Backup Server $(dpkg-query -W -f='${Version}' proxmox-backup-server 2>/dev/null || true) on ${OS_NAME}"
    elif is_pve; then
        PVE_VERSION=$(pveversion 2>/dev/null | sed -n -E 's#^pve-manager/([0-9][0-9.]*).*#\1#p' | head -n1)
        OS_NAME="Proxmox VE ${PVE_VERSION:-(version unknown)} on ${OS_NAME}"
    fi
    if is_rhel && dnf --version 2>/dev/null | head -n1 | qgrep -i dnf5; then DNF5=1; fi
    # Container and Kubernetes hosts: resolved before any change is made, so
    # forwarding, overlayfs, routed firewall traffic and cluster ports survive.
    CONTAINER_RUNTIMES=$(container_runtimes_detected)
    case $KUBERNETES_MODE in
        1) K8S=1; K8S_DISTRO=$(k8s_detected); K8S_DISTRO=${K8S_DISTRO:-kubeadm} ;;
        0) K8S=0 ;;
        *) K8S_DISTRO=$(k8s_detected); [[ -n $K8S_DISTRO ]] && K8S=1 ;;
    esac
    if is_k8s && k8s_control_plane_detected; then K8S_CONTROL=1; fi
    case $ALLOW_CONTAINERS in
        1|0) ;;
        *) if is_k8s || [[ -n $CONTAINER_RUNTIMES ]]; then ALLOW_CONTAINERS=1; else ALLOW_CONTAINERS=0; fi ;;
    esac
    if is_k8s && [[ $ALLOW_CONTAINERS != 1 ]]; then
        warn "ALLOW_CONTAINERS=0 on a Kubernetes node would cut pod networking: kept at 1"
        ALLOW_CONTAINERS=1
    fi
    if [[ -z $SCAP_PROFILE ]]; then
        if is_desktop; then
            if is_rhel; then SCAP_PROFILE=cis_workstation_l2; else SCAP_PROFILE=cis_level2_workstation; fi
        elif is_rhel; then
            SCAP_PROFILE=cis
        else
            SCAP_PROFILE=cis_level2_server
        fi
    fi
    if [[ -z $ACCOUNT_INACTIVE_DAYS ]]; then
        if is_fedora; then ACCOUNT_INACTIVE_DAYS=30; else ACCOUNT_INACTIVE_DAYS=45; fi
    fi
    if [[ -z $SSH_LOGLEVEL ]]; then
        if is_rhel; then SSH_LOGLEVEL=VERBOSE; else SSH_LOGLEVEL=INFO; fi
    fi
    if is_rhel; then
        case $(uname -m) in
            x86_64) DEB_ARCH=amd64 ;; aarch64) DEB_ARCH=arm64 ;; *) DEB_ARCH=$(uname -m) ;;
        esac
    else
        DEB_ARCH=$(dpkg --print-architecture)
    fi
    UID_MIN_VALUE=$(awk '/^[[:space:]]*UID_MIN[[:space:]]/{print $2}' /etc/login.defs 2>/dev/null || true)
    UID_MIN_VALUE=${UID_MIN_VALUE:-1000}
    log "${OS_NAME}${OS_CODENAME:+ (${OS_CODENAME})} ${DEB_ARCH}, ${OS_FAMILY} family; container=$(in_container && echo yes || echo no); desktop=$(is_desktop && echo yes || echo no)"
    if is_desktop; then
        log "desktop mode: the graphical session, printing, Bluetooth, USB storage, network discovery and toolbox/podman stay (DESKTOP_MODE=0 hardens it as a server)"
    fi
    if is_pve; then
        log "Proxmox VE mode: root keeps SSH (cluster/migration), pve-firewall stays the firewall (no UFW), guest storage, IP forwarding, NFS/rpcbind and Proxmox repositories are respected (PROXMOX_MODE=0 disables)"
    fi
    if containers_on; then
        log "container host (${CONTAINER_RUNTIMES:-runtime not installed yet}): overlayfs, IP forwarding and routed container traffic are kept; container storage is never scanned or modified (ALLOW_CONTAINERS=0 disables)"
    fi
    if is_k8s; then
        log "Kubernetes node (${K8S_DISTRO}, $( ((K8S_CONTROL)) && echo control plane || echo worker)): cluster and CNI ports stay open, pod networks are trusted, rp_filter is loose, SELinux mode is not raised (KUBERNETES_MODE=0 disables)"
    fi
}

# Interactive accounts that may log in (UID >= UID_MIN, real shell, not locked).
interactive_users() {
    awk -F: -v min="$UID_MIN_VALUE" '$3 >= min && $3 != 65534 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd
}

preflight_admin() {
    step "preflight: anti-lockout administrator check"
    ROOT_SSH=no
    if [[ $HARDEN_SKIP_ADMIN_CHECK == 1 ]]; then
        if is_pve; then
            pve_root_ssh 0
            return 0
        fi
        warn "HARDEN_SKIP_ADMIN_CHECK=1: root SSH login will be disabled without verifying another administrator exists"
        return 0
    fi
    local u home hash ok=0
    local -a members
    IFS=',' read -r -a members <<<"$(getent group "$ADMIN_GROUP" | cut -d: -f4)"
    for u in "${members[@]}"; do
        [[ -z $u ]] && continue
        id "$u" >/dev/null 2>&1 || continue
        [[ $(id -u "$u") -ge $UID_MIN_VALUE ]] || continue
        home=$(getent passwd "$u" | cut -d: -f6)
        hash=$(getent shadow "$u" | cut -d: -f2)
        if [[ -s ${home}/.ssh/authorized_keys || $hash == \$* ]]; then
            log "administrator '${u}' (${ADMIN_GROUP} group, has $( [[ -s ${home}/.ssh/authorized_keys ]] && echo 'SSH key' || echo 'password')) will retain access"
            ok=1
        fi
    done
    if is_pve; then
        # Root must keep SSH on a Proxmox VE node, so no lockout is possible.
        pve_root_ssh "$ok"
    elif [[ $ok -ne 1 ]]; then
        die "no non-root member of group '${ADMIN_GROUP}' with an SSH key or password exists. Root SSH login is about to be disabled, which would lock you out. Create one first, e.g.: useradd -m admin && passwd admin && usermod -aG ${ADMIN_GROUP} admin"
    fi
    if [[ $SSH_DISABLE_PASSWORD == 1 ]]; then
        for u in "${members[@]}"; do
            [[ -z $u ]] && continue
            home=$(getent passwd "$u" | cut -d: -f6)
            [[ -s ${home}/.ssh/authorized_keys ]] || die "SSH_DISABLE_PASSWORD=1 but ${ADMIN_GROUP} user '${u}' has no authorized_keys"
        done
    fi
}

# pve_root_ssh ADMIN_OK - effective PermitRootLogin on Proxmox VE. Cluster
# join, live/secure migration, replication, the node shell and console
# proxying all run as root over SSH between nodes (key based), and root@pam
# is the web UI's built-in administrator, so root is never disabled.
pve_root_ssh() {
    case $PVE_ROOT_SSH in
        yes|prohibit-password) ROOT_SSH=$PVE_ROOT_SSH ;;
        auto) if [[ $1 == 1 ]]; then ROOT_SSH=prohibit-password; else ROOT_SSH=yes; fi ;;
        *) die "PVE_ROOT_SSH must be auto, yes or prohibit-password (got '${PVE_ROOT_SSH}')" ;;
    esac
    log "Proxmox VE: root SSH login stays enabled (PermitRootLogin ${ROOT_SSH}); cluster, migration and replication use root keys"
    if [[ $ROOT_SSH == yes ]]; then
        warn "Proxmox VE: no non-root ${ADMIN_GROUP} administrator with a key or password, so root keeps SSH password login (PermitRootLogin yes). Add one to restrict root to keys (PVE_ROOT_SSH=prohibit-password)"
    fi
    # /root/.ssh/authorized_keys links to /etc/pve/priv/authorized_keys, which
    # always holds the cluster nodes' keys, so it says nothing about whether
    # an operator can still log in as root. Warn whenever root is key-only.
    if [[ $ROOT_SSH == prohibit-password && -z $PVE_ROOT_PASSWORD_FROM ]]; then
        warn "Proxmox VE: root SSH is key-only (PermitRootLogin prohibit-password); root password SSH logins will be refused after sshd reloads. Add your key to root, or set PVE_ROOT_PASSWORD_FROM=<CIDRs> to keep root password login from trusted networks"
    fi
    local hash
    hash=$(getent shadow root | cut -d: -f2)
    [[ $hash == \$* ]] || warn "Proxmox VE: root has no usable password - the web UI login root@pam will not work"
}

detect_ssh_ports() {
    step "preflight: detect SSH listening port(s)"
    local p
    if command -v sshd >/dev/null 2>&1 && install -d -m 0755 /run/sshd && sshd -T >/dev/null 2>&1; then
        mapfile -t SSH_PORTS < <(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un)
    fi
    # Socket activation (Ubuntu 22.10+): the listening port may come from an
    # ssh.socket drop-in that sshd -T knows nothing about.
    if systemctl is-enabled --quiet ssh.socket 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null; then
        local -a sock
        mapfile -t sock < <(systemctl show -p Listen --value ssh.socket 2>/dev/null | tr ' ' '\n' \
            | sed -n -E 's/^.*[:]([0-9]+)$/\1/p; s/^([0-9]+)$/\1/p' | sort -un)
        if [[ ${#sock[@]} -gt 0 ]]; then
            mapfile -t SSH_PORTS < <(printf '%s\n' "${SSH_PORTS[@]}" "${sock[@]}" | awk 'NF' | sort -un)
        fi
    fi
    if [[ ${#SSH_PORTS[@]} -eq 0 ]]; then
        if [[ -n ${SSH_CONNECTION:-} ]]; then
            p=$(awk '{print $4}' <<<"$SSH_CONNECTION")
            SSH_PORTS=("$p")
        else
            SSH_PORTS=(22)
        fi
    fi
    log "SSH port(s): ${SSH_PORTS[*]}"
}

preflight_ipv6() {
    step "preflight: IPv6 router-advertisement safety"
    case $KEEP_IPV6_RA in
        1) KEEP_RA=1 ;;
        0) KEEP_RA=0 ;;
        *)
            KEEP_RA=0
            # Keep RA/SLAAC if the host relies on it for addressing or routing,
            # otherwise accept_ra=0 would silently drop IPv6 connectivity.
            if ip -6 addr show scope global 2>/dev/null | qgrep 'dynamic'; then
                KEEP_RA=1
            elif ip -6 route show default 2>/dev/null | qgrep 'proto ra'; then
                KEEP_RA=1
            fi
            ;;
    esac
    if [[ $KEEP_RA == 1 ]]; then
        warn "IPv6 SLAAC/RA is in use: router advertisements stay enabled to avoid losing connectivity (sysctl accept_ra rules will report as failed)"
    else
        log "IPv6 router advertisements are not used; they will be disabled"
    fi
}

# ============================================================================
# 1. System minimalism
# ============================================================================
configure_apt_minimal() {
    step "1.1 package manager: no recommended/weak dependencies, signatures enforced"
    if is_rhel; then
        configure_dnf_minimal
        return 0
    fi
    write_file 0644 /etc/apt/apt.conf.d/90-harden-no-recommends <<'EOF'
// Managed by harden-and-audit.sh - keep the package footprint minimal.
APT::Install-Recommends "0";
APT::Install-Suggests "0";
APT::AutoRemove::RecommendsImportant "false";
APT::AutoRemove::SuggestsImportant "false";
EOF
    # /tmp is mounted noexec: give debconf an executable scratch directory.
    install -d -m 0700 -o root -g root /var/cache/harden-and-audit/apt-tmp
    write_file 0644 /etc/apt/apt.conf.d/91-harden-noexec-tmp <<'EOF'
// Managed by harden-and-audit.sh - /tmp is noexec, run debconf templates elsewhere.
APT::ExtractTemplates::TempDir "/var/cache/harden-and-audit/apt-tmp";
EOF
}

# dnf.conf [main]: no weak dependencies, signature checks everywhere (CIS),
# and every configured repository keeps gpgcheck on.
configure_dnf_minimal() {
    local conf=/etc/dnf/dnf.conf kv f
    backup_file "$conf"
    grep -q '^\[main\]' "$conf" || printf '[main]\n' >>"$conf"
    local weak=False
    is_fedora && weak=0    # Fedora CIS (dnf5) checks the numeric form
    for kv in install_weak_deps=${weak} gpgcheck=1 localpkg_gpgcheck=1 repo_gpgcheck=0 clean_requirements_on_remove=True skip_if_unavailable=False; do
        # repo_gpgcheck=0: vendor repositories sign packages, not metadata;
        # 1 would make every mirror without signed metadata unusable.
        [[ ${kv%%=*} == repo_gpgcheck ]] && continue
        sed -i -E "/^[[:space:]]*${kv%%=*}[[:space:]]*=/d" "$conf"
        sed -i "/^\[main\]/a ${kv}" "$conf"
    done
    for f in /etc/yum.repos.d/*.repo; do
        if grep -Eq '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*0' "$f"; then
            backup_file "$f"
            sed -i -E 's/^([[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*)0/\11/' "$f"
            warn "gpgcheck was off in ${f}: turned on (unsigned packages from it will now be refused)"
        fi
    done
}

purge_graphical() {
    step "1.2 purge graphical stack (display managers, desktops, X11, Wayland, Mesa)"
    if is_desktop; then
        log "desktop mode: graphical stack and graphical.target kept"
        apt_autoremove
        return 0
    fi
    local re='^(xserver-.*|xorg|xorg-.*|x11-.*|xinit|xauth|xterm|xwayland|weston|xbase-clients|xfonts-.*|'
    re+='gdm3|lightdm.*|sddm.*|xdm|lxdm|slim|nodm|wdm|'
    re+='task-desktop|task-.*-desktop|gnome-.*|gnome|kde-.*|plasma-.*|xfce4.*|lxde.*|lxqt.*|cinnamon.*|mate-.*|budgie-.*|openbox.*|'
    re+='ubuntu-desktop.*|ubuntu-session|[a-z]+ubuntu-desktop.*|ubuntu-gnome-.*|yaru-theme-.*|'
    re+='libgtk.*|libgdk.*|gir1\.2-gtk.*|libqt[56]gui.*|libqt[56]widgets.*|libqt6opengl.*|'
    re+='libx11-.*|libxcb.*|libxau6|libxdmcp6|libxext6|libxrender1|libxfixes3|libxi6|libxrandr2|libxinerama1|libxcursor1|'
    re+='libxcomposite1|libxdamage1|libxtst6|libxt6.*|libxmu.*|libxpm4|libxkbcommon.*|libxshmfence1|libxxf86vm1|libxss1|'
    re+='libxft2|libxv1|libxvmc1|libxaw7|libxkbfile1|libxmuu1|libxfont2|libxkbcommon-x11-0|libsm6|libice6|x11proto-.*|'
    re+='libwayland-.*|libgl1.*|libglx.*|libegl.*|libgles.*|libglapi-mesa|libgl1-mesa-dri|mesa-.*|libgbm1|libdrm-.*|'
    re+='libva-x11-.*|libva-drm-.*|libvdpau.*|xkb-data|libepoxy0|libllvm[0-9]+.*)$'
    if is_rhel; then
        # RPM names: X servers/clients, display managers, desktops, toolkits,
        # X11/Wayland/Mesa client libraries.
        re='^(xorg-x11-server-.*|xorg-x11-xinit.*|xorg-x11-xauth|xorg-x11-apps|xorg-x11-utils|xorg-x11-fonts-.*|xterm.*|xwayland.*|'
        re+='gdm|lightdm.*|sddm.*|xdm|gnome-.*|kde-.*|plasma-.*|xfce4-.*|lxde-.*|lxqt-.*|cinnamon.*|mate-.*|'
        re+='gtk2|gtk3|gtk4|qt5-qtbase-gui|qt6-qtbase-gui|'
        re+='libX11|libX11-common|libX11-xcb|libxcb|libXau|libXdmcp|libXext|libXrender|libXfixes|libXi|libXrandr|libXinerama|libXcursor|'
        re+='libXcomposite|libXdamage|libXtst|libXt|libXmu|libXpm|libxkbcommon.*|libxshmfence|libXxf86vm|libXScrnSaver|'
        re+='libXft|libXv|libXaw|libxkbfile|libXfont2|libSM|libICE|xkeyboard-config|'
        re+='libwayland-.*|libglvnd.*|mesa-.*|libdrm|libva|libvdpau|libepoxy|llvm-libs)$'
    fi
    local -a candidates
    mapfile -t candidates < <(pkg_list_installed | grep -E "$re" || true)
    if [[ ${#candidates[@]} -eq 0 ]]; then
        log "no graphical packages installed"
    else
        log "graphical candidates: ${candidates[*]}"
        safe_purge "${candidates[@]}"
    fi
    if is_rhel; then
        # No "dnf autoremove": installer-placed packages are often marked as
        # dependencies, and autoremove would take real services with it.
        systemctl set-default multi-user.target >/dev/null
        return 0
    fi
    apt_autoremove
    systemctl set-default multi-user.target >/dev/null
}

purge_insecure_services() {
    step "1.3 remove legacy / insecure network services"
    local -a legacy=(telnet telnetd inetutils-telnet inetutils-telnetd rsh-client rsh-server rsh-redone-client
        rsh-redone-server talk talkd inetutils-talk inetutils-talkd tftp tftp-hpa tftpd tftpd-hpa atftpd
        xinetd openbsd-inetd inetutils-inetd nis ypserv ypbind yp-tools ftp tnftp inetutils-ftp inetutils-ftpd vsftpd
        avahi-daemon avahi-autoipd cups cups-daemon cups-browsed rpcbind nfs-kernel-server isc-dhcp-server
        kea-dhcp4-server kea-dhcp6-server snmpd squid slapd ldap-utils autofs bluez dnsmasq)
    if is_rhel; then
        legacy=(telnet telnet-server rsh rsh-server talk talk-server tftp tftp-server xinetd ypserv ypbind ftp vsftpd
            avahi avahi-autoipd cups rpcbind dhcp-server net-snmp squid openldap-servers openldap-clients autofs bluez
            dnsmasq nfs-utils)
    fi
    local -a present=() p
    for p in "${legacy[@]}"; do
        # Desktops print, discover printers/shares and use Bluetooth devices.
        if is_desktop && [[ $p =~ ^(cups.*|avahi.*|bluez)$ ]]; then continue; fi
        # Proxmox VE: rpcbind serves NFSv3 storage (nfs-common), dnsmasq the
        # SDN DHCP; both are dependencies of the management stack.
        if is_pve && [[ $p =~ ^(rpcbind|dnsmasq)$ ]]; then continue; fi
        # Proxmox Backup Server used as an NFS server: keep what /etc/exports serves.
        if is_pbs && pbs_nfs_exports && [[ $p =~ ^(rpcbind|nfs-kernel-server)$ ]]; then continue; fi
        pkg_installed "$p" && present+=("$p")
    done
    if [[ ${#present[@]} -gt 0 ]]; then
        safe_purge "${present[@]}"
    else
        log "no legacy network services installed"
    fi
    # rsync is a common admin tool: keep the client but never run the daemon.
    if is_pbs && pbs_nfs_exports; then
        log "Proxmox Backup Server: NFS server and rpcbind stay (exports in /etc/exports)"
        disable_service rsync.service bluetooth.service avahi-daemon.service avahi-daemon.socket cups.service \
            cups.socket snmpd.service
    elif is_pve; then
        log "Proxmox VE: rpcbind stays available for NFS storage"
        disable_service rsync.service bluetooth.service avahi-daemon.service avahi-daemon.socket cups.service \
            cups.socket nfs-server.service snmpd.service
    elif is_desktop; then
        disable_service rsync.service rpcbind.service rpcbind.socket nfs-server.service snmpd.service
    else
        disable_service rsync.service bluetooth.service avahi-daemon.service avahi-daemon.socket cups.service \
            cups.socket rpcbind.service rpcbind.socket nfs-server.service snmpd.service
    fi
    # STIG: no Ctrl-Alt-Del reboot, no debug shell.
    systemctl mask ctrl-alt-del.target debug-shell.service >/dev/null 2>&1 || true
    if is_ubuntu; then
        purge_ubuntu_telemetry
    fi
    if is_rhel; then
        purge_rhel_extras
    fi
    local srv
    local -a servers=(apache2 nginx bind9 samba dovecot-core squid vsftpd slapd)
    is_rhel && servers=(httpd nginx bind samba dovecot squid vsftpd openldap-servers)
    for srv in "${servers[@]}"; do
        if pkg_installed "$srv"; then
            warn "application server '${srv}' is installed and was left in place; CIS expects it removed if not required"
        fi
    done
    # Dependencies only the purged services needed (Ubuntu telemetry included).
    apt_autoremove
}

# RHEL family (CIS): crash reporting (abrt), SELinux troubleshooting daemons
# that run as root (setroubleshoot) and the MLS translation service.
purge_rhel_extras() {
    local -a present=()
    local p
    while read -r p; do present+=("$p"); done < <(pkg_list_installed | grep -E '^(abrt.*|setroubleshoot.*|mcstrans)$' || true)
    if [[ ${#present[@]} -gt 0 ]]; then
        safe_purge "${present[@]}"
    fi
    disable_service abrtd.service abrt-journal-core.service abrt-oops.service mcstransd.service
    return 0
}

# Ubuntu: crash reporting and telemetry. apport also replaces the kernel's
# core_pattern with a pipe, which defeats the "no core dumps" control.
# snapd is deliberately kept: cloud management agents (e.g. the SSM agent
# on Ubuntu AMIs) ship as snaps, and removing it can cut the admin path.
purge_ubuntu_telemetry() {
    local -a present=()
    local p
    for p in apport apport-symptoms python3-apport whoopsie popularity-contest ubuntu-report; do
        pkg_installed "$p" && present+=("$p")
    done
    if [[ ${#present[@]} -gt 0 ]]; then
        safe_purge "${present[@]}"
    fi
    # Whatever had to stay installed (dependency-protected) is switched off.
    if pkg_installed apport; then
        if [[ -f /etc/default/apport ]]; then
            backup_file /etc/default/apport
            sed -i -E 's/^enabled=.*/enabled=0/' /etc/default/apport
        fi
        disable_service apport.service apport-autoreport.path apport-autoreport.service apport-forward.socket
    fi
    disable_service whoopsie.service whoopsie.path
    # motd-news fetches content from Canonical on logins and from a timer.
    if [[ -f /etc/default/motd-news ]]; then
        backup_file /etc/default/motd-news
        sed -i -E 's/^ENABLED=.*/ENABLED=0/' /etc/default/motd-news
    fi
    disable_service motd-news.timer motd-news.service
    return 0
}

# ============================================================================
# 2. Repositories, base stack, unattended security updates
# ============================================================================
configure_repositories() {
    if is_ubuntu; then
        configure_repositories_ubuntu
        return 0
    fi
    if is_rhel; then
        configure_repositories_rhel
        return 0
    fi
    step "2.1 official Debian repositories (stable, -updates, -security)"
    # Proxmox VE first: an enterprise repository without a subscription key
    # answers 401 and makes every "apt-get update" fail.
    is_pve && configure_repositories_pve
    apt_update
    apt_install ca-certificates debian-archive-keyring
    local keyring=/usr/share/keyrings/debian-archive-keyring.pgp
    [[ -f $keyring ]] || keyring=/usr/share/keyrings/debian-archive-keyring.gpg
    write_file 0644 /etc/apt/sources.list.d/debian.sources <<EOF
# Managed by ${SCRIPT_NAME} - official Debian ${OS_MAJOR} (${OS_CODENAME}) archives.
Types: deb
URIs: ${DEBIAN_MIRROR}
Suites: ${OS_CODENAME} ${OS_CODENAME}-updates
Components: main contrib non-free non-free-firmware
Signed-By: ${keyring}

Types: deb
URIs: ${DEBIAN_SECURITY_MIRROR}
Suites: ${OS_CODENAME}-security
Components: main contrib non-free non-free-firmware
Signed-By: ${keyring}
EOF
    # Neutralise duplicate official entries in the legacy one-line format,
    # leaving any third-party repositories untouched.
    if [[ -f /etc/apt/sources.list ]]; then
        backup_file /etc/apt/sources.list
        sed -i -E '/^[[:space:]]*deb(-src)?[[:space:]].*(deb\.debian\.org|security\.debian\.org|ftp\.[a-z.]*debian\.org|http\.debian\.net|debian-security)/s/^/# disabled by harden-and-audit (see sources.list.d\/debian.sources): /' /etc/apt/sources.list
        sed -i -E 's/^([[:space:]]*deb(-src)?[[:space:]]+cdrom:)/# disabled by harden-and-audit: \1/' /etc/apt/sources.list
    fi
    apt_update
}

pve_subscription_active() {
    command -v pvesubscription >/dev/null 2>&1 || return 1
    pvesubscription get 2>/dev/null | grep -Eiq '^[[:space:]]*status:[[:space:]]*active'
}

# Proxmox VE repositories. The enterprise repositories (PVE and Ceph) need a
# subscription; without one the node gets no updates at all and apt-get
# update fails. auto: keep enterprise with an active subscription, else
# switch to the matching no-subscription repositories (Proxmox's own
# recommendation for nodes without a subscription). Signed by the same key.
configure_repositories_pve() {
    local mode=$PVE_REPO f keyring="" c
    case $mode in auto|enterprise|no-subscription|keep) ;; *) die "PVE_REPO must be auto, enterprise, no-subscription or keep" ;; esac
    if [[ $mode == keep ]]; then
        log "Proxmox VE: repositories left as configured (PVE_REPO=keep)"
        return 0
    fi
    if [[ $mode == auto ]]; then
        if pve_subscription_active; then mode=enterprise; else mode=no-subscription; fi
    fi
    if [[ $mode == enterprise ]]; then
        log "Proxmox VE: enterprise repositories kept (subscription active or PVE_REPO=enterprise)"
        return 0
    fi
    for f in /usr/share/keyrings/proxmox-archive-keyring.gpg /etc/apt/trusted.gpg.d/proxmox-release-"${OS_CODENAME}".gpg /etc/apt/trusted.gpg.d/proxmox-*.gpg; do
        [[ -f $f ]] && { keyring=$f; break; }
    done
    [[ -n $keyring ]] || die "Proxmox VE: no Proxmox archive keyring found (proxmox-archive-keyring); cannot configure the no-subscription repository safely"
    local -a ceph=()
    # One-line format: comment out enterprise entries, remember Ceph releases
    # (also from entries a previous run already disabled - re-runs must keep
    # the Ceph no-subscription repository).
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
        [[ -f $f ]] || continue
        grep -q 'enterprise\.proxmox\.com' "$f" || continue
        while read -r c; do ceph+=("$c"); done < <(grep -Eo 'enterprise\.proxmox\.com/debian/ceph-[a-z]+' "$f" | grep -Eo 'ceph-[a-z]+$')
        grep -Eq '^[[:space:]]*deb[[:space:]].*enterprise\.proxmox\.com' "$f" || continue
        backup_file "$f"
        sed -i -E 's@^([[:space:]]*deb[[:space:]].*enterprise\.proxmox\.com.*)$@# disabled by harden-and-audit (no Proxmox subscription, see harden-proxmox.sources): \1@' "$f"
        log "Proxmox VE: enterprise repository disabled in ${f}"
    done
    # deb822: "Enabled: no" in every stanza that points at the enterprise server.
    for f in /etc/apt/sources.list.d/*.sources; do
        [[ -f $f && $f != */harden-proxmox.sources ]] || continue
        grep -q 'enterprise\.proxmox\.com' "$f" || continue
        while read -r c; do ceph+=("$c"); done < <(grep -Eo 'enterprise\.proxmox\.com/debian/ceph-[a-z]+' "$f" | grep -Eo 'ceph-[a-z]+$')
        if awk 'BEGIN { RS = ""; bad = 0 } /enterprise\.proxmox\.com/ && !/(^|\n)Enabled:[[:space:]]*no/ { bad = 1 } END { exit !bad }' "$f"; then
            backup_file "$f"
            awk 'BEGIN { RS = ""; ORS = "\n\n" } /enterprise\.proxmox\.com/ { gsub(/(^|\n)Enabled:[^\n]*/, ""); sub(/^\n/, ""); $0 = $0 "\nEnabled: no" } { print }' "$f" >"${f}.harden.tmp"
            cat "${f}.harden.tmp" >"$f"
            rm -f "${f}.harden.tmp"
            log "Proxmox VE: enterprise repository disabled in ${f}"
        fi
    done
    # Existing enabled no-subscription entries are not duplicated.
    local have_pve=0 enabled
    enabled=$(apt_enabled_sources)
    grep -Eq 'download\.proxmox\.com/debian/pve[[:space:]].*pve-no-subscription' <<<"$enabled" && have_pve=1
    {
        echo "# Managed by ${SCRIPT_NAME} - Proxmox VE ${OS_CODENAME} without a subscription."
        echo "# Set PVE_REPO=enterprise (or buy a subscription and re-run) for the enterprise repositories."
        if [[ $have_pve == 0 ]]; then
            printf '\nTypes: deb\nURIs: http://download.proxmox.com/debian/pve\nSuites: %s\nComponents: pve-no-subscription\nSigned-By: %s\n' "$OS_CODENAME" "$keyring"
        fi
        local r
        for r in $(printf '%s\n' "${ceph[@]}" | sort -u); do
            grep -Eq "download\.proxmox\.com/debian/${r}[[:space:]].*no-subscription" <<<"$enabled" && continue
            printf '\nTypes: deb\nURIs: http://download.proxmox.com/debian/%s\nSuites: %s\nComponents: no-subscription\nSigned-By: %s\n' "$r" "$OS_CODENAME" "$keyring"
        done
    } | write_file 0644 /etc/apt/sources.list.d/harden-proxmox.sources
    log "Proxmox VE: no subscription - using the pve-no-subscription repository$( [[ ${#ceph[@]} -gt 0 ]] && echo " and Ceph no-subscription")"
}

# Enabled apt entries as "URI suite components" lines (one-line and deb822).
apt_enabled_sources() {
    local f
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
        [[ -f $f ]] && awk '$1 == "deb" { $1 = ""; sub(/\[[^]]*\][[:space:]]*/, ""); print }' "$f"
    done
    for f in /etc/apt/sources.list.d/*.sources; do
        [[ -f $f && $f != */harden-proxmox.sources ]] || continue
        awk 'BEGIN { RS = "" } !/(^|\n)Enabled:[[:space:]]*no/ {
            u = ""; su = ""; c = ""
            n = split($0, l, "\n")
            for (i = 1; i <= n; i++) {
                if (l[i] ~ /^URIs:/) { u = l[i]; sub(/^URIs:[[:space:]]*/, "", u) }
                if (l[i] ~ /^Suites:/) { su = l[i]; sub(/^Suites:[[:space:]]*/, "", su) }
                if (l[i] ~ /^Components:/) { c = l[i]; sub(/^Components:[[:space:]]*/, "", c) }
            }
            print u, su, c }' "$f"
    done
}

# current_ubuntu_mirror SUITE - print the first enabled, configured Ubuntu
# archive URI that serves SUITE (deb822 *.sources or one-line sources.list).
current_ubuntu_mirror() {
    local suite=$1 f uri
    # ubuntu.sources is the official file; other *.sources files only count
    # when signed by the Ubuntu archive key (never a PPA or third party).
    for f in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/*.sources; do
        [[ -f $f ]] || continue
        uri=$(awk -v s="$suite" -v official="$([[ $f == */ubuntu.sources ]] && echo 1 || echo 0)" '
            BEGIN { RS = ""; FS = "\n" }
            {
                uri = ""; ok = 0; en = 1; key = official
                for (i = 1; i <= NF; i++) {
                    if ($i ~ /^URIs:/)    { v = $i; sub(/^URIs:[[:space:]]*/, "", v); split(v, u, /[[:space:]]+/); uri = u[1] }
                    if ($i ~ /^Suites:/)  { n = split($i, w, /[[:space:]]+/); for (j = 2; j <= n; j++) if (w[j] == s) ok = 1 }
                    if ($i ~ /^Enabled:[[:space:]]*no/) en = 0
                    if ($i ~ /^Signed-By:.*ubuntu-archive-keyring/) key = 1
                }
                if (ok && en && key && uri ~ /ubuntu/ && uri !~ /launchpad/) { print uri; exit }
            }' "$f")
        if [[ -n $uri ]]; then
            printf '%s\n' "$uri"
            return 0
        fi
    done
    [[ -f /etc/apt/sources.list ]] || return 0
    # One-line format: an archive path (.../ubuntu or .../ubuntu-ports) with
    # the "main" component; PPAs and vendor repositories never qualify.
    awk -v s="$suite" '
        $1 == "deb" {
            i = 2
            if ($2 ~ /^\[/) { while (i <= NF && $i !~ /\]$/) i++; i++ }
            main = 0
            for (j = i + 2; j <= NF; j++) if ($j == "main") main = 1
            if ($(i + 1) == s && main && $i ~ /\/ubuntu(-ports)?\/?$/ && $i !~ /launchpad/) { print $i; exit }
        }' /etc/apt/sources.list
}

# disable_ubuntu_oneline MIRROR SECURITY - comment out one-line entries for
# this release that point at *.ubuntu.com or at the detected mirrors.
disable_ubuntu_oneline() {
    local f=/etc/apt/sources.list tmp
    [[ -f $f ]] || return 0
    backup_file "$f"
    tmp=$(mktemp)
    awk -v c="$OS_CODENAME" -v m="${1%/}" -v sm="${2%/}" '
        /^[[:space:]]*deb(-src)?[[:space:]]/ {
            i = 2
            if ($2 ~ /^\[/) { while (i <= NF && $i !~ /\]$/) i++; i++ }
            uri = $i; sub(/\/$/, "", uri); suite = $(i + 1)
            host = uri; sub(/^[a-z+]+:\/\//, "", host); sub(/\/.*/, "", host)
            if ((suite == c || suite ~ "^" c "-(updates|security|backports|proposed)$") &&
                (host ~ /(^|\.)ubuntu\.com$/ || uri == m || uri == sm)) {
                print "# disabled by harden-and-audit (see sources.list.d/ubuntu.sources): " $0
                next
            }
        }
        /^[[:space:]]*deb(-src)?[[:space:]]+cdrom:/ { print "# disabled by harden-and-audit: " $0; next }
        { print }' "$f" >"$tmp"
    cat "$tmp" >"$f"
    rm -f "$tmp"
}

configure_repositories_ubuntu() {
    step "2.1 official Ubuntu repositories (release, -updates, -security; main restricted universe multiverse)"
    local def_main def_sec mirror sec keyring
    case $DEB_ARCH in
        amd64|i386) def_main=http://archive.ubuntu.com/ubuntu;   def_sec=http://security.ubuntu.com/ubuntu ;;
        *)          def_main=http://ports.ubuntu.com/ubuntu-ports; def_sec=http://ports.ubuntu.com/ubuntu-ports ;;
    esac
    # Keep an already-configured regional/cloud/private mirror: it is often
    # the only archive reachable from a private subnet. apt verifies every
    # index against the Ubuntu archive key, so http transport is safe.
    mirror=${UBUNTU_MIRROR:-$(current_ubuntu_mirror "$OS_CODENAME")}
    sec=${UBUNTU_SECURITY_MIRROR:-$(current_ubuntu_mirror "${OS_CODENAME}-security")}
    mirror=${mirror:-$def_main}
    sec=${sec:-$def_sec}
    mirror=${mirror%/}
    sec=${sec%/}
    log "Ubuntu archive: ${mirror}; security archive: ${sec}"
    apt_update
    apt_install ca-certificates ubuntu-keyring
    keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
    [[ -f $keyring ]] || die "${keyring} missing (package ubuntu-keyring)"
    write_file 0644 /etc/apt/sources.list.d/ubuntu.sources <<EOF
# Managed by ${SCRIPT_NAME} - official Ubuntu ${OS_VERSION} (${OS_CODENAME}) archives.
Types: deb
URIs: ${mirror}
Suites: ${OS_CODENAME} ${OS_CODENAME}-updates
Components: main restricted universe multiverse
Signed-By: ${keyring}

Types: deb
URIs: ${sec}
Suites: ${OS_CODENAME}-security
Components: main restricted universe multiverse
Signed-By: ${keyring}
EOF
    # Neutralise the official entries in the legacy one-line format (the
    # Ubuntu 22.04 default), leaving third-party repositories untouched.
    disable_ubuntu_oneline "$mirror" "$sec"
    apt_update
}

# RHEL family: vendor BaseOS/AppStream stay as configured (often a regional
# or private mirror). CRB/PowerTools and EPEL are enabled: EPEL provides
# fail2ban, dkms and media libraries the vendor does not ship.
configure_repositories_rhel() {
    step "2.1 official EL repositories (BaseOS, AppStream, CRB) + EPEL"
    if is_fedora; then
        [[ -n $(dnf -q repolist --enabled 2>/dev/null | awk 'NR > 1') ]] \
            || die "no package repository is enabled: configure the Fedora repositories; automatic security updates are mandatory"
        log "Fedora: fedora + updates repositories (fail2ban, dkms and the media libraries are in Fedora itself)"
        configure_dnf_minimal
        pkg_refresh
        return 0
    fi
    if [[ $OS_ID == rhel ]] && command -v subscription-manager >/dev/null 2>&1; then
        if ! subscription-manager status >/dev/null 2>&1; then
            warn "this RHEL host is not registered with subscription-manager: only repositories configured locally are available"
        fi
    fi
    if [[ -z $(dnf -q repolist --enabled 2>/dev/null | awk 'NR > 1') ]]; then
        die "no package repository is enabled: register the host (subscription-manager register) or configure a mirror; automatic security updates are mandatory"
    fi
    dnf_install dnf-plugins-core
    if [[ $EPEL_ENABLE == 1 ]]; then
        local crb="" id
        for id in crb powertools PowerTools codeready-builder-for-rhel-${OS_MAJOR}-$(uname -m)-rpms; do
            if dnf -q repolist --all 2>/dev/null | awk '{print $1}' | qgrep -Fx "$id"; then
                crb=$id
                break
            fi
        done
        if [[ -n $crb ]]; then
            dnf config-manager --set-enabled "$crb" >/dev/null 2>&1 || warn "could not enable the ${crb} repository"
        elif [[ $OS_ID == rhel ]] && command -v subscription-manager >/dev/null 2>&1; then
            subscription-manager repos --enable "codeready-builder-for-rhel-${OS_MAJOR}-$(uname -m)-rpms" >/dev/null 2>&1 \
                || warn "could not enable CodeReady Builder (some EPEL packages need it)"
        fi
        if ! pkg_installed epel-release; then
            if [[ $OS_ID == rhel || $OS_ID == ol ]] && ! dnf -q list --available epel-release >/dev/null 2>&1; then
                rpm --import "https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-${OS_MAJOR}"
                dnf_install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_MAJOR}.noarch.rpm"
            else
                dnf_install epel-release
            fi
        fi
        log "EPEL enabled (set EPEL_ENABLE=0 to stay on vendor repositories only)"
    else
        warn "EPEL_ENABLE=0: fail2ban, dkms and some media libraries are not available from vendor repositories"
    fi
    configure_dnf_minimal
    pkg_refresh
}

install_base_stack() {
    step "2.2 install the hardened base server stack"
    if is_rhel; then
        install_base_stack_rhel
        return 0
    fi
    local -a pkgs=(openssh-server openssh-client tmux curl git ufw iptables fail2ban python3-systemd
        libpam-pwquality libpam-modules libpam-runtime auditd audispd-plugins unattended-upgrades
        sudo rsyslog rsyslog-gnutls logrotate cron acl vlock apparmor apparmor-utils unzip perl
        procps iproute2 kmod e2fsprogs)
    local opt
    opt=$(first_available libpam-apparmor) && pkgs+=("$opt")
    # Proxmox VE: pve-firewall owns netfilter; UFW would fight it.
    # (A Proxmox Backup Server without pve-firewall keeps UFW - pbs_uses_ufw.)
    if is_pve && ! pbs_uses_ufw; then
        local -a nf=()
        for opt in "${pkgs[@]}"; do [[ $opt == ufw ]] || nf+=("$opt"); done
        pkgs=("${nf[@]}")
    fi
    if pkg_installed chrony; then
        log "chrony is installed - it stays the time synchronisation service"
    else
        pkgs+=(systemd-timesyncd)
    fi
    apt_install "${pkgs[@]}"
    log "installing pending security updates"
    apt-get "${APT_LOCK_WAIT[@]}" -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade
    # Dependencies the upgrade made obsolete (replaced libraries, old kernels).
    apt_autoremove
}

install_base_stack_rhel() {
    local auto=dnf-automatic
    [[ $DNF5 == 1 ]] && auto=dnf5-plugin-automatic
    local -a pkgs=(openssh-server openssh-clients tmux kbd git firewalld nftables libpwquality pam
        audit rsyslog rsyslog-gnutls logrotate cronie acl unzip perl procps-ng iproute kmod e2fsprogs chrony
        "$auto" sudo policycoreutils policycoreutils-python-utils selinux-policy-targeted
        crypto-policies-scripts authselect grubby python3-systemd) opt
    # CIS EL: systemd-journal-remote available (its listener stays masked, see
    # configure_logging), a local-only MTA (postfix). cracklib-dicts: with
    # pwquality dictcheck=1 and no dictionary every password change fails
    # (minimal Fedora images lack it) - an expired password could not be renewed.
    for opt in systemd-journal-remote postfix cracklib-dicts; do
        pkg_candidate "$opt" && pkgs+=("$opt")
    done
    # EL9+ images ship curl-minimal, which conflicts with curl: keep either.
    pkg_installed curl-minimal || pkg_installed curl || pkgs+=(curl)
    # audit 4 (EL10) splits augenrules' default rules into audit-rules.
    opt=$(first_available audit-rules) && pkgs+=("$opt")
    if [[ $EPEL_ENABLE == 1 ]] || is_fedora; then
        for opt in fail2ban-server fail2ban-firewalld fail2ban-systemd; do
            pkg_candidate "$opt" && pkgs+=("$opt")
        done
    fi
    dnf_install "${pkgs[@]}"
    log "installing pending updates"
    dnf -y -q upgrade --refresh >/dev/null
}

configure_unattended_upgrades() {
    step "2.3 unattended security upgrades (daily, mandatory)"
    # Owner policy: automatic distro security updates are NOT optional. There
    # is deliberately no opt-out variable, and the run fails on a real host if
    # they are not effectively enabled (masked timers, overriding apt.conf.d).
    if is_rhel; then
        configure_dnf_automatic
        return 0
    fi
    write_file 0644 /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
// Managed by harden-and-audit.sh
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    # ${distro_codename} is expanded by unattended-upgrades, not by bash.
    local origins check
    # shellcheck disable=SC2016
    if is_ubuntu; then
        # Ubuntu security pocket, plus the ESM pockets (used only when the
        # host is attached to Ubuntu Pro; harmless otherwise).
        origins='Unattended-Upgrade::Origins-Pattern {
        "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu";
        "origin=UbuntuESMApps,archive=${distro_codename}-apps-security";
        "origin=UbuntuESM,archive=${distro_codename}-infra-security";
};'
        check='Unattended-Upgrade::Origins-Pattern:: "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu"'
    else
        local pve_origin=""
        # Proxmox VE: the Proxmox repositories (enterprise or no-subscription).
        is_pve && pve_origin='
        "origin=Proxmox,codename=${distro_codename}";'
        origins='Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Debian,codename=${distro_codename},label=Debian-Security";'"${pve_origin}"'
};'
        check='Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security,label=Debian-Security"'
    fi
    {
        echo "// Managed by ${SCRIPT_NAME} - apply official ${OS_ID^} security updates daily."
        printf '%s\n' "$origins"
        # No clear directives: these lists add to the ones in other apt.conf.d
        # files (50unattended-upgrades, other tools) instead of replacing them.
        cat <<'EOF'
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
Unattended-Upgrade::Verbose "false";
Dpkg::Options {
        "--force-confdef";
        "--force-confold";
};
EOF
    } | write_file 0644 /etc/apt/apt.conf.d/52unattended-upgrades-harden
    # apt.conf.d is read in lexical order and the last value wins: images ship
    # files such as docker-disable-periodic-update (APT::Periodic::Enable "0")
    # that silently turn updates off. Neutralise every such override (backed
    # up first), then write our values in a file that sorts last.
    rm -f /etc/apt/apt.conf.d/99zz-harden-auto-upgrades
    local f
    for f in /etc/apt/apt.conf /etc/apt/apt.conf.d/*; do
        [[ -f $f && $f != */zz-harden-auto-upgrades ]] || continue
        grep -Eq '^[[:space:]]*APT::Periodic::(Enable|Update-Package-Lists|Download-Upgradeable-Packages|Unattended-Upgrade)[[:space:]]+"?(0|false)"?' "$f" || continue
        backup_file "$f"
        sed -i -E 's@^([[:space:]]*APT::Periodic::(Enable|Update-Package-Lists|Download-Upgradeable-Packages|Unattended-Upgrade)[[:space:]]+"?(0|false)"?.*)$@// disabled by harden-and-audit (automatic security updates are mandatory): \1@' "$f"
        log "automatic security updates: neutralised an override in ${f}"
    done
    write_file 0644 /etc/apt/apt.conf.d/zz-harden-auto-upgrades <<'EOF'
// Managed by harden-and-audit.sh - read last on purpose: automatic security
// updates are mandatory and must not be overridden by another apt.conf.d file.
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    apt-config dump | qgrep -F "$check" || die "unattended-upgrades origin pattern did not take effect"
    local key val
    for key in APT::Periodic::Enable APT::Periodic::Update-Package-Lists APT::Periodic::Unattended-Upgrade; do
        val=""
        eval "$(apt-config shell val "$key")"
        [[ $val == 1 ]] || die "automatic security updates are mandatory but ${key} is '${val}' after configuration"
    done
    # Cloud/golden images often MASK the apt timers; enable fails on a masked unit.
    local u
    for u in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service; do
        systemctl unmask "$u" >/dev/null 2>&1 || true
    done
    systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
    systemctl enable unattended-upgrades.service >/dev/null 2>&1 || true
    for u in apt-daily.timer apt-daily-upgrade.timer; do
        if ! systemctl is-enabled --quiet "$u" 2>/dev/null || ! systemctl is-active --quiet "$u" 2>/dev/null; then
            in_container || die "automatic security updates are mandatory but ${u} is not enabled and active"
            warn "container: ${u} is not active here (it is enforced on a real host)"
        fi
    done
    log "automatic security updates: enabled (apt-daily + apt-daily-upgrade timers active, security origins only)"
}

# RHEL family: dnf-automatic applies updates daily. Security errata only,
# except on CentOS Stream, which publishes no errata (security-only would
# never install anything there).
configure_dnf_automatic() {
    local type=security conf=/etc/dnf/automatic.conf u timer=dnf-automatic.timer
    # dnf5 (Fedora 41+): dnf5-automatic.timer, and the plugin's own config path too.
    if [[ $DNF5 == 1 ]]; then
        timer=dnf5-automatic.timer
        systemctl cat "$timer" >/dev/null 2>&1 || timer=dnf-automatic.timer
    fi
    if [[ $OS_ID == centos ]]; then
        type=default
        log "CentOS Stream publishes no security errata: dnf-automatic applies all updates"
    fi
    write_file 0644 "$conf" <<EOF
# Managed by ${SCRIPT_NAME} - automatic updates are mandatory (owner policy).
[commands]
upgrade_type = ${type}
random_sleep = 0
network_online_timeout = 60
download_updates = yes
apply_updates = yes
reboot = never

[emitters]
emit_via = stdio
system_name = $(hostname)

[email]
email_from = root@localhost
email_to = root
email_host = localhost

[command]

[command_email]

[base]
debuglevel = 1
EOF
    if [[ $DNF5 == 1 ]]; then
        install -d -m 0755 /etc/dnf/dnf5-plugins
        write_file 0644 /etc/dnf/dnf5-plugins/automatic.conf <"$conf"
    fi
    # The timer must run: unmask (golden images mask it), enable, start.
    for u in "$timer" "${timer%.timer}.service"; do
        systemctl unmask "$u" >/dev/null 2>&1 || true
    done
    # The other dnf-automatic timers would race the managed one.
    systemctl disable --now dnf-automatic-notifyonly.timer dnf-automatic-download.timer dnf-automatic-install.timer >/dev/null 2>&1 || true
    [[ $timer == dnf-automatic.timer ]] || systemctl disable --now dnf-automatic.timer >/dev/null 2>&1 || true
    systemctl enable --now "$timer" >/dev/null 2>&1 || true
    grep -Eq '^apply_updates[[:space:]]*=[[:space:]]*yes$' "$conf" || die "automatic updates are mandatory but apply_updates is not yes in ${conf}"
    if ! systemctl is-enabled --quiet "$timer" 2>/dev/null || ! systemctl is-active --quiet "$timer" 2>/dev/null; then
        in_container || die "automatic security updates are mandatory but ${timer} is not enabled and active"
        warn "container: ${timer} is not active here (it is enforced on a real host)"
    fi
    if grep -Eq '^[[:space:]]*(exclude|excludepkgs)[[:space:]]*=' /etc/dnf/dnf.conf; then
        warn "/etc/dnf/dnf.conf excludes packages from every update (review: $(grep -E '^[[:space:]]*(exclude|excludepkgs)[[:space:]]*=' /etc/dnf/dnf.conf | tr '\n' ' '))"
    fi
    log "automatic updates: ${timer} active, upgrade_type=${type}, apply_updates=yes"
}

# ============================================================================
# 3. auditd - SCAP-aligned, non-disruptive rotation policy (owner exception)
# ============================================================================
configure_auditd() {
    step "3.1 auditd.conf (ROTATE + SYSLOG; never SUSPEND/SINGLE/HALT)"
    write_file 0640 /etc/audit/auditd.conf <<'EOF'
#
# Managed by harden-and-audit.sh
#
# Owner policy: auditing must NEVER suspend logging, drop the host into
# single-user mode, or halt it under disk pressure - losing remote access is
# a worse outcome than a syslog alert. Logs rotate at 20 MB, 10 files kept.
#
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 20
num_logs = 10
priority_boost = 4
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 500
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 250
admin_space_left_action = SYSLOG
disk_full_action = SYSLOG
disk_error_action = SYSLOG
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
transport = TCP
distribute_network = no
q_depth = 2000
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d
end_of_event_timeout = 2
EOF
    # Hard guarantee: no disruptive action may ever be configured.
    if grep -Eiq '^[[:space:]]*[a-z_]*action[[:space:]]*=[[:space:]]*(suspend|single|halt)' /etc/audit/auditd.conf; then
        die "forbidden auditd action (SUSPEND/SINGLE/HALT) present in auditd.conf"
    fi
    grep -Eq '^max_log_file = 20$' /etc/audit/auditd.conf
    grep -Eq '^max_log_file_action = ROTATE$' /etc/audit/auditd.conf
    install -d -m 0700 -o root -g root /var/log/audit
    chmod 0700 /var/log/audit
    find /var/log/audit -type f -exec chmod 0600 {} + -exec chown root:root {} +
    chmod 0640 /etc/audit/auditd.conf
}

configure_audit_rules() {
    step "3.2 audit rules (CIS L2 / STIG set, immutable)"
    local uid=$UID_MIN_VALUE rules_dir=/etc/audit/rules.d
    install -d -m 0750 "$rules_dir"
    # Debian's stock rules.d/audit.rules is superseded by 10-harden-base.rules.
    if [[ -f ${rules_dir}/audit.rules ]]; then
        backup_file "${rules_dir}/audit.rules"
        rm -f "${rules_dir}/audit.rules"
    fi
    write_file 0640 ${rules_dir}/10-harden-base.rules <<'EOF'
## Managed by harden-and-audit.sh
## Remove existing rules, size the backlog for bursts, and on audit failure
## only log to the kernel ring buffer (-f 1). -f 2 (panic) is forbidden by
## the owner's no-halt policy. backlog_wait_time 0: when the backlog is full
## the kernel drops the record and logs it instead of blocking every audited
## process for up to 60 s (a stalled auditd would otherwise freeze sshd and
## every service: a hung cloud machine).
-D
-b 8192
--backlog_wait_time 0
-f 1
## Keep loading the remaining rules if one rule is rejected (e.g. a syscall
## unknown to an older kernel) instead of leaving the host unaudited.
-c
EOF
    write_file 0640 ${rules_dir}/50-harden.rules <<EOF
## Managed by ${SCRIPT_NAME} - CIS Debian Level 2 Server / DISA STIG aligned rules.

## --- Time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change

## --- User / group / authentication database changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d/ -p wa -k identity

## --- Network environment
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -F auid>=${uid} -F auid!=unset -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -F auid>=${uid} -F auid!=unset -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
$(for d in /etc/network/ /etc/NetworkManager /etc/NetworkManager/system-connections/ /etc/sysconfig/network /etc/sysconfig/network-scripts; do
    if [[ -e $d ]]; then echo "-w ${d} -p wa -k system-locale"; fi
done)

## --- Mandatory access control (AppArmor / SELinux)
$(for d in /etc/apparmor /etc/apparmor.d /etc/selinux/ /usr/share/selinux/ /var/lib/selinux/; do
    if [[ -e $d ]]; then echo "-w ${d} -p wa -k MAC-policy"; fi
done)

## --- Login / logout and sessions
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

## --- Discretionary access control changes
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${uid} -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${uid} -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=${uid} -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat,chown32,fchown32,lchown32 -F auid>=${uid} -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${uid} -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${uid} -F auid!=unset -k perm_mod

## --- Unsuccessful file access attempts
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=unset -k access

## --- Mounts / media export
-a always,exit -F arch=b64 -S mount,umount2 -F auid>=${uid} -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount,umount,umount2 -F auid>=${uid} -F auid!=unset -k mounts

## --- File deletion by users
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=${uid} -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=${uid} -F auid!=unset -k delete

## --- Kernel module loading / unloading
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${uid} -F auid!=unset -k kernel_modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${uid} -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${uid} -F auid!=unset -k kernel_modules

## --- Privilege escalation / user emulation
-a always,exit -F arch=b64 -C uid!=euid -F euid=0 -S execve -k setuid
-a always,exit -F arch=b32 -C uid!=euid -F euid=0 -S execve -k setuid
-a always,exit -F arch=b64 -C gid!=egid -F egid=0 -S execve -k setgid
-a always,exit -F arch=b32 -C gid!=egid -F egid=0 -S execve -k setgid
-a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=unset -k user_emulation
-a always,exit -F arch=b32 -S execve -C euid!=uid -F auid!=unset -k user_emulation

## --- Sudoers scope and sudo log
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k sudo_log_file

## --- Permission / ACL / user modification tools
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${uid} -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${uid} -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${uid} -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${uid} -F auid!=unset -k usermod
EOF
    # EL content checks the syscall form of every watch, for both ABIs:
    # "-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity"
    # (dir= with a trailing slash for directories).
    if is_rhel; then
        install -d -m 0755 /etc/sysconfig/network-scripts /var/run/faillock /etc/NetworkManager/system-connections
        [[ -e /etc/sysconfig/network ]] || : >/etc/sysconfig/network
        audit_watches_to_syscall ${rules_dir}/50-harden.rules
    fi
    # Syscalls added in Linux 6.6 (fchmodat2) / 3.15 (renameat2): emitted only
    # for the architectures whose syscall table the installed audit userspace
    # knows (fchmodat2 is unknown before audit 4.x, e.g. Ubuntu 22.04/24.04).
    local -a newrules=()
    local sc key abi tbl
    for sc in fchmodat2:perm_mod renameat2:delete; do
        key=${sc#*:}
        sc=${sc%%:*}
        for abi in b64 b32; do
            case $DEB_ARCH:$abi in
                amd64:b64) tbl=x86_64 ;; amd64:b32) tbl=i386 ;;
                arm64:b64) tbl=aarch64 ;; arm64:b32) tbl=arm ;;
                *) continue ;;
            esac
            if ausyscall "$tbl" "$sc" >/dev/null 2>&1; then
                newrules+=("-a always,exit -F arch=${abi} -S ${sc} -F auid>=${uid} -F auid!=unset -k ${key}")
            fi
        done
    done
    # Ubuntu and EL CIS also audit extended-attribute changes made as root (auid=0).
    if is_ubuntu || is_rhel; then
        newrules+=("-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid=0 -k perm_mod"
                   "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid=0 -k perm_mod")
    fi
    if [[ ${#newrules[@]} -gt 0 ]]; then
        { echo "## Managed by ${SCRIPT_NAME}"; printf '%s\n' "${newrules[@]}"; } | write_file 0600 ${rules_dir}/51-harden-new-syscalls.rules
    else
        rm -f ${rules_dir}/51-harden-new-syscalls.rules
    fi
    # Ubuntu network configuration lives in netplan (created if absent, so
    # the watch is valid and catches the first configuration written).
    if is_ubuntu; then
        install -d -m 0755 -o root -g root /etc/netplan
    fi
    if [[ -d /etc/netplan ]]; then
        printf '## Managed by %s\n-w /etc/netplan/ -p wa -k system-locale\n' "$SCRIPT_NAME" \
            | write_file 0600 ${rules_dir}/52-harden-netplan.rules
    fi
    # Privileged (setuid/setgid) commands on every local filesystem.
    local -a mounts files
    # Never container layers or guest storage: their setuid files are not the host's.
    mapfile -t mounts < <(host_fs_mounts '^(ext[234]|xfs|btrfs|overlay|zfs|f2fs|jfs|reiserfs)$')
    [[ ${#mounts[@]} -eq 0 ]] && mounts=(/)
    mapfile -t files < <(for m in "${mounts[@]}"; do find "$m" -xdev \( -regextype posix-extended -regex "$CONTAINER_PATH_RE" -o -regex "$(is_pve && echo "$PVE_GUEST_PATH_RE" || echo '^$')" \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null || true; done | sort -u)
    {
        echo "## Managed by ${SCRIPT_NAME} - generated $(ts): setuid/setgid binaries"
        local f
        for f in "${files[@]}"; do
            echo "-a always,exit -F path=${f} -F perm=x -F auid>=${uid} -F auid!=unset -k privileged"
        done
    } | write_file 0640 ${rules_dir}/55-harden-privileged.rules
    write_file 0640 ${rules_dir}/99-harden-finalize.rules <<'EOF'
## Managed by harden-and-audit.sh - make the configuration immutable until reboot.
-e 2
EOF
    chmod 0600 ${rules_dir}/*.rules
    augenrules --check >/dev/null 2>&1 || true

    systemctl enable auditd.service >/dev/null 2>&1 || true
    if in_container; then
        # Compile /etc/audit/audit.rules without loading into the shared kernel.
        augenrules >/dev/null
        warn "container: kernel audit is host-global; rules were compiled but not loaded"
        return 0
    fi
    if auditctl -s 2>/dev/null | qgrep '^enabled 2'; then
        warn "audit rules are immutable (-e 2) from a previous run: new rules apply at next reboot"
    elif ! is_pve; then
        augenrules --load
    else
        # Proxmox VE: nodes often carry rule files from an earlier CIS script
        # (50-*.rules) that repeat these rules; auditctl then reports "Rule
        # exists" and exits non-zero although every rule is loaded. Only
        # other errors fail.
        local aout
        if ! aout=$(augenrules --load 2>&1); then
            if grep -E 'Error|error' <<<"$aout" | grep -Ev 'Rule exists|There was an error in line' | qgrep .; then
                printf '%s\n' "$aout" >&2
                die "augenrules --load failed"
            fi
            warn "audit: $(grep -c 'Rule exists' <<<"$aout") duplicate rule(s) from other files in /etc/audit/rules.d were skipped (already loaded)"
        fi
    fi
    if systemctl is-active --quiet auditd; then
        # auditd refuses manual stop (RefuseManualStop); SIGHUP reloads its config.
        systemctl kill -s HUP auditd.service
    else
        systemctl start auditd.service
    fi
}

# audit_watches_to_syscall FILE - add the syscall form next to every
# "-w PATH -p PERM -k KEY" line. The EL content checks some watches as -w
# (/etc/selinux/, /etc/hosts) and others as "-F path=" (even directories such
# as /etc/NetworkManager) or "-F dir=.../" (/etc/pam.d/): a trailing slash in
# the source rule selects dir=. Both forms audit the same writes.
audit_watches_to_syscall() {
    local file=$1 tmp line path perm key field
    tmp=$(mktemp)
    while IFS= read -r line; do
        printf '%s\n' "$line"
        if [[ $line =~ ^-w[[:space:]]+([^[:space:]]+)[[:space:]]+-p[[:space:]]+([rwxa]+)[[:space:]]+-k[[:space:]]+([^[:space:]]+) ]]; then
            path=${BASH_REMATCH[1]}; perm=${BASH_REMATCH[2]}; key=${BASH_REMATCH[3]}
            field=path
            [[ $path == */ ]] && field=dir
            echo "-a always,exit -F arch=b64 -F ${field}=${path} -F perm=${perm} -k ${key}"
            echo "-a always,exit -F arch=b32 -F ${field}=${path} -F perm=${perm} -k ${key}"
        elif [[ $line =~ ^-a\ always,exit\ -F\ path=([^[:space:]]+)\ -F\ perm=x\ (.*)$ ]]; then
            # Command-execution rules: the Fedora content checks per-ABI copies.
            echo "-a always,exit -F arch=b64 -F path=${BASH_REMATCH[1]} -F perm=x ${BASH_REMATCH[2]}"
            echo "-a always,exit -F arch=b32 -F path=${BASH_REMATCH[1]} -F perm=x ${BASH_REMATCH[2]}"
        fi
    done <"$file" >"$tmp"
    cat "$tmp" >"$file"
    rm -f "$tmp"
}

# ============================================================================
# 4. FIPS cryptography
# ============================================================================
# grub_set_args VAR ARG... - set key[=value] words in the GRUB variable VAR
# (GRUB_CMDLINE_LINUX or GRUB_CMDLINE_LINUX_DEFAULT), replacing any existing
# word with the same key.
grub_set_args() {
    local var=$1 file=/etc/default/grub cur arg w key
    shift
    grep -q "^${var}=" "$file" || echo "${var}=\"\"" >>"$file"
    cur=$(sed -n "s/^${var}=\"\\(.*\\)\"[[:space:]]*\$/\\1/p" "$file" | tail -n1)
    local -a words
    read -r -a words <<<"$cur"
    for arg in "$@"; do
        key=${arg%%=*}
        local -a kept=()
        for w in "${words[@]}"; do
            [[ ${w%%=*} == "$key" ]] || kept+=("$w")
        done
        words=("${kept[@]}" "$arg")
    done
    local new="${words[*]}"
    sed -i -E "s|^${var}=.*|${var}=\"${new}\"|" "$file"
}

configure_grub() {
    step "4.1 kernel command line: fips=1, audit, MAC, memory hardening"
    if is_rhel; then
        configure_grub_rhel
        return 0
    fi
    # Proxmox VE on ZFS/UEFI boots with systemd-boot through proxmox-boot-tool:
    # its command line is /etc/kernel/cmdline, synced to every ESP on refresh.
    if is_pve && [[ -f /etc/kernel/cmdline ]]; then
        pve_kernel_cmdline
    fi
    if [[ ! -f /etc/default/grub ]]; then
        warn "GRUB is not installed (/etc/default/grub missing): kernel arguments (fips=1, audit=1, ...) must be set in this host's bootloader manually"
        return 0
    fi
    backup_file /etc/default/grub
    # GRUB_CMDLINE_LINUX applies to every boot entry, including recovery;
    # fips=1 is also put in the default (non-recovery) string, as required.
    local -a kargs
    mapfile -t kargs < <(kargs_for_host)
    kargs+=(apparmor=1 security=apparmor)
    if kernel_fips_ok; then
        grub_set_args GRUB_CMDLINE_LINUX_DEFAULT fips=1
    else
        if is_pve; then
            log "Proxmox VE: kernel FIPS mode (fips=1) not set (unsupported by Proxmox; PVE_KERNEL_FIPS=1 forces it); user-space FIPS provider stays"
        else
            log "desktop mode: kernel FIPS mode (fips=1) not set (it breaks Wi-Fi/Bluetooth algorithms); user-space FIPS provider stays"
        fi
        sed -i -E 's/(^GRUB_CMDLINE_LINUX(_DEFAULT)?="[^"]*)\bfips=1\b ?/\1/' /etc/default/grub
    fi
    grub_set_args GRUB_CMDLINE_LINUX "${kargs[@]}"
    if kernel_fips_ok; then
        grep -E '^GRUB_CMDLINE_LINUX=' /etc/default/grub | qgrep 'fips=1' || die "fips=1 was not written to GRUB_CMDLINE_LINUX"
        grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | qgrep 'fips=1' || die "fips=1 was not written to GRUB_CMDLINE_LINUX_DEFAULT"
    fi
    # Drop-ins are sourced after /etc/default/grub. Cloud images replace the
    # command line there (e.g. Ubuntu's 50-cloudimg-settings.cfg sets
    # GRUB_CMDLINE_LINUX_DEFAULT); re-append the hardening arguments last.
    local d var dropin=/etc/default/grub.d/99-harden-and-audit.cfg
    local -a lines=()
    for var in GRUB_CMDLINE_LINUX_DEFAULT GRUB_CMDLINE_LINUX; do
        for d in /etc/default/grub.d/*.cfg; do
            [[ $d == "$dropin" ]] && continue
            # An assignment that does not build on the previous value wins.
            if grep -Eq "^[[:space:]]*(export[[:space:]]+)?${var}=" "$d" \
                && ! grep -Eq "^[[:space:]]*(export[[:space:]]+)?${var}=.*\\\$\\{?${var}([^_A-Z]|\$)" "$d"; then
                log "${d} replaces ${var}; hardening arguments are re-applied by ${dropin}"
                if [[ $var == GRUB_CMDLINE_LINUX_DEFAULT ]]; then
                    kernel_fips_ok && lines+=("${var}=\"\${${var}} fips=1\"")
                else
                    lines+=("${var}=\"\${${var}} ${kargs[*]}\"")
                fi
                break
            fi
        done
    done
    if [[ ${#lines[@]} -gt 0 ]]; then
        {
            echo "# Managed by ${SCRIPT_NAME}: sourced after the other drop-ins, which"
            echo "# replace the kernel command line; re-append the hardening arguments."
            printf '%s\n' "${lines[@]}"
        } | write_file 0644 "$dropin"
    else
        rm -f "$dropin"
    fi

    if [[ $ENABLE_GRUB_PASSWORD == 1 ]]; then
        # Keep normal boots unattended: menu entries stay bootable without a
        # password; only editing and the GRUB shell require it. Every
        # generator that emits Linux entries (10_linux, Ubuntu's ZFS-root
        # 10_linux_zfs) must carry --unrestricted, or no password is set.
        local gen unrestricted_ok=1
        for gen in /etc/grub.d/10_linux /etc/grub.d/10_linux_zfs; do
            [[ -f $gen ]] || continue
            grep -q -- '--unrestricted' "$gen" && continue
            backup_file "$gen"
            sed -i -E 's/^([[:space:]]*)CLASS="--class gnu-linux --class gnu --class os"[[:space:]]*$/\1CLASS="--class gnu-linux --class gnu --class os --unrestricted"/' "$gen"
            if ! grep -q -- '--unrestricted' "$gen"; then
                if [[ $gen == */10_linux ]]; then
                    die "could not mark GRUB entries --unrestricted in ${gen} (refusing to risk an unbootable host)"
                fi
                if [[ -x $gen ]]; then
                    unrestricted_ok=0
                    warn "could not mark ${gen} entries --unrestricted: GRUB password NOT set (would block unattended boots)"
                fi
            fi
        done
        if [[ $unrestricted_ok != 1 ]]; then
            rm -f /etc/grub.d/01_harden_password
        fi
    fi

    if [[ $ENABLE_GRUB_PASSWORD == 1 && ${unrestricted_ok:-1} == 1 ]]; then
        local hash=$GRUB_PASSWORD_PBKDF2 pw
        if [[ -z $hash && -f ${STATE_DIR}/grub.pbkdf2 ]]; then
            hash=$(cat "${STATE_DIR}/grub.pbkdf2")
        fi
        if [[ -z $hash ]]; then
            pw=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
            hash=$(printf '%s\n%s\n' "$pw" "$pw" | grub-mkpasswd-pbkdf2 2>/dev/null | awk '/grub\.pbkdf2/ {print $NF}')
            [[ $hash == grub.pbkdf2.* ]] || die "could not generate GRUB password hash"
            umask 077
            printf 'GRUB superuser: %s\nGRUB password:  %s\n(Editing boot entries requires this; normal boots do not.)\n' "$GRUB_SUPERUSER" "$pw" >/root/grub-superuser-password.txt
            umask 022
            chmod 0400 /root/grub-superuser-password.txt
            warn "generated a GRUB superuser password: /root/grub-superuser-password.txt (store it in your vault and delete the file)"
        fi
        printf '%s\n' "$hash" >"${STATE_DIR}/grub.pbkdf2"
        chmod 0600 "${STATE_DIR}/grub.pbkdf2"
        write_file 0700 /etc/grub.d/01_harden_password <<EOF
#!/bin/sh
# Managed by ${SCRIPT_NAME}: protect GRUB editing/command line with a password.
cat <<'GRUBEOF'
set superusers="${GRUB_SUPERUSER}"
password_pbkdf2 ${GRUB_SUPERUSER} ${hash}
GRUBEOF
EOF
    fi

    if command -v update-grub >/dev/null 2>&1; then
        host_only "update-grub" update-grub
    else
        warn "update-grub not found; regenerate the GRUB configuration manually"
    fi
    # Proxmox VE with proxmox-boot-tool (GRUB on several ESPs): copy the
    # regenerated configuration to every ESP, or the change never boots.
    is_pve && pve_boot_refresh
    local cfg
    for cfg in /boot/grub/grub.cfg /boot/grub/user.cfg /boot/efi/EFI/debian/grub.cfg /boot/efi/EFI/ubuntu/grub.cfg; do
        if [[ -f $cfg ]]; then
            chown root:root "$cfg"
            chmod 0400 "$cfg"
        fi
    done
}

# Proxmox VE: hardening arguments in /etc/kernel/cmdline (systemd-boot).
pve_kernel_cmdline() {
    local f=/etc/kernel/cmdline a w
    local -a words kargs out
    backup_file "$f"
    read -r -a words <"$f"
    mapfile -t kargs < <(kargs_for_host)
    kargs+=(apparmor=1 security=apparmor)
    kernel_fips_ok || words=("${words[@]/fips=1/}")
    for a in "${kargs[@]}"; do
        out=()
        for w in "${words[@]}"; do
            [[ -n $w && ${w%%=*} != "${a%%=*}" ]] && out+=("$w")
        done
        words=("${out[@]}" "$a")
    done
    out=()
    for w in "${words[@]}"; do [[ -n $w ]] && out+=("$w"); done
    printf '%s\n' "${out[*]}" >"$f"
    log "Proxmox VE: kernel arguments written to ${f}"
    [[ -f /etc/default/grub ]] || pve_boot_refresh
}

# proxmox-boot-tool refresh when the node boots from proxmox-boot-tool ESPs.
PVE_BOOT_REFRESHED=0
pve_boot_refresh() {
    [[ $PVE_BOOT_REFRESHED == 1 ]] && return 0
    command -v proxmox-boot-tool >/dev/null 2>&1 || return 0
    [[ -s /etc/kernel/proxmox-boot-uuids ]] || return 0
    host_only "proxmox-boot-tool refresh" proxmox-boot-tool refresh >/dev/null
    PVE_BOOT_REFRESHED=1
    log "Proxmox VE: boot configuration synced to every ESP (proxmox-boot-tool refresh)"
}

# Kernel arguments shared by both families (the Debian family adds AppArmor;
# on the RHEL family "security=apparmor" would switch SELinux off).
KARGS_COMMON=(fips=1 audit=1 audit_backlog_limit=8192 slab_nomerge=yes pti=on page_alloc.shuffle=1
    vsyscall=none init_on_alloc=1 spectre_v2=on spec_store_bypass_disable=seccomp rng_core.default_quality=500)

# Kernel FIPS mode (fips=1) only where the distribution supports it and it
# cannot take the machine down: Fedora does not support FIPS mode (missing
# HMACs/dracut module can stop the boot), and on desktops kernel FIPS mode
# breaks Wi-Fi/Bluetooth algorithms. User-space FIPS stays in both cases.
kernel_fips_ok() {
    is_fedora && return 1
    # Proxmox VE does not support kernel FIPS mode: its kernel is untested
    # with fips=1, and corosync/knet (NSS) switching to FIPS mode at boot can
    # keep a node out of the cluster quorum. User-space FIPS stays.
    is_pve && [[ $PVE_KERNEL_FIPS != 1 ]] && return 1
    is_deb && is_desktop && return 1
    return 0
}
# kargs_for_host - KARGS_COMMON without fips=1 where kernel_fips_ok says no.
kargs_for_host() {
    local a
    for a in "${KARGS_COMMON[@]}"; do
        [[ $a == fips=1 ]] && ! kernel_fips_ok && continue
        printf '%s\n' "$a"
    done
}

# RHEL family: grubby edits every installed kernel's BLS entry; GRUB_CMDLINE_LINUX
# in /etc/default/grub carries the arguments to kernels installed later.
configure_grub_rhel() {
    local -a kargs
    mapfile -t kargs < <(kargs_for_host)
    kernel_fips_ok || log "kernel FIPS mode (fips=1) not set on this host: $(is_fedora && echo 'Fedora does not support it' || echo 'desktop')"
    # FIPS with a separate /boot: the initramfs verifies the kernel HMAC there.
    local bootdev
    if findmnt -n /boot >/dev/null 2>&1; then
        bootdev=$(findmnt -n -o UUID /boot 2>/dev/null || true)
        [[ -n $bootdev ]] && kargs+=("boot=UUID=${bootdev}")
    fi
    if [[ -f /etc/default/grub ]]; then
        backup_file /etc/default/grub
        grub_set_args GRUB_CMDLINE_LINUX "${kargs[@]}"
        # A disabled SELinux on the command line would defeat the MAC control.
        sed -i -E 's/(^GRUB_CMDLINE_LINUX="[^"]*)\b(selinux|enforcing)=0\b ?/\1/g' /etc/default/grub
        if kernel_fips_ok; then
            grep -E '^GRUB_CMDLINE_LINUX=' /etc/default/grub | qgrep 'fips=1' || die "fips=1 was not written to GRUB_CMDLINE_LINUX"
        else
            sed -i -E 's/(^GRUB_CMDLINE_LINUX="[^"]*)\bfips=1\b ?/\1/' /etc/default/grub
        fi
    else
        warn "/etc/default/grub missing: kernel arguments are applied with grubby only"
    fi
    if command -v grubby >/dev/null 2>&1; then
        host_only "grubby: add kernel arguments" grubby --update-kernel=ALL --args="${kargs[*]}"
        host_only "grubby: remove selinux=0/enforcing=0" grubby --update-kernel=ALL --remove-args="selinux enforcing"
    fi
    if [[ $ENABLE_GRUB_PASSWORD == 1 && -d /boot/grub2 ]]; then
        # What grub2-setpassword writes: only editing and the GRUB shell need
        # it; EL menu entries are unrestricted, so normal boots do not.
        local hash=$GRUB_PASSWORD_PBKDF2 pw
        if [[ -z $hash && -f ${STATE_DIR}/grub.pbkdf2 ]]; then
            hash=$(cat "${STATE_DIR}/grub.pbkdf2")
        fi
        if [[ -z $hash ]]; then
            pw=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
            hash=$(printf '%s\n%s\n' "$pw" "$pw" | grub2-mkpasswd-pbkdf2 2>/dev/null | awk '/grub\.pbkdf2/ {print $NF}')
            [[ $hash == grub.pbkdf2.* ]] || die "could not generate GRUB password hash"
            umask 077
            printf 'GRUB superuser: root\nGRUB password:  %s\n(Editing boot entries requires this; normal boots do not.)\n' "$pw" >/root/grub-superuser-password.txt
            umask 022
            chmod 0400 /root/grub-superuser-password.txt
            warn "generated a GRUB superuser password: /root/grub-superuser-password.txt (store it in your vault and delete the file)"
        fi
        printf '%s\n' "$hash" >"${STATE_DIR}/grub.pbkdf2"
        chmod 0600 "${STATE_DIR}/grub.pbkdf2"
        printf 'GRUB2_PASSWORD=%s\n' "$hash" | write_file 0600 /boot/grub2/user.cfg
    fi
    local cfg
    if [[ -f /boot/grub2/grub.cfg ]] && command -v grub2-mkconfig >/dev/null 2>&1; then
        host_only "grub2-mkconfig" grub2-mkconfig -o /boot/grub2/grub.cfg
    fi
    for cfg in /boot/grub2/grub.cfg /boot/grub2/user.cfg /boot/grub2/grubenv /boot/efi/EFI/*/grub.cfg /boot/efi/EFI/*/user.cfg; do
        if [[ -f $cfg && $cfg != /boot/efi/* ]]; then
            chown root:root "$cfg"
            chmod 0600 "$cfg"
        fi
    done
}

# fips_selftest MODULE FIPSCNF - load the provider in isolation. Loading runs
# the module's integrity check and known-answer self-tests (FIPS 140-3
# "self-test on load"); success proves the installed module is intact.
fips_selftest() {
    local module=$1 fipscnf=$2 tmp rc=0
    [[ -f $module && -f $fipscnf ]] || return 1
    tmp=$(mktemp)
    {
        echo 'openssl_conf = openssl_init'
        echo '[openssl_init]'
        echo 'providers = provider_sect'
        echo '[provider_sect]'
        echo 'fips = fips_sect'
        echo 'base = base_sect'
        echo '[base_sect]'
        echo 'activate = 1'
        sed -e "/^\[ *fips_sect *\]/a module = ${module}" "$fipscnf"
    } >"$tmp"
    OPENSSL_CONF=$tmp openssl list -providers 2>/dev/null | grep -A3 -E '^[[:space:]]*fips$' | qgrep 'status: active' || rc=1
    echo selftest | OPENSSL_CONF=$tmp openssl dgst -sha256 -provider fips >/dev/null 2>&1 || rc=1
    rm -f "$tmp"
    return "$rc"
}

# Ubuntu Pro FIPS ("pro enable fips" / "fips-updates") installs Canonical's
# own certified OpenSSL provider and kernel. Never stack a second provider
# on top of it.
UBUNTU_PRO_FIPS=""
ubuntu_pro_fips_active() {
    if [[ -z $UBUNTU_PRO_FIPS ]]; then
        UBUNTU_PRO_FIPS=0
        if is_ubuntu && command -v pro >/dev/null 2>&1; then
            if pro status --format json 2>/dev/null | python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
ok = any(s.get("name") in ("fips", "fips-updates", "fips-preview") and s.get("status") == "enabled"
         for s in d.get("services", []))
sys.exit(0 if ok else 1)'; then
                UBUNTU_PRO_FIPS=1
            fi
        fi
    fi
    [[ $UBUNTU_PRO_FIPS == 1 ]]
}

install_fips_provider() {
    step "4.2 FIPS 140 cryptographic module"
    if is_rhel; then
        enable_fips_rhel
        return 0
    fi
    log "building the validated OpenSSL ${FIPS_OPENSSL_VERSION} FIPS provider (FIPS 140-3 cert #4985)"
    if ubuntu_pro_fips_active; then
        log "Ubuntu Pro FIPS is enabled: Canonical's certified OpenSSL FIPS provider is kept; the ${FIPS_OPENSSL_VERSION} build is skipped"
        return 0
    fi
    local prefix=/opt/openssl-fips-${FIPS_OPENSSL_VERSION}
    local module=${prefix}/lib64/ossl-modules/fips.so
    local fipscnf=${prefix}/ssl/fipsmodule.cnf
    if fips_selftest "$module" "$fipscnf"; then
        log "validated FIPS provider already installed; self-test on load passed (${module})"
        return 0
    fi
    apt_install build-essential perl make gcc curl ca-certificates
    local target
    case $DEB_ARCH in
        amd64) target=linux-x86_64 ;;
        arm64) target=linux-aarch64 ;;
        *) die "unsupported architecture for the FIPS provider build: ${DEB_ARCH}" ;;
    esac
    local build=${CACHE_DIR}/build
    rm -rf "$build"
    install -d -m 0700 "$build"
    local tarball=${CACHE_DIR}/openssl-${FIPS_OPENSSL_VERSION}.tar.gz
    if [[ ! -f $tarball ]] || ! echo "${FIPS_OPENSSL_SHA256}  ${tarball}" | sha256sum -c --status; then
        set_curl_retry
        curl -fsSL --proto '=https' --tlsv1.2 --retry 5 "${CURL_RETRY_ALL[@]}" -o "$tarball" "$FIPS_OPENSSL_URL"
    fi
    echo "${FIPS_OPENSSL_SHA256}  ${tarball}" | sha256sum -c --status \
        || die "SHA-256 mismatch for ${tarball}: refusing to build an unverified FIPS module"
    log "source verified (sha256 ${FIPS_OPENSSL_SHA256})"
    tar -xzf "$tarball" -C "$build"
    (
        cd "${build}/openssl-${FIPS_OPENSSL_VERSION}"
        # Build exactly as the FIPS 140-3 Security Policy (cert #4985) prescribes.
        ./Configure enable-fips "$target" --prefix="$prefix" --openssldir="${prefix}/ssl" --libdir=lib64 >/dev/null
        make -j"$(nproc)" >/dev/null
        make install_fips >/dev/null
    ) || die "FIPS provider build or installation failed"
    # 3.1.2 writes a self-test-on-load configuration (no install-status), so
    # 'fipsinstall -verify' does not apply; loading the module runs its
    # integrity check and KATs, which is the authoritative verification.
    [[ -f $module && -f $fipscnf ]] || die "FIPS provider installation did not produce ${module}"
    fips_selftest "$module" "$fipscnf" || die "installed FIPS module failed its load-time self-test"
    rm -rf "$build"
    log "FIPS provider installed: ${module}"
}

# RHEL family: the distribution's own FIPS module (its OpenSSL is built to
# load it when the kernel runs in FIPS mode). A second, self-built provider
# is never stacked on it.
# Crypto policy for the host: FIPS, except Fedora desktops (Fedora has no
# FIPS validation; DEFAULT:NO-SHA1 is the CIS policy and keeps browsing/Wi-Fi).
crypto_policy_for_host() {
    if is_fedora && is_desktop; then echo "DEFAULT:NO-SHA1"; else echo FIPS; fi
}

enable_fips_rhel() {
    if [[ $(cat /proc/sys/crypto/fips_enabled 2>/dev/null) == 1 ]]; then
        log "kernel already in FIPS mode"
    fi
    if is_fedora; then
        # No fips-mode-setup, no kernel FIPS mode on Fedora: the policy only.
        update-crypto-policies --set "$(crypto_policy_for_host)" >/dev/null
        log "Fedora: system crypto policy $(crypto_policy_for_host) (Fedora does not support kernel FIPS mode)"
        return 0
    fi
    if in_container; then
        update-crypto-policies --set FIPS >/dev/null
        warn "container: kernel FIPS mode is host-global; crypto policy FIPS set, fips=1 applies on a real host"
        return 0
    fi
    if command -v fips-mode-setup >/dev/null 2>&1; then
        # EL8/9: crypto policy FIPS, dracut-fips (EL8), fips=1 (+ boot=) on every kernel.
        fips-mode-setup --enable >/dev/null || die "fips-mode-setup --enable failed"
    else
        # EL10 removed fips-mode-setup: policy here, fips=1 by configure_grub.
        update-crypto-policies --set FIPS >/dev/null
    fi
    log "FIPS mode configured (distribution module); active after reboot"
}

# tls_loopback_test CONF - full TLS handshake through 127.0.0.1 with CONF as
# the system OpenSSL configuration (catches provider/algorithm mismatches
# that would otherwise break curl, git and every other TLS client).
tls_loopback_test() {
    local conf=$1 dir port rc=1 pid
    dir=$(mktemp -d)
    port=$(( 20000 + RANDOM % 20000 ))
    OPENSSL_CONF=$conf openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "${dir}/k.pem" -out "${dir}/c.pem" -subj '/CN=localhost' -days 1 >/dev/null 2>&1 || { rm -rf "$dir"; return 1; }
    OPENSSL_CONF=$conf openssl s_server -accept "127.0.0.1:${port}" -cert "${dir}/c.pem" -key "${dir}/k.pem" \
        -www -naccept 1 >/dev/null 2>&1 &
    pid=$!
    sleep 1
    if echo | OPENSSL_CONF=$conf timeout 10 openssl s_client -connect "127.0.0.1:${port}" -CAfile "${dir}/c.pem" \
        -verify_return_error -brief 2>&1 | qgrep -E 'CONNECTION ESTABLISHED|Verification: OK'; then
        rc=0
    fi
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
    rm -rf "$dir"
    return "$rc"
}

configure_openssl_fips() {
    step "4.3 system cryptography: FIPS provider / crypto policy"
    if is_rhel; then
        local pol
        pol=$(update-crypto-policies --show 2>/dev/null || true)
        [[ $pol == "$(crypto_policy_for_host)"* ]] || die "system crypto policy is '${pol}', expected $(crypto_policy_for_host)"
        if command -v sshd >/dev/null 2>&1; then
            sshd_test >/dev/null 2>&1 || die "sshd rejects its configuration under the FIPS crypto policy"
        fi
        log "system crypto policy: ${pol} (OpenSSL, GnuTLS, NSS, OpenSSH, Kerberos, libssh follow it)"
        return 0
    fi
    if ubuntu_pro_fips_active; then
        log "Ubuntu Pro FIPS is enabled: /etc/ssl/openssl.cnf is managed by the Pro FIPS packages and left unchanged"
        return 0
    fi
    local prefix=/opt/openssl-fips-${FIPS_OPENSSL_VERSION}
    local module=${prefix}/lib64/ossl-modules/fips.so
    local cnf=/etc/ssl/openssl.cnf
    [[ -f $cnf ]] || die "${cnf} missing"
    backup_file "$cnf"

    # FIPS module configuration with an absolute module path.
    {
        echo "# Managed by ${SCRIPT_NAME}: OpenSSL ${FIPS_OPENSSL_VERSION} FIPS provider (FIPS 140-3 cert #4985)"
        sed -e "/^\[ *fips_sect *\]/a module = ${module}" "${prefix}/ssl/fipsmodule.cnf"
    } >/etc/ssl/fipsmodule.cnf.new
    chmod 0644 /etc/ssl/fipsmodule.cnf.new
    mv -f /etc/ssl/fipsmodule.cnf.new /etc/ssl/fipsmodule.cnf

    local props="# default_properties = fips=yes   (enable with FIPS_STRICT=1)"
    [[ $FIPS_STRICT == 1 ]] && props="default_properties = fips=yes"
    local block
    block=$(cat <<EOF
# BEGIN ${MARK} FIPS provider configuration
[openssl_init]
providers = provider_sect
alg_section = algorithm_sect
ssl_conf = ssl_sect

[provider_sect]
# default is listed first: unqualified fetches resolve there (OpenSSL 3.5's
# ML-KEM needs SHAKE squeeze, which the 3.1.2 FIPS module predates); FIPS
# implementations are selected with the "fips=yes" property.
default = default_sect
fips = fips_sect

[default_sect]
activate = 1

[algorithm_sect]
${props}

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=2
# FIPS-approved key exchange groups only (NIST curves, RFC 7919 FFDHE).
Groups = P-256:P-384:P-521:ffdhe2048:ffdhe3072:ffdhe4096

.include /etc/ssl/fipsmodule.cnf
# END ${MARK} FIPS provider configuration
EOF
)
    local tmp
    tmp=$(mktemp /etc/ssl/openssl.cnf.XXXXXX)
    # Rewrite the provider-related sections, keep everything else verbatim.
    local pve=0
    is_pve && pve=1
    awk -v block="$block" -v mark="$MARK" -v pve="$pve" '
        BEGIN { managed["openssl_init"]=1; managed["provider_sect"]=1; managed["default_sect"]=1;
                managed["fips_sect"]=1; managed["base_sect"]=1; managed["algorithm_sect"]=1;
                managed["ssl_sect"]=1; managed["system_default_sect"]=1; skip=0; done=0; has_conf=0 }
        $0 ~ "^# (BEGIN|END) " mark { next }
        /^[[:space:]]*\.include[[:space:]].*fipsmodule\.cnf/ { next }
        /^[[:space:]]*openssl_conf[[:space:]]*=/ { has_conf=1 }
        /^[[:space:]]*\[[[:space:]]*[^]]+[[:space:]]*\]/ {
            name=$0; sub(/^[[:space:]]*\[[[:space:]]*/, "", name); sub(/[[:space:]]*\].*$/, "", name)
            if (name in managed) { skip=1; if (!done) { print block; print ""; done=1 }; next }
            skip=0
        }
        skip { next }
        # Proxmox VE: the managed [openssl_init] loads the providers, so
        # openssl_conf must point at it even when the node used another name
        # (default_conf): otherwise the FIPS provider is never loaded. The old
        # section stays in the file, unreferenced. Lines inside replaced
        # sections were dropped above (a stray one after the .include would
        # land in [fips_sect]).
        /^[[:space:]]*openssl_conf[[:space:]]*=/ && pve { print "openssl_conf = openssl_init"; next }
        { print }
        END { if (!done) { print ""; print block } }
    ' "$cnf" >"$tmp"
    if ! grep -Eq '^[[:space:]]*openssl_conf[[:space:]]*=' "$tmp"; then
        sed -i '1i openssl_conf = openssl_init' "$tmp"
    fi
    chmod 0644 "$tmp"

    # Validate BEFORE activation: a broken config would break sshd/curl/apt.
    local ok=1
    OPENSSL_CONF=$tmp openssl list -providers 2>/dev/null | grep -A3 -E '^[[:space:]]*fips' | qgrep 'status: active' || ok=0
    OPENSSL_CONF=$tmp openssl list -providers 2>/dev/null | grep -A3 -E '^[[:space:]]*default' | qgrep 'status: active' || ok=0
    echo test | OPENSSL_CONF=$tmp openssl dgst -sha256 -propquery fips=yes >/dev/null 2>&1 || ok=0
    if command -v sshd >/dev/null 2>&1; then
        OPENSSL_CONF=$tmp sshd_test >/dev/null 2>&1 || ok=0
    fi
    tls_loopback_test "$tmp" || ok=0
    if [[ $ok -ne 1 ]]; then
        rm -f "$tmp"
        die "new openssl.cnf failed validation (providers, sshd -t or TLS loopback handshake); original left untouched"
    fi
    mv -f "$tmp" "$cnf"
    log "openssl.cnf active providers: $(openssl list -providers 2>/dev/null | awk '/^ *[a-z]+$/{printf "%s ", $1}')"
}

# ============================================================================
# 5. CIS Level 2 / STIG controls
# ============================================================================
harden_file_permissions() {
    step "5.1 critical file ownership and permissions"
    chown root:root /etc/passwd /etc/group
    chmod 0644 /etc/passwd /etc/group
    local f
    if is_rhel; then
        # EL: no shadow group; the shadow files are root-only (CIS: 0000).
        for f in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-; do
            [[ -f $f ]] && { chown root:root "$f"; chmod 0000 "$f"; }
        done
    else
        chown root:shadow /etc/shadow /etc/gshadow
        chmod 0640 /etc/shadow /etc/gshadow
        # Backup copies of the password databases: nobody needs to read them.
        [[ -f /etc/shadow- ]] && { chown root:shadow /etc/shadow-; chmod 0000 /etc/shadow-; }
        # CIS Debian 12 and Ubuntu expect group shadow here, CIS Debian 13 root.
        if [[ -f /etc/gshadow- ]]; then
            if is_debian && (( OS_MAJOR >= 13 )); then chown root:root /etc/gshadow-; else chown root:shadow /etc/gshadow-; fi
            chmod 0000 /etc/gshadow-
        fi
    fi
    for f in /etc/passwd- /etc/group-; do
        [[ -f $f ]] && { chown root:root "$f"; chmod 0644 "$f"; }
    done
    [[ -f /etc/shells ]] && { chown root:root /etc/shells; chmod 0644 /etc/shells; }
    if [[ -f /etc/security/opasswd ]]; then chown root:root /etc/security/opasswd; chmod 0600 /etc/security/opasswd; fi
    if [[ -f /etc/security/opasswd.old ]]; then chown root:root /etc/security/opasswd.old; chmod 0600 /etc/security/opasswd.old; fi
    [[ -f /etc/crypttab ]] && { chown root:root /etc/crypttab; chmod 0600 /etc/crypttab; }
    for f in /boot/System.map-*; do chown root:root "$f"; chmod 0600 "$f"; done

    # cron / at
    [[ -f /etc/crontab ]] && { chown root:root /etc/crontab; chmod 0600 /etc/crontab; }
    local d
    for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly; do
        [[ -d $d ]] && { chown root:root "$d"; chmod 0700 "$d"; }
    done
    rm -f /etc/cron.deny /etc/at.deny
    printf 'root\n' | write_file 0640 /etc/cron.allow
    # Ubuntu CIS: /etc/cron.allow group crontab (cron runs setgid crontab).
    if is_ubuntu && getent group crontab >/dev/null; then chgrp crontab /etc/cron.allow; fi
    printf 'root\n' | write_file 0640 /etc/at.allow

    # sudo / sysctl / firewall directories (ANSSI)
    for d in /etc/sudoers.d /etc/iptables /etc/nftables; do
        [[ -d $d ]] && { chown root:root "$d"; chmod 0750 "$d"; }
    done
    [[ -d /etc/sysctl.d ]] && { chown root:root /etc/sysctl.d; chmod 0755 /etc/sysctl.d; }
    [[ -f /etc/sudoers ]] && { chown root:root /etc/sudoers; chmod 0440 /etc/sudoers; }

    # Audit tools
    for f in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules; do
        [[ -e $f ]] && { chown root:root "$f"; chmod 0755 "$f"; }
    done
    find /etc/audit -type f -exec chown root:root {} + -exec chmod 0640 {} +
    find /etc/audit/rules.d -type f -name '*.rules' -exec chmod 0600 {} +

    # Log files: no group write, no world access (rsyslog will keep 0640).
    find /var/log -type f -perm /u+xs,g+xws,o+xwrt -exec chmod u-xs,g-xws,o-xwrt {} + 2>/dev/null || true
    find /var/log -type d -perm /o+w -exec chmod o-w {} + 2>/dev/null || true
    if is_deb; then
        for f in /var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/messages /var/log/user.log /var/log/cron.log; do
            [[ -f $f ]] && chgrp adm "$f"
        done
    fi
    for f in /var/log/wtmp /var/log/btmp /var/log/lastlog; do
        [[ -f $f ]] && chgrp utmp "$f"
    done

    # World-writable regular files on local filesystems lose o+w.
    local m
    while read -r m; do
        find "$m" -xdev \( -regextype posix-extended -regex "$CONTAINER_PATH_RE" -o -regex "$(is_pve && echo "$PVE_GUEST_PATH_RE" || echo '^$')" \) -prune \
            -o -type f -perm -0002 -exec chmod o-w {} + 2>/dev/null || true
        find "$m" -xdev \( -regextype posix-extended -regex "$CONTAINER_PATH_RE" -o -regex "$(is_pve && echo "$PVE_GUEST_PATH_RE" || echo '^$')" \) -prune \
            -o -type d -perm -0002 ! -perm -1000 -exec chmod +t {} + 2>/dev/null || true
    done < <(host_fs_mounts '^(ext[234]|xfs|btrfs|overlay|zfs|f2fs)$')

    # Home directories and dot files.
    local u home
    while read -r u; do
        home=$(getent passwd "$u" | cut -d: -f6)
        [[ -d $home && $home != / ]] || continue
        chmod 0750 "$home"
        chown "$u":"$(id -gn "$u")" "$home"
        find "$home" -mindepth 1 -maxdepth 1 -name '.*' ! -type l -exec chmod g-wx,o-rwx {} + -exec chown "$u":"$(id -gn "$u")" {} + 2>/dev/null || true
        [[ -f ${home}/.bash_history ]] && chmod 0600 "${home}/.bash_history"
        rm -f "${home}/.rhosts" "${home}/.shosts"
        [[ -e ${home}/.netrc ]] && warn "${home}/.netrc exists (stored credentials) - review and remove"
        [[ -e ${home}/.forward ]] && warn "${home}/.forward exists - review and remove"
    done < <(interactive_users)
    chmod 0700 /root
    find /root -mindepth 1 -maxdepth 1 -name '.*' ! -type l -exec chmod g-wx,o-rwx {} + 2>/dev/null || true
    rm -f /etc/hosts.equiv /etc/shosts.equiv
}

# neutralize_sysctl_conflicts MANAGED_FILE - every other sysctl source that
# sets a key from MANAGED_FILE to a different value is neutralised:
#   * /etc/sysctl.conf and /etc/sysctl.d/*.conf: the line is commented out;
#   * /usr/lib|/lib/sysctl.d/*.conf (vendor): masked by an /etc/sysctl.d file
#     of the same name with the conflicting line commented out.
# Vendor files such as Ubuntu's 10-network-security.conf (rp_filter=2),
# 10-magic-sysrq.conf (sysrq=176) and 99-protect-links.conf (which sorts
# AFTER 60-harden.conf and silently wins at boot) would otherwise override
# the hardening or make the SCAP sysctl checks fail.
neutralize_sysctl_conflicts() {
    local managed=$1 f base dest
    local -A want=()
    local k v
    while IFS='=' read -r k v; do
        k=${k//[[:space:]]/}; v=$(xargs <<<"$v")
        [[ -n $k && $k != \#* ]] && want[$k]=$v
    done < <(grep -E '^[[:space:]]*[a-z]' "$managed")
    # conflict_filter FILE - print FILE with conflicting assignments commented
    conflict_filter() {
        local line key val
        while IFS= read -r line || [[ -n $line ]]; do
            if [[ $line =~ ^[[:space:]]*-?([a-z0-9_.*/-]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
                key=${BASH_REMATCH[1]//\//.}
                val=$(xargs <<<"${BASH_REMATCH[2]}")
                if [[ -n ${want[$key]+x} && $val != "${want[$key]}" ]]; then
                    printf '# overridden by %s (%s = %s): %s\n' "$MARK" "$key" "${want[$key]}" "$line"
                    continue
                fi
            fi
            printf '%s\n' "$line"
        done <"$1"
    }
    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
        [[ -f $f && ! -L $f && $f != "$managed" ]] || continue
        if ! cmp -s <(conflict_filter "$f") "$f"; then
            backup_file "$f"
            conflict_filter "$f" >"${f}.harden.tmp"
            cat "${f}.harden.tmp" >"$f"
            rm -f "${f}.harden.tmp"
            log "sysctl: neutralised conflicting values in ${f}"
        fi
    done
    for f in /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf; do
        [[ -f $f ]] || continue
        base=${f##*/}
        dest=/etc/sysctl.d/${base}
        # An /etc file of the same name already masks it (handled above).
        [[ -e $dest ]] && continue
        if ! cmp -s <(conflict_filter "$f") "$f"; then
            { printf '# Managed by %s: masks %s (conflicting values commented out)\n' "$SCRIPT_NAME" "$f"; conflict_filter "$f"; } \
                | write_file 0644 "$dest"
            log "sysctl: ${f} masked by ${dest}"
        fi
    done
    unset -f conflict_filter
}

configure_sysctl() {
    step "5.2 kernel & network stack hardening (sysctl)"
    local fwd=0
    [[ $ALLOW_CONTAINERS == 1 ]] && fwd=1
    local ra=0
    [[ $KEEP_RA == 1 ]] && ra=1
    # Forwarding: off on plain servers, on for container/Kubernetes hosts, and
    # left to the node's own network configuration on Proxmox VE (NAT, routed
    # and SDN guests need it; bridged guests do not care).
    local fwd4 fwd6
    if is_pve && ! containers_on; then
        fwd4="# IPv4 forwarding: managed by the Proxmox VE network configuration (not set here)"
        fwd6="# IPv6 forwarding: managed by the Proxmox VE network configuration (not set here)"
    else
        fwd4=$(printf 'net.ipv4.ip_forward = %s\nnet.ipv4.conf.all.forwarding = %s\nnet.ipv4.conf.default.forwarding = %s' "$fwd" "$fwd" "$fwd")
        # IPv6: only dual-stack Kubernetes nodes (an IPv6 default route) route
        # IPv6 permanently; Docker turns it on itself for IPv6 networks.
        local f6=0
        is_k8s && [[ -n $(ip -6 route show default 2>/dev/null) ]] && f6=1
        fwd6=$(printf 'net.ipv6.conf.all.forwarding = %s\nnet.ipv6.conf.default.forwarding = %s' "$f6" "$f6")
    fi
    # rp_filter: strict (CIS) except where traffic is legitimately asymmetric:
    # Kubernetes CNIs (Cilium/Calico eBPF, multi-NIC) and Proxmox SDN EVPN.
    local rpf=1
    if is_k8s || { is_pve && grep -Eqs '^evpn:' /etc/pve/sdn/zones.cfg; }; then rpf=2; fi
    # Gratuitous ARP announces moved IPs: VM live migration, HA/keepalived,
    # kube-vip and MetalLB L2 virtual IPs. Dropping it leaves stale ARP entries.
    local garp="net.ipv4.conf.all.drop_gratuitous_arp = 1"
    if is_pve || is_k8s; then garp="# drop_gratuitous_arp not set: migrating VMs / floating virtual IPs announce themselves by gratuitous ARP"; fi
    write_file 0644 /etc/sysctl.d/60-harden.conf <<EOF
# Managed by ${SCRIPT_NAME} - CIS Debian L2 / ANSSI BP-028 / DISA STIG aligned.

# --- IPv4: no routing, no redirects, no source routing, spoofing protection
${fwd4}
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = ${rpf}
net.ipv4.conf.default.rp_filter = ${rpf}
net.ipv4.conf.all.accept_local = 0
net.ipv4.conf.all.route_localnet = 0
net.ipv4.conf.all.shared_media = 0
net.ipv4.conf.default.shared_media = 0
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.all.arp_ignore = 2
${garp}
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ip_local_port_range = 32768 65535

# --- IPv6: no routing, no redirects, no source routing, no router advertisements
${fwd6}
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = ${ra}
net.ipv6.conf.default.accept_ra = ${ra}
net.ipv6.conf.all.accept_ra_defrtr = ${ra}
net.ipv6.conf.default.accept_ra_defrtr = ${ra}
net.ipv6.conf.all.accept_ra_pinfo = ${ra}
net.ipv6.conf.default.accept_ra_pinfo = ${ra}
net.ipv6.conf.all.accept_ra_rtr_pref = ${ra}
net.ipv6.conf.default.accept_ra_rtr_pref = ${ra}
net.ipv6.conf.all.autoconf = ${ra}
net.ipv6.conf.default.autoconf = ${ra}
net.ipv6.conf.all.router_solicitations = 0
net.ipv6.conf.default.router_solicitations = 0
$(is_desktop || printf 'net.ipv6.conf.all.max_addresses = 1\nnet.ipv6.conf.default.max_addresses = 1\n')

# --- Kernel self-protection
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.perf_event_paranoid = 3
kernel.perf_cpu_time_max_percent = 1
kernel.perf_event_max_sample_rate = 1
vm.mmap_min_addr = 65536
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
    # Systemd ships rp_filter=2 (loose) in /usr/lib/sysctl.d/50-default.conf;
    # an /etc file of the same name masks it so only one value exists.
    if [[ -f /usr/lib/sysctl.d/50-default.conf ]] && grep -q 'rp_filter' /usr/lib/sysctl.d/50-default.conf; then
        sed -E "s/^(-?net\\.ipv4\\.conf\\.[a-z*]+\\.rp_filter[[:space:]]*=[[:space:]]*).*/\\1${rpf}/" /usr/lib/sysctl.d/50-default.conf \
            | write_file 0644 /etc/sysctl.d/50-default.conf
    fi
    neutralize_sysctl_conflicts /etc/sysctl.d/60-harden.conf
    # Media / TURN relay throughput (large UDP socket buffers).
    write_file 0644 /etc/sysctl.d/70-media-coturn.conf <<'EOF'
# Managed by harden-and-audit.sh - socket buffers for real-time media / TURN relays.
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 5000
EOF
    # Interfaces created after early boot get per-interface defaults; re-apply.
    write_file 0644 /etc/systemd/system/sysctl-reapply-network.service <<'EOF'
# Managed by harden-and-audit.sh
[Unit]
Description=Re-apply sysctl hardening after network interfaces come up
After=networking.service systemd-networkd.service NetworkManager.service network-online.target
Wants=network-online.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/sysctl --system
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sysctl-reapply-network.service >/dev/null 2>&1 || true
    host_only "apply sysctl settings" sysctl -q -e --system
}

configure_sshd() {
    step "5.3 OpenSSH server lockdown (FIPS algorithms)"
    local cfg=/etc/ssh/sshd_config
    [[ -f $cfg ]] || die "${cfg} missing"
    backup_file "$cfg"
    # Every existing interactive user keeps SSH access through ssh-users.
    getent group ssh-users >/dev/null || groupadd -r ssh-users
    local u
    while read -r u; do
        usermod -aG ssh-users "$u"
    done < <(interactive_users)
    # Proxmox VE: root logs in between cluster nodes (AllowGroups applies to root too).
    is_pve && usermod -aG ssh-users root
    local pwauth="# PasswordAuthentication: unchanged (set SSH_DISABLE_PASSWORD=1 for key-only)"
    [[ $SSH_DISABLE_PASSWORD == 1 ]] && pwauth="PasswordAuthentication no"
    # Debian family: explicit FIPS algorithms. RHEL family: the system crypto
    # policy (FIPS) governs sshd; CIS fails sshd_config overrides of it.
    # EL CIS: one unanswered keepalive (300 s) ends the session; Debian/Ubuntu CIS: 3.
    local alive_max=3
    is_rhel && alive_max=1
    local crypto=""
    if is_deb; then
        crypto='Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
'
    fi
    local block
    block=$(cat <<EOF
# BEGIN ${MARK} managed block - first match wins in sshd, keep this at the top
LogLevel ${SSH_LOGLEVEL}
PermitRootLogin ${ROOT_SSH}
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
DisableForwarding yes
MaxAuthTries 4
MaxSessions 10
MaxStartups 10:30:60
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax ${alive_max}
HostbasedAuthentication no
IgnoreRhosts yes
PermitEmptyPasswords no
PermitUserEnvironment no
GSSAPIAuthentication no
KerberosAuthentication no
UsePAM yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
${pwauth}
StrictModes yes
Compression no
PrintLastLog yes
Banner /etc/issue.net
AllowGroups ssh-users
${crypto}RekeyLimit 1G 1h
# END ${MARK} managed block
EOF
)
    local keys
    keys=$(sed -n '/^# BEGIN/,/^# END/p' <<<"$block" | awk '!/^#/ && NF {print $1}' | sort -u | paste -sd'|')
    is_rhel && keys+="|Ciphers|MACs|KexAlgorithms"
    local tmp
    tmp=$(mktemp "${cfg}.XXXXXX")
    # Proxmox VE: secure live migration and storage migration tunnel the
    # QEMU/NBD streams through root SSH port and unix-socket forwarding
    # (ssh -L), so root - and only root - keeps those two forwarding types.
    # A Match block must be last in the file; it is appended after the rest.
    local pve_match="" pve_pw_match=""
    if is_pve; then
        # PVE_ROOT_PASSWORD_FROM: root keeps password login from these
        # networks only; everywhere else root stays key-only.
        if [[ -n $PVE_ROOT_PASSWORD_FROM ]]; then
            local pw_from
            pw_from=$(tr -s ' ,' ',' <<<"$PVE_ROOT_PASSWORD_FROM" | sed 's/^,//; s/,$//')
            [[ $pw_from =~ ^[0-9A-Fa-f:.,/]+$ ]] || die "PVE_ROOT_PASSWORD_FROM must be a list of CIDRs (got '${PVE_ROOT_PASSWORD_FROM}')"
            pve_pw_match="Match User root Address ${pw_from}
    PermitRootLogin yes
"
        fi
        pve_match=$(cat <<EOF
# BEGIN ${MARK} proxmox root match - must stay at the end of the file
${pve_pw_match}Match User root
    DisableForwarding no
    AllowTcpForwarding yes
    AllowStreamLocalForwarding yes
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
# END ${MARK} proxmox root match
EOF
)
    fi
    {
        printf '%s\n\n' "$block"
        # Drop the previous managed blocks; comment out managed keys elsewhere.
        sed "/^# BEGIN ${MARK} managed block/,/^# END ${MARK} managed block/d; /^# BEGIN ${MARK} proxmox root match/,/^# END ${MARK} proxmox root match/d" "$cfg" \
            | sed -E "s/^([[:space:]]*(${keys})[[:space:]].*)/# overridden by ${MARK}: \1/I"
        if [[ -n $pve_match ]]; then printf '\n%s\n' "$pve_match"; fi
    } >"$tmp"
    chown root:root "$tmp"
    chmod 0600 "$tmp"
    local f
    for f in /etc/ssh/sshd_config.d/*.conf; do
        backup_file "$f"
        sed -i -E "s/^([[:space:]]*(${keys})[[:space:]].*)/# overridden by ${MARK}: \1/I" "$f"
        chmod 0600 "$f"
    done
    # Strong DH group-exchange moduli only (>= 3071 bits).
    if [[ -f /etc/ssh/moduli ]]; then
        backup_file /etc/ssh/moduli
        awk '$5 >= 3071' /etc/ssh/moduli >/etc/ssh/moduli.tmp
        if [[ -s /etc/ssh/moduli.tmp ]]; then mv -f /etc/ssh/moduli.tmp /etc/ssh/moduli; else rm -f /etc/ssh/moduli.tmp; fi
    fi
    if ! sshd_test -f "$tmp"; then
        rm -f "$tmp"
        die "hardened sshd_config failed 'sshd -t'; original configuration left in place"
    fi
    mv -f "$tmp" "$cfg"
    # Host keys
    if is_rhel; then
        getent group ssh_keys >/dev/null || groupadd -r ssh_keys
    fi
    if is_rhel && getent group ssh_keys >/dev/null; then
        for f in /etc/ssh/ssh_host_*_key; do chown root:ssh_keys "$f"; chmod 0600 "$f"; done
    else
        for f in /etc/ssh/ssh_host_*_key; do chown root:root "$f"; chmod 0600 "$f"; done
    fi
    for f in /etc/ssh/ssh_host_*_key.pub; do chown root:root "$f"; chmod 0644 "$f"; done
    if is_rhel; then
        # Keys cleared by the crypto policy above stay out of sshd_config.d too.
        for f in /etc/ssh/sshd_config.d/*.conf; do
            sed -i -E 's/^([[:space:]]*(Ciphers|MACs|KexAlgorithms)[[:space:]].*)/# overridden by '"${MARK}"' (system crypto policy): \1/I' "$f"
        done
    fi
    if is_desktop && ! systemctl is-enabled --quiet "${SSH_UNIT}.service" 2>/dev/null \
        && ! systemctl is-active --quiet "${SSH_UNIT}.service" 2>/dev/null && ! systemctl is-active --quiet ssh.socket 2>/dev/null; then
        log "desktop mode: sshd was not enabled - configuration hardened, service left off"
        return 0
    fi
    systemctl enable "${SSH_UNIT}.service" >/dev/null 2>&1 || true
    if systemctl is-active --quiet "${SSH_UNIT}.service"; then
        systemctl reload "${SSH_UNIT}.service"
    else
        # Socket activation (Ubuntu 22.10+): ssh.socket holds the listener and
        # hands it to ssh.service, which then reads the new configuration.
        systemctl start "${SSH_UNIT}.service"
    fi
    log "sshd reloaded (existing sessions are not interrupted)"
}

configure_ufw() {
    step "5.4 host firewall: default deny inbound (UFW / firewalld / pve-firewall)"
    if is_pve && ! pbs_uses_ufw; then
        configure_pve_firewall
        return 0
    fi
    if pbs_uses_ufw; then
        log "Proxmox Backup Server: no pve-firewall - UFW is the host firewall"
        pkg_installed ufw || apt_install ufw
    fi
    if is_rhel; then
        configure_firewalld
        return 0
    fi
    sed -i -E 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
    if [[ $ALLOW_CONTAINERS != 1 ]]; then
        sed -i -E 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="DROP"/' /etc/default/ufw
    fi
    ufw default deny incoming >/dev/null
    if [[ $ALLOW_CONTAINERS == 1 ]]; then
        ufw default allow routed >/dev/null
    else
        ufw default deny routed >/dev/null
    fi
    local p
    # SSH is allowed BEFORE the firewall is enabled - never cut the session.
    for p in "${SSH_PORTS[@]}"; do
        ufw allow in "${p}/tcp" comment 'SSH (harden-and-audit)' >/dev/null
    done
    # Desktops discover printers and shares over mDNS.
    is_desktop && ufw allow in 5353/udp comment 'mDNS (desktop, harden-and-audit)' >/dev/null
    # Proxmox Backup Server: its own services are allowed before UFW is enabled too.
    pbs_uses_ufw && ufw_pbs_rules
    ufw allow in on lo >/dev/null
    ufw allow out on lo >/dev/null
    ufw deny in from 127.0.0.0/8 >/dev/null
    ufw deny in from ::1 >/dev/null
    if [[ $FIREWALL_OUTBOUND_POLICY == deny ]]; then
        local r
        for r in 53/udp 53/tcp 67/udp 547/udp 123/udp 80/tcp 443/tcp $FIREWALL_EXTRA_OUT; do
            ufw allow out "$r" comment 'egress allow-list (harden-and-audit)' >/dev/null
        done
        ufw default deny outgoing >/dev/null
    else
        ufw default allow outgoing >/dev/null
    fi
    if is_k8s; then ufw_kubernetes_rules; fi
    if containers_on; then ufw_container_ifaces; else ufw_container_ifaces_remove; fi
    ufw logging low >/dev/null
    # UFW re-applies /etc/ufw/sysctl.conf whenever it starts; its stock file
    # turns martian logging OFF, silently undoing the CIS setting each boot.
    backup_file /etc/ufw/sysctl.conf
    sed -i -E 's|^(net/ipv4/conf/(all\|default)/log_martians)=.*|\1=1|' /etc/ufw/sysctl.conf
    systemctl enable ufw.service >/dev/null 2>&1 || true
    host_only "enable UFW" ufw --force enable
    # 'ufw enable' loads the rules but leaves the oneshot unit inactive.
    host_only "start ufw.service" systemctl start ufw.service
    ufw status verbose || true
}

# Inbound ports a Kubernetes node needs (control plane: API server, etcd,
# controller-manager, scheduler, k3s/rke2 supervisor; every node: kubelet,
# NodePorts; CNI overlays: VXLAN (flannel/Cilium/Calico), Geneve, WireGuard,
# Calico BGP/Typha, Cilium health/Hubble).
# Proxmox Backup Server (UFW): allow what PBS serves before UFW is enabled.
# Web UI/API 8007 from anywhere (like a PVE node's 8006); NFS only from the
# export clients, with mountd/statd/lockd pinned to fixed ports first (they are
# random by default and UFW cannot follow them); Samba and a local web server
# when installed; the Tueri Core agent; PBS_FIREWALL_EXTRA_IN.
PBS_NFS_PORTS=(111 2049 20048 32765 32768)
ufw_pbs_rules() {
    local c='Proxmox Backup Server, harden-and-audit' r p src
    ufw allow in 8007/tcp comment 'PBS web UI / API (harden-and-audit)' >/dev/null
    if pbs_nfs_exports; then
        pbs_pin_nfs_ports
        local -a clients=()
        while read -r src; do [[ -n $src ]] && clients+=("$src"); done < <(exportfs -s 2>/dev/null |
            awk '{print $2}' | sed -E 's/\(.*//' | sort -u)
        [[ ${#clients[@]} -eq 0 ]] && warn "Proxmox Backup Server: NFS exports found but exportfs lists no clients - NFS not opened"
        for src in "${clients[@]}"; do
            [[ $src == '*' ]] && src=any
            for p in "${PBS_NFS_PORTS[@]}"; do
                ufw allow in from "$src" to any port "$p" comment 'NFS export client (harden-and-audit)' >/dev/null
            done
        done
        log "Proxmox Backup Server: NFS (${PBS_NFS_PORTS[*]}) open to ${#clients[@]} export client(s)"
    fi
    if pkg_installed samba; then
        for r in 139/tcp 445/tcp 137/udp 138/udp; do ufw allow in "$r" comment "Samba ($c)" >/dev/null; done
    fi
    if pkg_installed nginx || pkg_installed apache2; then
        for r in 80/tcp 443/tcp; do ufw allow in "$r" comment "web server ($c)" >/dev/null; done
    fi
    if pkg_installed tuericore-agent || command -v tuericore-agent >/dev/null 2>&1; then
        ufw allow in 4422/tcp comment 'tuericore-access gateway' >/dev/null
    fi
    for r in $PBS_FIREWALL_EXTRA_IN; do ufw allow in "$r" comment "extra ($c)" >/dev/null; done
    return 0
}

# NFSv3 helpers on fixed ports (mountd 20048, statd 32765/32766, lockd 32768)
# so the firewall can allow them. Restarts the NFS services only when changed;
# clients see a pause of a few seconds and carry on.
pbs_pin_nfs_ports() {
    local f=/etc/nfs.conf.d/60-harden-nfs-ports.conf
    local want
    want=$(printf '%s\n' '# Managed by harden-and-audit.sh - fixed NFSv3 helper ports for the host firewall' \
        '[mountd]' 'port=20048' '[statd]' 'port=32765' 'outgoing-port=32766' '[lockd]' 'port=32768' 'udp-port=32768')
    if [[ -f $f && "$(cat "$f")" == "$want" ]]; then
        log "NFS helper ports already fixed (${f})"
        return 0
    fi
    mkdir -p /etc/nfs.conf.d
    printf '%s\n' "$want" | write_file 0644 "$f"
    echo 'options lockd nlm_tcpport=32768 nlm_udpport=32768' | write_file 0644 /etc/modprobe.d/60-harden-lockd.conf
    sysctl -q -w fs.nfs.nlm_tcpport=32768 fs.nfs.nlm_udpport=32768 2>/dev/null || true
    host_only "restart NFS services" systemctl restart rpc-statd.service nfs-server.service
    log "NFS helper ports fixed: mountd 20048, statd 32765, lockd 32768 (NFS services restarted)"
}

k8s_ports() {
    local -a p=(10250/tcp 30000:32767/tcp 30000:32767/udp 8472/udp 4789/udp 6081/udp 51820:51821/udp
        179/tcp 5473/tcp 4240/tcp 4244/tcp)
    if [[ $K8S_CONTROL == 1 ]]; then
        p+=(6443/tcp 2379:2380/tcp 10257/tcp 10259/tcp)
        [[ $K8S_DISTRO == rke2 ]] && p+=(9345/tcp)
        [[ $K8S_DISTRO == k0s ]] && p+=(9443/tcp 8132/tcp)
        [[ $K8S_DISTRO == microk8s ]] && p+=(16443/tcp 25000/tcp 19001/tcp)
    fi
    local x
    for x in $K8S_EXTRA_PORTS; do p+=("$x"); done
    printf '%s\n' "${p[@]}"
}

# Sources allowed to reach the cluster ports: K8S_TRUSTED_CIDRS plus the
# detected pod/service CIDRs; nothing printed means any source.
k8s_sources() {
    [[ -n $K8S_TRUSTED_CIDRS ]] || return 0
    # shellcheck disable=SC2086
    { printf '%s\n' $K8S_TRUSTED_CIDRS; k8s_cluster_cidrs; } | awk 'NF' | sort -u
}

# UFW on a Kubernetes node: cluster/CNI ports (restricted to the trusted
# sources when given) and the pod/service networks.
ufw_kubernetes_rules() {
    local port proto src n
    local -a srcs cidrs
    mapfile -t srcs < <(k8s_sources)
    mapfile -t cidrs < <(k8s_cluster_cidrs)
    # Rules from earlier runs are replaced, so a narrowed source list takes effect.
    while n=$(ufw status numbered 2>/dev/null | awk -F'[][]' '/Kubernetes.*\(harden-and-audit\)/ {gsub(/ /, "", $2); print $2; exit}') && [[ -n $n ]]; do
        ufw --force delete "$n" >/dev/null || break
    done
    while read -r port; do
        proto=${port##*/}; port=${port%/*}
        if [[ ${#srcs[@]} -eq 0 ]]; then
            ufw allow in proto "$proto" to any port "$port" comment 'Kubernetes (harden-and-audit)' >/dev/null
        else
            for src in "${srcs[@]}"; do
                ufw allow in proto "$proto" from "$src" to any port "$port" comment 'Kubernetes (harden-and-audit)' >/dev/null
            done
        fi
    done < <(k8s_ports)
    for src in "${cidrs[@]}"; do
        ufw allow in from "$src" comment 'Kubernetes pod/service network (harden-and-audit)' >/dev/null
    done
    if [[ ${#srcs[@]} -eq 0 ]]; then
        warn "Kubernetes: cluster ports (kubelet$( [[ $K8S_CONTROL == 1 ]] && echo ', API server, etcd')) accept any source; set K8S_TRUSTED_CIDRS to the node network to narrow them"
    fi
    log "Kubernetes (${K8S_DISTRO}): cluster and CNI ports allowed; pod/service networks: ${cidrs[*]:-none detected}"
}

# Container/CNI interfaces: pods and containers reach node services (DNS,
# kubelet, host-published ports) and route through them. UFW has no
# interface wildcards, so the rules go in a managed block of before.rules
# (iptables syntax, "+" = prefix match), read whenever UFW starts.
ufw_container_ifaces() {
    local f i block
    for f in /etc/ufw/before.rules /etc/ufw/before6.rules; do
        [[ -f $f ]] || continue
        block="# BEGIN ${MARK} container interfaces"$'\n'
        # before6.rules names its chains ufw6-*.
        local c=ufw
        [[ $f == */before6.rules ]] && c=ufw6
        for i in "${CNI_IFACES[@]}"; do
            block+="-A ${c}-before-input -i ${i} -j ACCEPT"$'\n'
            block+="-A ${c}-before-forward -i ${i} -j ACCEPT"$'\n'
            block+="-A ${c}-before-forward -o ${i} -j ACCEPT"$'\n'
        done
        # Calico IP-in-IP (protocol 4) between nodes, IPv4 only.
        if [[ $f == */before.rules ]] && is_k8s; then block+="-A ufw-before-input -p 4 -j ACCEPT"$'\n'; fi
        block+="# END ${MARK} container interfaces"
        backup_file "$f"
        sed -i "/^# BEGIN ${MARK} container interfaces/,/^# END ${MARK} container interfaces/d" "$f"
        # Insert before the filter table's COMMIT (the last COMMIT in the file).
        awk -v blk="$block" '{ l[NR] = $0 } /^COMMIT/ { c = NR } END { for (i = 1; i <= NR; i++) { if (i == c) print blk; print l[i] } }' "$f" >"${f}.harden.tmp"
        cat "${f}.harden.tmp" >"$f"
        rm -f "${f}.harden.tmp"
    done
    log "UFW: container/CNI interfaces (${CNI_IFACES[*]}) may reach node services and route"
}

ufw_container_ifaces_remove() {
    local f
    for f in /etc/ufw/before.rules /etc/ufw/before6.rules; do
        [[ -f $f ]] && grep -q "^# BEGIN ${MARK} container interfaces" "$f" || continue
        sed -i "/^# BEGIN ${MARK} container interfaces/,/^# END ${MARK} container interfaces/d" "$f"
    done
    return 0
}

# Proxmox VE: pve-firewall is the host firewall (datacenter / node / guest
# levels, cluster-wide config in /etc/pve). UFW is never installed: both
# would rewrite the same netfilter tables. Rules are only changed on request
# (PVE_FIREWALL_ENABLE=1), and then SSH and the web UI are allowed first.
configure_pve_firewall() {
    log "Proxmox VE: the host firewall is pve-firewall; UFW is not used"
    if pkg_installed ufw; then
        ufw --force disable >/dev/null 2>&1 || true
        disable_service ufw.service
        warn "Proxmox VE: UFW was installed and has been disabled (it conflicts with pve-firewall); remove it with: apt purge ufw"
    fi
    if ! pkg_installed pve-firewall; then
        warn "Proxmox VE: pve-firewall is not installed - the node has no host firewall"
        return 0
    fi
    systemctl unmask pve-firewall.service >/dev/null 2>&1 || true
    systemctl enable pve-firewall.service >/dev/null 2>&1 || true
    host_only "start pve-firewall" systemctl start pve-firewall.service
    local fw=/etc/pve/firewall/cluster.fw
    if [[ $PVE_FIREWALL_ENABLE == 1 ]]; then
        pve_firewall_enable "$fw"
    fi
    if [[ -f $fw ]] && awk '/^\[/ { s = $0 } s == "[OPTIONS]" && /^[[:space:]]*enable:[[:space:]]*1/ { f = 1 } END { exit !f }' "$fw"; then
        log "Proxmox VE: datacenter firewall enabled"
    else
        warn "Proxmox VE: the datacenter firewall is OFF - enable it in Datacenter > Firewall, or re-run with PVE_FIREWALL_ENABLE=1 (SSH and port 8006 are allowed first)"
    fi
    if [[ $FIREWALL_OUTBOUND_POLICY == deny ]]; then
        warn "Proxmox VE: FIREWALL_OUTBOUND_POLICY=deny is not applied - set policy_out in Datacenter > Firewall > Options (it must allow corosync, Ceph and migration traffic)"
    fi
}

# pve_firewall_enable FILE - turn the datacenter firewall on without
# clobbering existing rules: enable: 1 in [OPTIONS], and SSH + web UI accept
# rules (marked, replaced on re-runs) at the top of [RULES]. Corosync and
# the local management network are allowed by pve-firewall itself.
pve_firewall_enable() {
    local fw=$1 p src rules="" orig
    if [[ ! -d ${fw%/*} ]] && ! install -d -m 0750 "${fw%/*}" 2>/dev/null; then
        warn "Proxmox VE: ${fw%/*} is not writable (cluster not quorate?) - datacenter firewall not enabled"
        return 0
    fi
    local -a sources=("")
    [[ -n $PVE_FIREWALL_MGMT_SOURCE ]] && read -r -a sources <<<"$PVE_FIREWALL_MGMT_SOURCE"
    for src in "${sources[@]}"; do
        for p in "${SSH_PORTS[@]}" 8006; do
            rules+="IN ACCEPT${src:+ -source ${src}} -p tcp -dport ${p} -log nolog # ${MARK}: $( [[ $p == 8006 ]] && echo 'web UI' || echo SSH)"$'\n'
        done
    done
    orig=$(mktemp)
    if [[ -f $fw ]]; then
        cat "$fw" >"$orig"
        backup_file "$fw"
    fi
    awk -v rules="$rules" -v mark="$MARK" '
        BEGIN { hasopt = 0; hasrules = 0; en = 0; sec = "" }
        index($0, "# " mark ":") { next }
        /^\[/ {
            if (sec == "[OPTIONS]" && !en) { print "enable: 1"; print ""; en = 1 }
            sec = $0; print
            if (sec == "[OPTIONS]") hasopt = 1
            if (sec == "[RULES]") { hasrules = 1; printf "\n%s", rules; skip = 1 }
            next
        }
        skip && /^[[:space:]]*$/ { next }
        { skip = 0 }
        sec == "[OPTIONS]" && /^[[:space:]]*enable:/ { if (!en) print "enable: 1"; en = 1; next }
        { print }
        END {
            if (sec == "[OPTIONS]" && !en) { print "enable: 1"; en = 1 }
            if (!hasopt) printf "\n[OPTIONS]\n\nenable: 1\n"
            if (!hasrules) printf "\n[RULES]\n\n%s", rules
        }' "$orig" >"${fw}.harden.tmp"
    cat "${fw}.harden.tmp" >"$fw"
    rm -f "${fw}.harden.tmp"
    if command -v pve-firewall >/dev/null 2>&1 && ! pve-firewall compile >/dev/null 2>&1; then
        if [[ -s $orig ]]; then cat "$orig" >"$fw"; else rm -f "$fw"; fi
        rm -f "$orig"
        warn "Proxmox VE: the firewall configuration did not compile - ${fw} restored, firewall NOT enabled"
        return 0
    fi
    rm -f "$orig"
    log "Proxmox VE: datacenter firewall enabled; SSH (${SSH_PORTS[*]}) and 8006 allowed from ${PVE_FIREWALL_MGMT_SOURCE:-any source}"
}

# RHEL family: firewalld, default zone public with only SSH (and DHCPv6
# client) open, loopback anti-spoofing, optional egress allow-list.
configure_firewalld() {
    systemctl unmask firewalld.service >/dev/null 2>&1 || true
    systemctl enable firewalld.service >/dev/null 2>&1 || true
    if ! systemctl is-active --quiet firewalld.service; then
        host_only "start firewalld" systemctl start firewalld.service
    fi
    local zone=public p svc online=0
    # Desktops keep their default zone (FedoraWorkstation, ...) and its services
    # (mDNS, KDE Connect, ...); only SSH and the loopback rules are ensured.
    if is_desktop; then
        zone=$(firewall-cmd --get-default-zone 2>/dev/null || firewall-offline-cmd --get-default-zone 2>/dev/null || echo public)
    fi
    systemctl is-active --quiet firewalld.service && online=1
    # fw: permanent configuration, through the daemon or (not running, e.g.
    # no netfilter in a container) firewall-offline-cmd on the same files.
    if [[ $online == 1 ]]; then
        fw() { firewall-cmd --permanent -q "$@"; }
        is_desktop || firewall-cmd -q --set-default-zone="$zone"
    else
        fw() { firewall-offline-cmd -q "$@"; }
        is_desktop || firewall-offline-cmd -q --set-default-zone="$zone"
    fi
    # SSH first, before anything is removed - never cut the session.
    for p in "${SSH_PORTS[@]}"; do
        if [[ $p == 22 ]]; then fw --zone="$zone" --add-service=ssh; else fw --zone="$zone" --add-port="${p}/tcp"; fi
    done
    local -a listed
    if [[ $online == 1 ]]; then
        read -r -a listed <<<"$(firewall-cmd --permanent --zone="$zone" --list-services 2>/dev/null)"
    else
        read -r -a listed <<<"$(firewall-offline-cmd --zone="$zone" --list-services 2>/dev/null)"
    fi
    is_desktop && listed=()
    for svc in "${listed[@]}"; do
        case $svc in ssh|dhcpv6-client) ;; *) fw --zone="$zone" --remove-service="$svc"; log "firewalld: closed ${svc} in zone ${zone}" ;; esac
    done
    # Loopback: trusted on lo, spoofed 127.0.0.0/8 / ::1 from elsewhere dropped.
    fw --zone=trusted --add-interface=lo 2>/dev/null || true
    local zr
    for zr in trusted "$zone"; do
        fw --zone="$zr" --add-rich-rule='rule family="ipv4" source address="127.0.0.1" destination not address="127.0.0.1" drop' 2>/dev/null || true
        fw --zone="$zr" --add-rich-rule='rule family="ipv6" source address="::1" destination not address="::1" drop' 2>/dev/null || true
    done
    # Kubernetes: cluster/CNI ports in the default zone; pod/service
    # networks and existing CNI interfaces in the trusted zone (pods reach
    # node services and route through the node). Docker manages its own
    # "docker" zone.
    if is_k8s; then
        local port src i fam
        local -a srcs
        mapfile -t srcs < <(k8s_sources)
        while read -r port; do
            port=${port/:/-}
            if [[ ${#srcs[@]} -eq 0 ]]; then
                fw --zone="$zone" --add-port="$port"
            else
                for src in "${srcs[@]}"; do
                    fam=ipv4; [[ $src == *:* ]] && fam=ipv6
                    fw --zone="$zone" --add-rich-rule="rule family=\"${fam}\" source address=\"${src}\" port port=\"${port%/*}\" protocol=\"${port##*/}\" accept" 2>/dev/null || true
                done
            fi
        done < <(k8s_ports)
        fw --zone="$zone" --add-protocol=ipip 2>/dev/null || true
        while read -r src; do
            fw --zone=trusted --add-source="$src" 2>/dev/null || true
        done < <(k8s_cluster_cidrs)
        while read -r i; do
            fw --zone=trusted --add-interface="$i" 2>/dev/null || true
        done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(cni0|flannel|cali|vxlan|tunl0|cilium_|weave|kube-bridge)' || true)
        if [[ ${#srcs[@]} -eq 0 ]]; then
            warn "Kubernetes: cluster ports accept any source; set K8S_TRUSTED_CIDRS to the node network to narrow them"
        fi
        log "Kubernetes (${K8S_DISTRO}): cluster and CNI ports open in zone ${zone}, pod/service networks trusted"
    fi
    # firewalld drives nftables itself: a second ruleset service would conflict (CIS).
    systemctl disable --now nftables.service >/dev/null 2>&1 || true
    systemctl mask nftables.service >/dev/null 2>&1 || true
    if [[ $FIREWALL_OUTBOUND_POLICY == deny ]]; then
        local r
        fw --get-policies 2>/dev/null | qgrep -w harden-egress || fw --new-policy=harden-egress
        fw --policy=harden-egress --add-ingress-zone=HOST
        fw --policy=harden-egress --add-egress-zone=ANY
        fw --policy=harden-egress --set-target=REJECT
        for r in 53/udp 53/tcp 67/udp 547/udp 123/udp 80/tcp 443/tcp $FIREWALL_EXTRA_OUT; do
            fw --policy=harden-egress --add-port="$r"
        done
    fi
    unset -f fw
    if [[ $online == 1 ]]; then
        firewall-cmd -q --reload
        firewall-cmd --list-all || true
    fi
}

configure_pam() {
    step "5.5 PAM: password quality, history, lockout, hashing, su restriction"
    write_file 0644 /etc/security/pwquality.conf <<'EOF'
# Managed by harden-and-audit.sh - CIS L2 / DISA STIG password complexity.
minlen = 15
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 4
maxrepeat = 3
maxsequence = 3
maxclassrepeat = 4
difok = 8
dictcheck = 1
usercheck = 1
gecoscheck = 1
enforcing = 1
enforce_for_root
retry = 3
EOF
    local deny_root="even_deny_root
root_unlock_time = ${FAILLOCK_UNLOCK_TIME}"
    if is_pve; then
        deny_root="# even_deny_root / root_unlock_time: not set on Proxmox VE. The web UI login
# (root@pam) uses this same PAM stack, so locking root would let anyone on the
# network lock root out of both SSH and the web UI. Other users are still locked."
    fi
    write_file 0644 /etc/security/faillock.conf <<EOF
# Managed by ${SCRIPT_NAME} - temporary lockout (auto-unlocks; never permanent).
dir = /var/run/faillock
audit
silent
deny = ${FAILLOCK_DENY}
fail_interval = 900
unlock_time = ${FAILLOCK_UNLOCK_TIME}
${deny_root}
EOF
    write_file 0644 /etc/security/pwhistory.conf <<'EOF'
# Managed by harden-and-audit.sh
remember = 24
enforce_for_root
file = /etc/security/opasswd
EOF
    touch /etc/security/opasswd
    chown root:root /etc/security/opasswd
    chmod 0600 /etc/security/opasswd

    if is_rhel; then
        configure_authselect
    else
        configure_pam_debian
    fi

    # su is restricted to members of the (empty) sugroup: admins use sudo.
    getent group sugroup >/dev/null || groupadd -r sugroup
    backup_file /etc/pam.d/su
    if ! grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*group=sugroup' /etc/pam.d/su; then
        sed -i -E '/^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so/d' /etc/pam.d/su
        sed -i '0,/^# auth       required   pam_wheel.so$/s//# auth       required   pam_wheel.so\nauth       required   pam_wheel.so use_uid group=sugroup/' /etc/pam.d/su
        # EL: no commented example; after pam_rootok (root keeps su), else first.
        if ! grep -q 'group=sugroup' /etc/pam.d/su; then
            if grep -Eq '^auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so' /etc/pam.d/su; then
                sed -i -E '0,/^auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so.*$/s//&\nauth       required   pam_wheel.so use_uid group=sugroup/' /etc/pam.d/su
            else
                sed -i '0,/^auth/s//auth       required   pam_wheel.so use_uid group=sugroup\nauth/' /etc/pam.d/su
            fi
        fi
        grep -q 'group=sugroup' /etc/pam.d/su || printf 'auth       required   pam_wheel.so use_uid group=sugroup\n' >>/etc/pam.d/su
    fi
    # shadow group must have no members (CIS)
    if [[ -n $(getent group shadow | cut -d: -f4) ]]; then
        gpasswd -M '' shadow >/dev/null
    fi
}

# RHEL family: a custom authselect profile (CIS EL) with faillock, password
# history and no nullok. pam_pwhistory gets remember=24 in the profile
# itself (EL8's PAM has no pwhistory.conf). The base profile must match the
# installed modules: "sssd" needs pam_sss.so (sssd-client); without it the
# account phase denies EVERY login, SSH included. Local-only hosts use
# "minimal" (EL8/9) or "local" (EL10).
pam_modules_present() {
    local f m missing=0
    for f in "$@"; do
        while read -r m; do
            [[ -e /usr/lib64/security/${m} || -e /usr/lib/security/${m} || -e /lib64/security/${m} ]] && continue
            echo "PAM module ${m} referenced by ${f} is not installed" >&2
            missing=1
        # A leading "-" (e.g. "-session optional pam_systemd.so") tells PAM to
        # skip the line silently when the module is absent: never a denial.
        done < <(grep -Ev '^[[:space:]]*(#|-)' "$f" | grep -Eo '\bpam_[a-z0-9_]+\.so' | sort -u)
    done
    return "$missing"
}

configure_authselect() {
    local base prof=/etc/authselect/custom/harden f feat
    if [[ -e /usr/lib64/security/pam_sss.so ]]; then
        base=sssd
    elif authselect list 2>/dev/null | qgrep -E '^-[[:space:]]+local[[:space:]]'; then
        base=local
    else
        base=minimal
    fi
    # A profile created from another base (earlier run, sssd removed) is rebuilt.
    if [[ -d $prof && $(cat "${prof}/.harden-base" 2>/dev/null) != "$base" ]]; then
        rm -rf "$prof"
    fi
    if [[ ! -d $prof ]]; then
        authselect create-profile harden -b "$base" --symlink-meta >/dev/null
        echo "$base" >"${prof}/.harden-base"
    fi
    for f in system-auth password-auth; do
        [[ -f ${prof}/${f} ]] || continue
        # pam_unix must reuse the pwquality-checked token (CIS pam_unix_authtok).
        sed -i -E '/^password[[:space:]].*pam_unix\.so/ { /use_authtok/! s/(pam_unix\.so)/\1 use_authtok/ }' "${prof}/${f}"
        # EL9+: pwhistory.conf carries remember/enforce_for_root (CIS checks it there).
        if (( OS_MAJOR == 8 )); then
            sed -i -E '/pam_pwhistory\.so/ { /remember=/! s/(pam_pwhistory\.so)/\1 remember=24 enforce_for_root/ }' "${prof}/${f}"
        fi
        sed -i -E 's/[[:space:]]nullok\b//g' "${prof}/${f}"
    done
    local -a feats=()
    local -a wantfeat=(with-faillock with-pwhistory without-nullok)
    # Keep what the host already uses (fingerprint, smartcard, mkhomedir,
    # gnome-keyring, ...): dropping it would break desktop logins.
    while read -r feat; do
        [[ $feat == with-* || $feat == without-* ]] && wantfeat+=("$feat")
    done < <(authselect current 2>/dev/null | awk '/^- /{print $2}')
    for feat in $(printf '%s\n' "${wantfeat[@]}" | awk '!seen[$0]++'); do
        authselect list-features "custom/harden" 2>/dev/null | qgrep -Fx "$feat" && feats+=("$feat")
    done
    backup_file /etc/pam.d/system-auth
    backup_file /etc/pam.d/password-auth
    local prev
    prev=$(authselect current -r 2>/dev/null || true)
    authselect select custom/harden "${feats[@]}" --force >/dev/null
    authselect apply-changes >/dev/null 2>&1 || true
    # Anti-lockout: a stack referencing a missing module denies all logins.
    if ! pam_modules_present /etc/pam.d/system-auth /etc/pam.d/password-auth; then
        if [[ -n $prev ]]; then
            # shellcheck disable=SC2086  # profile name followed by its features
            authselect select $prev --force >/dev/null 2>&1 || true
        fi
        die "the hardened PAM stack references a missing module (logins would be denied); previous authselect profile '${prev:-none}' restored"
    fi
    grep -q 'pam_faillock.so preauth' /etc/pam.d/system-auth || die "pam_faillock was not enabled"
    grep -q 'pam_pwquality.so' /etc/pam.d/system-auth || die "pam_pwquality was not enabled"
    if grep -Eq '^[^#].*pam_unix\.so.*nullok' /etc/pam.d/system-auth /etc/pam.d/password-auth; then
        die "pam_unix nullok is still present"
    fi
    log "authselect: custom/harden (from ${base}) ${feats[*]}"
}

configure_pam_debian() {
    # pam-auth-update profiles (the Debian-native way to edit common-*).
    write_file 0644 /usr/share/pam-configs/harden-faillock <<'EOF'
Name: harden-and-audit: lock accounts after repeated authentication failures
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
	sufficient	pam_faillock.so authsucc
EOF
    write_file 0644 /usr/share/pam-configs/harden-faillock-notify <<'EOF'
Name: harden-and-audit: faillock pre-check and reset on success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	required	pam_faillock.so preauth
Account-Type: Primary
Account:
	required	pam_faillock.so
EOF
    write_file 0644 /usr/share/pam-configs/harden-pwhistory <<'EOF'
Name: harden-and-audit: password history (24)
Default: yes
Priority: 1024
Password-Type: Primary
Password:
	requisite	pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok
Password-Initial:
	requisite	pam_pwhistory.so remember=24 enforce_for_root try_first_pass
EOF
    # pam_unix without nullok, yescrypt hashing (replaces the stock profile).
    write_file 0644 /usr/share/pam-configs/harden-unix <<'EOF'
Name: harden-and-audit: Unix authentication (no empty passwords, yescrypt)
Default: yes
Priority: 257
Conflicts: unix
Auth-Type: Primary
Auth:
	[success=end default=ignore]	pam_unix.so try_first_pass
Auth-Initial:
	[success=end default=ignore]	pam_unix.so
Account-Type: Primary
Account:
	[success=end new_authtok_reqd=done default=ignore]	pam_unix.so
Account-Initial:
	[success=end new_authtok_reqd=done default=ignore]	pam_unix.so
Session-Type: Additional
Session:
	required	pam_unix.so
Session-Initial:
	required	pam_unix.so
Password-Type: Primary
Password:
	[success=end default=ignore]	pam_unix.so obscure use_authtok try_first_pass yescrypt
Password-Initial:
	[success=end default=ignore]	pam_unix.so obscure yescrypt
EOF
    local f
    for f in common-auth common-account common-password common-session common-session-noninteractive; do
        backup_file "/etc/pam.d/${f}"
    done
    pam-auth-update --package --force --enable harden-unix harden-faillock harden-faillock-notify harden-pwhistory --remove unix
    grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth || die "pam_faillock was not enabled"
    grep -q 'pam_pwquality.so' /etc/pam.d/common-password || die "pam_pwquality was not enabled"
    if grep -Eq '^[^#].*pam_unix\.so.*nullok' /etc/pam.d/common-auth /etc/pam.d/common-password; then
        die "pam_unix nullok is still present"
    fi
}

# sed_shell_file FILE SED-ARGS... - edit a shell startup file (/etc/profile,
# bashrc, profile.d) through a copy and install it only if "bash -n" accepts
# the result. A broken /etc/profile stops every login script from running.
sed_shell_file() {
    local f=$1 tmp; shift
    tmp=$(mktemp "${f}.XXXXXX")
    cp -a -- "$f" "$tmp"
    sed -i -E "$@" "$tmp"
    if cmp -s "$f" "$tmp"; then rm -f "$tmp"; return 0; fi
    if ! bash -n "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        warn "${f}: edit skipped, the result would not parse (bash -n); file left unchanged"
        return 1
    fi
    backup_file "$f"
    mv -f "$tmp" "$f"
}

# TMOUT is read-only once /etc/profile.d/60-harden.sh has run, so any later
# assignment (a profile.d file sorting after it, /etc/bash.bashrc, root's
# dotfiles) prints "-bash: TMOUT: readonly variable" at every login. Guard
# those assignments so they only apply when TMOUT is not set yet: an earlier,
# stricter value still wins and nothing is printed. Other users' dotfiles are
# reported, not edited.
guard_other_tmout() {
    local re='^([[:space:]]*)(((export|readonly|declare[[:space:]]+-[[:alpha:]]+|typeset[[:space:]]+-[[:alpha:]]+)[[:space:]]+)?TMOUT=)'
    local f
    for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/*.sh /root/.bashrc /root/.profile /root/.bash_profile /root/.bash_login; do
        [[ -f $f && $f != /etc/profile.d/60-harden.sh ]] || continue
        grep -Eq "$re" "$f" || continue
        sed_shell_file "$f" "s/${re}/\\1[ -n \"\${TMOUT:-}\" ] || \\2/" \
            && log "TMOUT: guarded another assignment in ${f} (TMOUT is read-only after 60-harden.sh)"
    done
    local u home
    while read -r u; do
        home=$(getent passwd "$u" | cut -d: -f6)
        for f in "$home/.bashrc" "$home/.profile" "$home/.bash_profile" "$home/.bash_login"; do
            [[ -f $f ]] && grep -Eq "$re" "$f" \
                && warn "TMOUT: ${f} assigns TMOUT, which is read-only system-wide (${SHELL_TMOUT}s); that user will see 'TMOUT: readonly variable' at login until the line is removed"
        done
    done < <(interactive_users)
    return 0
}

configure_login_defs() {
    step "5.6 password aging, umask, account inactivity"
    local f=/etc/login.defs
    set_kv "$f" PASS_MAX_DAYS "$PASS_MAX_DAYS" $'\t'
    set_kv "$f" PASS_MIN_DAYS "$PASS_MIN_DAYS" $'\t'
    set_kv "$f" PASS_WARN_AGE "$PASS_WARN_AGE" $'\t'
    set_kv "$f" UMASK 027 $'\t\t'
    if is_rhel && ! is_fedora; then
        # EL CIS: SHA512 (matches the authselect profiles' pam_unix hashing).
        set_kv "$f" ENCRYPT_METHOD SHA512 ' '
    elif is_fedora; then
        # Fedora's authselect profiles hash with yescrypt.
        set_kv "$f" ENCRYPT_METHOD YESCRYPT ' '
    else
        set_kv "$f" ENCRYPT_METHOD YESCRYPT ' '
        set_kv "$f" LOGIN_RETRIES 3 $'\t\t'
        set_kv "$f" LOGIN_TIMEOUT 60 $'\t\t'
    fi
    set_kv "$f" HOME_MODE 0750 $'\t\t'
    useradd -D -f "$ACCOUNT_INACTIVE_DAYS"
    # Apply aging to existing accounts that have a usable password - except
    # where that would expire the password immediately (lockout risk).
    local today u hash lastchg
    today=$(( $(date +%s) / 86400 ))
    # shadow-utils 4.20 (Fedora 45) removed "chage --mindays"; login.defs
    # PASS_MIN_DAYS still applies to new passwords there.
    local -a minday=()
    chage --help 2>&1 | qgrep -- '--mindays' && minday=(--mindays "$PASS_MIN_DAYS")
    while IFS=: read -r u hash lastchg _; do
        [[ $hash == \$* ]] || continue
        # Proxmox VE: an expired root password makes PAM's account phase fail
        # for root's non-interactive key logins between nodes (migration,
        # replication, cluster tasks) and blocks root@pam in the web UI.
        if is_pve && [[ $u == root ]]; then continue; fi
        if [[ -n $lastchg && $lastchg =~ ^[0-9]+$ && $(( lastchg + PASS_MAX_DAYS )) -lt $today ]]; then
            warn "password of '${u}' is older than ${PASS_MAX_DAYS} days: aging NOT applied to avoid immediate expiry - change it, then re-run"
            continue
        fi
        if [[ -z $lastchg || $lastchg -gt $today ]]; then
            chage -d "$today" "$u"
        fi
        chage --maxdays "$PASS_MAX_DAYS" "${minday[@]}" --warndays "$PASS_WARN_AGE" --inactive "$ACCOUNT_INACTIVE_DAYS" "$u"
        # chage without --mindays (shadow 4.20): passwd -n sets the minimum age.
        if [[ ${#minday[@]} -eq 0 ]]; then
            passwd -n "$PASS_MIN_DAYS" "$u" >/dev/null 2>&1 || warn "could not set the minimum password age of ${u}"
        fi
    done < /etc/shadow
    if is_pve; then
        chage --maxdays 99999 --inactive -1 --expiredate -1 root
        log "Proxmox VE: root is exempt from password expiry and inactivity locking (cluster operations run as root)"
    fi

    # Interactive shells: umask 027, idle timeout. Desktops: no TMOUT (it would
    # close idle terminal tabs); the desktop's own screen lock covers idleness.
    if is_desktop; then
        write_file 0644 /etc/profile.d/60-harden.sh <<EOF
# Managed by ${SCRIPT_NAME} (desktop mode: no shell TMOUT, the screen lock covers idle sessions)
umask 027
EOF
    elif is_rhel; then
        # The EL CIS check expects "typeset -xr TMOUT=<n>".
        write_file 0644 /etc/profile.d/60-harden.sh <<EOF
# Managed by ${SCRIPT_NAME}
umask 027
# Idle shell timeout (read-only, exported); skip if already set (re-sourcing).
if [ -z "\${TMOUT:-}" ]; then
    typeset -xr TMOUT=${SHELL_TMOUT}
fi
EOF
    elif is_ubuntu; then
        # The Ubuntu CIS check expects the POSIX three-line form.
        write_file 0644 /etc/profile.d/60-harden.sh <<EOF
# Managed by ${SCRIPT_NAME}
umask 027
# Idle shell timeout (read-only, exported); skip if already set (re-sourcing).
if [ -z "\${TMOUT:-}" ]; then
    TMOUT=${SHELL_TMOUT}
    readonly TMOUT
    export TMOUT
fi
EOF
    else
        write_file 0644 /etc/profile.d/60-harden.sh <<EOF
# Managed by ${SCRIPT_NAME}
umask 027
# Idle shell timeout (read-only, exported). bash only: dash also reads
# /etc/profile.d and has no declare; skip if already set (re-sourcing).
if [ -n "\${BASH_VERSION:-}" ] && [ -z "\${TMOUT:-}" ]; then
    declare -xr TMOUT=${SHELL_TMOUT}
fi
EOF
    fi
    is_desktop || guard_other_tmout
    if is_rhel && [[ -f /etc/bashrc ]]; then
        # EL CIS checks every umask in /etc/bashrc (inside its if/else).
        sed_shell_file /etc/bashrc 's/^([^#]*\bumask)[[:space:]]+[0-7]+/\1 027/' || true
    fi
    for f in /etc/profile /etc/bash.bashrc /etc/bashrc; do
        [[ -f $f ]] || continue
        # Weak umask values are raised to 027 in place. They used to be
        # commented out, which left an empty then/else on EL8's /etc/profile
        # (umask 002/022 in an if/else): a syntax error that stopped every
        # login script. Lines commented out that way are restored as 027.
        sed_shell_file "$f" \
            -e 's/^# ([[:space:]]*umask)[[:space:]]+[0-7]+  \(superseded by harden-and-audit\)$/\1 027/' \
            -e 's/^([[:space:]]*umask)[[:space:]]+0?(0[0-2][0-6]|[0-2][0-6])[[:space:]]*$/\1 027/' || true
        backup_file "$f"
        sed -i "/^umask 027  # ${MARK}$/d" "$f"
        grep -qx 'umask 027' "$f" || printf '\n# %s\numask 027\n' "$MARK" >>"$f"
    done
    grep -q "^umask 027" /root/.bashrc 2>/dev/null || printf '\numask 027\n' >>/root/.bashrc
    # System accounts never get a login shell.
    local name uid shell
    while IFS=: read -r name _ uid _ _ _ shell; do
        if (( uid < UID_MIN_VALUE )) && [[ $name != root && $name != sync && $name != shutdown && $name != halt ]]; then
            if [[ $shell != */nologin && $shell != */false ]]; then
                usermod -s /usr/sbin/nologin "$name"
                log "set nologin shell for system account ${name}"
            fi
        fi
    done < /etc/passwd
    # Lock system accounts' passwords too
    while IFS=: read -r name _ uid _; do
        if (( uid < UID_MIN_VALUE )) && [[ $name != root ]]; then
            usermod -L "$name" >/dev/null 2>&1 || true
        fi
    done < /etc/passwd
}

# Ubuntu 25.10+ ships sudo-rs as /usr/bin/sudo (update-alternatives), with
# classic sudo installed as sudo.ws. sudo-rs has no sudo log file and no I/O
# logging, which the CIS/STIG sudo controls require.
select_sudo_provider() {
    [[ -L /etc/alternatives/sudo ]] || return 0
    local cur
    cur=$(readlink -f /etc/alternatives/sudo)
    case $SUDO_PROVIDER in
        keep)
            log "SUDO_PROVIDER=keep: sudo stays ${cur}"
            ;;
        classic)
            [[ $cur == */sudo.ws ]] && { log "sudo is classic sudo (${cur})"; return 0; }
            [[ -x /usr/bin/sudo.ws ]] || apt_install sudo
            if [[ ! -x /usr/bin/sudo.ws || ! -x /usr/sbin/visudo.ws ]]; then
                warn "classic sudo (sudo.ws) is not available: sudo stays ${cur}"
                return 0
            fi
            # Anti-lockout: classic sudo must accept the existing policy first.
            if ! /usr/sbin/visudo.ws -cq >/dev/null 2>&1; then
                warn "the current sudoers policy does not validate under classic sudo: sudo stays ${cur} (review with visudo.ws -c)"
                return 0
            fi
            update-alternatives --set sudo /usr/bin/sudo.ws >/dev/null
            log "sudo provider: classic sudo (sudo.ws) selected over ${cur} for sudo log file and I/O logging (SUDO_PROVIDER=keep to retain it)"
            ;;
        *) die "SUDO_PROVIDER must be 'classic' or 'keep'" ;;
    esac
}

configure_sudo() {
    step "5.7 sudo: pty, logging, re-authentication"
    select_sudo_provider
    local -a settings=(
        'Defaults use_pty'
        'Defaults logfile="/var/log/sudo.log"'
        'Defaults log_input, log_output'
        'Defaults iolog_dir="/var/log/sudo-io/%{user}"'
        'Defaults timestamp_timeout=15'
        'Defaults env_reset'
        'Defaults !visiblepw'
        'Defaults always_set_home'
        'Defaults ignore_dot'
        'Defaults passwd_tries=3'
    )
    local tmp line one
    tmp=$(mktemp)
    one=$(mktemp)
    echo "# Managed by ${SCRIPT_NAME}" >"$tmp"
    # Keep only what the active sudo implementation understands (sudo-rs
    # rejects the logging settings); classic sudo accepts every line.
    for line in "${settings[@]}"; do
        printf '%s\n' "$line" >"$one"
        if visudo -cqf "$one" >/dev/null 2>&1; then
            printf '%s\n' "$line" >>"$tmp"
        else
            warn "the active sudo implementation rejects '${line}': setting skipped"
        fi
    done
    rm -f "$one"
    visudo -cqf "$tmp" || { rm -f "$tmp"; die "generated sudoers fragment is invalid"; }
    install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/60-harden
    rm -f "$tmp"
    visudo -cq || die "sudoers configuration is invalid"
    touch /var/log/sudo.log
    chmod 0600 /var/log/sudo.log
    install -d -m 0700 /var/log/sudo-io
    # NOPASSWD / !authenticate are reported, never auto-removed: removing them
    # can strip the only working sudo path (cloud images) and lock admins out.
    local hits
    hits=$(grep -rEn '^[^#].*(NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d 2>/dev/null || true)
    [[ -n $hits ]] && warn "sudo rules without re-authentication remain (review manually): ${hits//$'\n'/; }"
    return 0
}

configure_banners() {
    step "5.8 login warning banner (${BANNER_STYLE})"
    # Proxmox VE: pvebanner.service rewrites /etc/issue at every boot (web UI
    # URL), which would replace the login banner.
    if is_pve; then
        disable_service pvebanner.service
    fi
    local banner org=${BANNER_ORG:-the owner of this system}
    # Plain printable text only; no OS/kernel details (CIS 1.7.x).
    org=${org//[^[:print:]]/}; org=${org//\\/}
    case ${BANNER_STYLE} in
        dod)
            banner=$(cat <<'EOF'
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF
)
            ;;
        *)
            [[ ${BANNER_STYLE} == generic ]] || warn "BANNER_STYLE=${BANNER_STYLE} unknown; using the generic notice"
            banner=$(cat <<EOF
WARNING: AUTHORIZED USE ONLY

This computer system is the property of ${org} and is provided for authorized use only.

By using this system you acknowledge and consent to the following:

- All activity on this system may be monitored, recorded, and audited by authorized personnel.
- You have no expectation of privacy in any communications or data stored on, processed by, or transmitted through this system.
- Data on this system may be inspected, copied, and disclosed for security, legal, or business purposes, including to law enforcement.
- Unauthorized access or use is prohibited and may result in disciplinary action and civil or criminal penalties.

If you do not consent to these conditions, disconnect now.
EOF
)
            ;;
    esac
    if [[ -n ${BANNER_FILE} ]]; then
        if [[ -r ${BANNER_FILE} ]]; then
            banner=$(cat "$BANNER_FILE")
        else
            warn "BANNER_FILE=${BANNER_FILE} is not readable; using the ${BANNER_STYLE} notice"
        fi
    fi
    printf '%s\n' "$banner" | write_file 0644 /etc/issue
    printf '%s\n' "$banner" | write_file 0644 /etc/issue.net
    printf 'Authorized use only. All activity may be monitored and reported.\n' | write_file 0644 /etc/motd
    # Dynamic MOTD must not disclose kernel/OS details.
    [[ -f /etc/update-motd.d/10-uname ]] && chmod 0644 /etc/update-motd.d/10-uname
    return 0
}

# Desktop mode, GNOME: lock the screen after 15 idle minutes (5 s grace),
# Login banner on the login screen, no user list, no autorun, no window popping
# up on mount (USB drives still mount). Locked so users cannot undo them.
configure_gnome_desktop() {
    is_desktop || return 0
    command -v dconf >/dev/null 2>&1 || return 0
    local banner
    banner=$(tr '\n' ' ' </etc/issue | sed -E "s/'/\\\\'/g; s/[[:space:]]+/ /g")
    install -d -m 0755 /etc/dconf/profile /etc/dconf/db/local.d/locks /etc/dconf/db/distro.d/locks
    if [[ ! -f /etc/dconf/profile/user ]]; then
        printf 'user-db:user\nsystem-db:local\nsystem-db:site\nsystem-db:distro\n' | write_file 0644 /etc/dconf/profile/user
    fi
    write_file 0644 /etc/dconf/db/local.d/00-security-settings <<'EOF'
# Managed by harden-and-audit.sh (desktop mode)
[org/gnome/desktop/session]
idle-delay=uint32 900

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 5

[org/gnome/desktop/media-handling]
autorun-never=true
automount-open=false
EOF
    write_file 0644 /etc/dconf/db/local.d/locks/00-security-settings-lock <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/media-handling/autorun-never
/org/gnome/desktop/media-handling/automount-open
EOF
    {
        echo "# Managed by ${SCRIPT_NAME} (desktop mode)"
        echo "[org/gnome/login-screen]"
        echo "banner-message-enable=true"
        echo "banner-message-text='${banner}'"
        echo "disable-user-list=true"
    } | write_file 0644 /etc/dconf/db/distro.d/00-security-settings
    write_file 0644 /etc/dconf/db/distro.d/locks/00-security-settings-lock <<'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
/org/gnome/login-screen/disable-user-list
EOF
    dconf update || warn "dconf update failed: GNOME settings apply after the next dconf update"
    log "desktop mode: GNOME screen lock (15 min), login banner, no autorun"
}

configure_kernel_modules() {
    step "5.9 disable unneeded filesystems, protocols and USB storage"
    local -a mods=(cramfs freevxfs hfs hfsplus jffs2 udf dccp rds sctp tipc atm can firewire-core firewire-ohci)
    # Desktops keep USB drives and overlay (toolbox / podman / flatpak builders).
    is_desktop || mods+=(usb-storage)
    # overlayfs: container image layers (Docker, containerd, Podman, Kubernetes,
    # Docker inside Proxmox LXC containers).
    if ! containers_on && ! is_desktop && ! is_pve; then mods+=(overlay overlayfs); fi
    # Ubuntu and EL CIS also disable squashfs, which every snap is mounted
    # from: only where snapd is absent.
    if is_ubuntu || is_rhel; then
        if pkg_installed snapd; then
            log "squashfs stays available: snapd is installed (snaps are squashfs images)"
        else
            mods+=(squashfs)
        fi
    fi
    # SCTP: corosync's knet transport can run over it (Proxmox VE), and
    # Kubernetes Services/CNIs may use it when the cluster declares it.
    if grep -Eqs '^[[:space:]]*knet_transport:[[:space:]]*sctp' /etc/pve/corosync.conf /etc/corosync/corosync.conf \
        || { is_k8s && grep -RIqs 'protocol:[[:space:]]*SCTP' /etc/kubernetes/manifests /var/lib/rancher/k3s/server/manifests; }; then
        local -a keep=()
        local x
        for x in "${mods[@]}"; do [[ $x == sctp ]] || keep+=("$x"); done
        mods=("${keep[@]}")
        log "SCTP stays available (corosync knet / Kubernetes uses it)"
    fi
    {
        echo "# Managed by ${SCRIPT_NAME}"
        local m
        for m in "${mods[@]}"; do
            echo "install ${m} /bin/false"
            echo "blacklist ${m}"
        done
    } | write_file 0644 /etc/modprobe.d/60-harden-blacklist.conf
    if ! containers_on && ! is_desktop && ! is_pve; then
        log "overlayfs disabled (no container runtime found; set ALLOW_CONTAINERS=1 before installing Docker/Podman/Kubernetes)"
    fi
}

configure_mounts() {
    step "5.10 /tmp, /var/tmp, /dev/shm: nodev,nosuid,noexec"
    backup_file /etc/fstab
    local opts="nodev,nosuid,noexec"
    # /tmp on desktops: nodev,nosuid only (AppImages, IDEs and installers run from it).
    local tmpopts=$opts
    is_desktop && tmpopts="nodev,nosuid"
    # /tmp
    if grep -Eq '^[^#[:space:]]+[[:space:]]+/tmp[[:space:]]' /etc/fstab; then
        awk -v o="$tmpopts" '$2=="/tmp" && $1 !~ /^#/ { n=split(o,a,","); for (i=1;i<=n;i++) if ($4 !~ "(^|,)"a[i]"(,|$)") $4=$4","a[i] } {print}' /etc/fstab >/etc/fstab.tmp
        cat /etc/fstab.tmp >/etc/fstab && rm -f /etc/fstab.tmp
    else
        local unit=/usr/lib/systemd/system/tmp.mount
        [[ -f $unit ]] || unit=/usr/share/systemd/tmp.mount
        if [[ -f $unit ]]; then
            write_file 0644 /etc/systemd/system/tmp.mount <<EOF
# Managed by ${SCRIPT_NAME}
[Unit]
Description=Temporary Directory /tmp (hardened)
Documentation=https://systemd.io/TEMPORARY_DIRECTORIES
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,${tmpopts},size=50%%,nr_inodes=1m

[Install]
WantedBy=local-fs.target
EOF
            systemctl daemon-reload
            systemctl enable tmp.mount >/dev/null 2>&1 || true
        fi
    fi
    # /dev/shm
    if grep -Eq '^[^#[:space:]]+[[:space:]]+/dev/shm[[:space:]]' /etc/fstab; then
        sed -i -E '\|^[^#[:space:]]+[[:space:]]+/dev/shm[[:space:]]|d' /etc/fstab
    fi
    # nofail on every line the script adds: a mount that fails at boot is
    # logged, it never drops a console-less cloud VM into emergency mode.
    printf 'tmpfs\t/dev/shm\ttmpfs\tdefaults,%s,size=50%%,nofail\t0\t0\n' "$opts" >>/etc/fstab
    # /var/tmp: honour a dedicated partition; otherwise bind it onto itself
    # to enforce the mount options (does not add space isolation).
    if grep -Eq '^[^#[:space:]]+[[:space:]]+/var/tmp[[:space:]]' /etc/fstab; then
        awk -v o="$opts" '$2=="/var/tmp" && $1 !~ /^#/ { n=split(o,a,","); for (i=1;i<=n;i++) if ($4 !~ "(^|,)"a[i]"(,|$)") $4=$4","a[i] } {print}' /etc/fstab >/etc/fstab.tmp
        cat /etc/fstab.tmp >/etc/fstab && rm -f /etc/fstab.tmp
    else
        printf '/var/tmp\t/var/tmp\tnone\tbind,%s,nofail\t0\t0\n' "$opts" >>/etc/fstab
    fi
    # Hosts hardened by an earlier version: give the script's bind line nofail.
    sed -i -E '/^\/var\/tmp[[:space:]]+\/var\/tmp[[:space:]]+none[[:space:]]+/{/nofail/!s/^(\/var\/tmp[[:space:]]+\/var\/tmp[[:space:]]+none[[:space:]]+[^[:space:]]+)/\1,nofail/}' /etc/fstab
    systemctl daemon-reload

    # Apply now where safe.
    host_only "remount /dev/shm" mount -o remount,"$opts" /dev/shm
    if ! findmnt -n /var/tmp >/dev/null; then
        host_only "bind-mount /var/tmp" mount --bind /var/tmp /var/tmp
    fi
    host_only "remount /var/tmp" mount -o remount,bind,"$opts" /var/tmp
    if findmnt -n /tmp >/dev/null; then
        host_only "remount /tmp" mount -o remount,"$tmpopts" /tmp
    elif [[ -n $(find /tmp -mindepth 1 -maxdepth 2 -type s 2>/dev/null) ]]; then
        warn "/tmp holds live sockets (e.g. tmux): the hardened tmpfs /tmp activates at next boot"
    else
        host_only "mount hardened /tmp" systemctl start tmp.mount
    fi
}

configure_coredumps() {
    step "5.11 disable core dumps"
    write_file 0644 /etc/security/limits.d/60-harden.conf <<'EOF'
# Managed by harden-and-audit.sh
*    hard    core    0
root hard    core    0
EOF
    # Debian 13's systemd-coredump ships "* hard core infinity"; neutralise it.
    local f
    for f in /etc/security/limits.conf /etc/security/limits.d/*.conf; do
        [[ $f == /etc/security/limits.d/60-harden.conf ]] && continue
        if grep -Eq '^[[:space:]]*[^#[:space:]]+[[:space:]]+(hard|-)[[:space:]]+core[[:space:]]+' "$f"; then
            backup_file "$f"
            sed -i -E 's/^([[:space:]]*[^#[:space:]]+[[:space:]]+(hard|-)[[:space:]]+core[[:space:]]+.*)/# disabled by harden-and-audit: \1/' "$f"
        fi
    done
    write_file 0644 /etc/systemd/coredump.conf.d/60-harden.conf <<'EOF'
# Managed by harden-and-audit.sh
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
}

# Hourly logrotate (so maxsize is enforced within the hour, not once a day)
# followed by a hard size/free-space budget for /var/log: a noisy service can
# never fill the disk and take the host down.
configure_log_budget() {
    numfmt --from=iec "$LOG_MAX_TOTAL" >/dev/null 2>&1 || die "LOG_MAX_TOTAL='${LOG_MAX_TOTAL}' is not a size (e.g. 4G)"
    [[ $LOG_MIN_FREE_PCT =~ ^[0-9]+$ && $LOG_MIN_FREE_PCT -lt 90 ]] || die "LOG_MIN_FREE_PCT must be 0-89"
    {
        printf '#!/bin/bash\n'
        printf '# Managed by harden-and-audit.sh - prune /var/log to its budget.\n'
        printf 'DEFAULT_MAX=%q\nDEFAULT_MIN_FREE_PCT=%q\n' "$LOG_MAX_TOTAL" "$LOG_MIN_FREE_PCT"
        cat <<'EOF'
# Deletes the OLDEST ROTATED archives (never a live log, never the journal,
# which journald caps itself) while /var/log is larger than MAX or its
# filesystem has less than MIN_FREE_PCT free. Usage: [MAX] [MIN_FREE_PCT]
set -u
MAX=$(numfmt --from=iec "${1:-$DEFAULT_MAX}")
MIN_FREE_PCT=${2:-$DEFAULT_MIN_FREE_PCT}
used=$(du -sxb /var/log 2>/dev/null | cut -f1)
free_pct() { df -P /var/log | awk 'NR == 2 { gsub("%", "", $5); print 100 - $5 }'; }
over() { (( used > MAX || $(free_pct) < MIN_FREE_PCT )); }
over || exit 0
start=$used n=0
while IFS= read -r -d '' rec; do
    over || break
    rec=${rec#* }; size=${rec%% *}; f=${rec#* }
    if rm -f -- "$f"; then used=$(( used - size )); n=$(( n + 1 )); fi
done < <(find /var/log -xdev -regextype posix-extended -type f -not -path '/var/log/journal/*' \
    \( -name '*.gz' -o -name '*.xz' -o -name '*.zst' -o -name '*.bz2' -o -name '*.old' \
       -o -regex '.*\.[0-9]+(\.log)?' -o -regex '.*-[0-9]{8}([0-9]{2})?(\.log)?' \) \
    -printf '%T@ %s %p\0' | sort -zn)
msg="pruned ${n} rotated log file(s), freed $(numfmt --to=iec $(( start - used ))); /var/log now $(numfmt --to=iec "$used"), $(free_pct)% free"
if over; then msg+=" - STILL OVER BUDGET: live logs alone exceed it"; fi
logger -t harden-log-budget -p user.warning "$msg"
echo "$msg"
EOF
    } | write_file 0700 /usr/local/sbin/harden-log-budget
    # EL8's logrotate has no systemd units (cron.daily only): ship them.
    if ! systemctl cat logrotate.service >/dev/null 2>&1; then
        write_file 0644 /etc/systemd/system/logrotate.service <<'EOF'
# Managed by harden-and-audit.sh (this logrotate ships no systemd units)
[Unit]
Description=Rotate log files
ConditionACPower=true

[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate /etc/logrotate.conf
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF
        write_file 0644 /etc/systemd/system/logrotate.timer <<'EOF'
# Managed by harden-and-audit.sh
[Unit]
Description=Hourly rotation of log files

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF
        # The cron.daily job would rotate a second time.
        if [[ -f /etc/cron.daily/logrotate ]]; then
            backup_file /etc/cron.daily/logrotate
            rm -f /etc/cron.daily/logrotate
        fi
    fi
    write_file 0644 /etc/systemd/system/logrotate.timer.d/60-harden.conf <<'EOF'
# Managed by harden-and-audit.sh - rotate hourly so maxsize is enforced
# within the hour (logrotate.conf keeps "daily" for time-based rotation).
[Timer]
OnCalendar=
OnCalendar=hourly
AccuracySec=1m
RandomizedDelaySec=0
EOF
    write_file 0644 /etc/systemd/system/logrotate.service.d/60-harden.conf <<'EOF'
# Managed by harden-and-audit.sh - after rotating, prune /var/log to budget.
[Service]
ExecStartPost=-/usr/local/sbin/harden-log-budget
EOF
    systemctl daemon-reload
    systemctl enable --now logrotate.timer >/dev/null 2>&1 || true
    log "log budget: /var/log capped at ${LOG_MAX_TOTAL} with >= ${LOG_MIN_FREE_PCT}% disk free; ${LOG_ROTATE_KEEP} generations, ${LOG_MAXSIZE} max per file, rotated hourly"
    # Enforce now: an oversized /var/log also makes the AIDE baseline crawl.
    local out
    out=$(/usr/local/sbin/harden-log-budget) || true
    if [[ -n $out ]]; then log "log budget: ${out}"; fi
}

configure_logging() {
    step "5.12 journald, rsyslog and logrotate (bounded, rotated, persistent)"
    # Storage/Compress/ForwardToSyslog are set in journald.conf itself (where
    # CIS scanners read them); size limits live in a drop-in.
    local jc=/etc/systemd/journald.conf
    backup_file "$jc"
    [[ -f $jc ]] || printf '[Journal]\n' >"$jc"
    grep -q '^\[Journal\]' "$jc" || printf '[Journal]\n' >>"$jc"
    local kv
    for kv in Storage=persistent Compress=yes ForwardToSyslog=yes; do
        sed -i -E "/^[#[:space:]]*${kv%%=*}[[:space:]]*=/d" "$jc"
        sed -i "/^\[Journal\]/a ${kv}" "$jc"
    done
    chmod 0644 "$jc"
    write_file 0644 /etc/systemd/journald.conf.d/60-harden.conf <<'EOF'
# Managed by harden-and-audit.sh
[Journal]
SystemMaxUse=512M
SystemKeepFree=1G
MaxFileSec=1month
EOF
    # New log files are 0640: one $FileCreateMode, in rsyslog.conf itself.
    backup_file /etc/rsyslog.conf
    local f
    for f in /etc/rsyslog.d/*.conf; do
        sed -i '/^[[:space:]]*\$FileCreateMode/d' "$f"
    done
    rm -f /etc/rsyslog.d/60-harden.conf
    if grep -qE '^[[:space:]]*\$FileCreateMode' /etc/rsyslog.conf; then
        sed -i -E 's/^[[:space:]]*\$FileCreateMode.*/$FileCreateMode 0640/' /etc/rsyslog.conf
    else
        sed -i '1i $FileCreateMode 0640' /etc/rsyslog.conf
    fi
    # This host never receives remote syslog: disable imtcp/imudp listeners.
    for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf; do
        backup_file "$f"
        sed -i -E \
            -e 's/^([[:space:]]*module\(load="im(tcp|udp)".*)$/# disabled by harden-and-audit: \1/' \
            -e 's/^([[:space:]]*input\(type="im(tcp|udp)".*)$/# disabled by harden-and-audit: \1/' \
            -e 's/^([[:space:]]*\$ModLoad[[:space:]]+im(tcp|udp).*)$/# disabled by harden-and-audit: \1/' \
            -e 's/^([[:space:]]*\$(InputTCPServerRun|UDPServerRun).*)$/# disabled by harden-and-audit: \1/' "$f"
    done
    local rout
    if ! rout=$(rsyslogd -N1 2>&1); then
        # rsyslog >= 8.2312 drops capabilities even when only validating;
        # unprivileged containers refuse that (error 2455), the config is fine.
        if in_container && grep -q -- '-2455' <<<"$rout"; then
            warn "container: rsyslogd cannot drop capabilities here, so its config check cannot run (it does on a real host)"
        else
            printf '%s\n' "$rout" >&2
            die "rsyslog configuration is invalid"
        fi
    fi
    # Rotation: daily, LOG_ROTATE_KEEP generations, compressed, size-capped.
    # Logs are shipped off-host, so local copies are a short buffer only.
    backup_file /etc/logrotate.conf
    sed -i -E 's/^(weekly|monthly)$/daily/' /etc/logrotate.conf
    sed -i -E "s/^rotate [0-9]+$/rotate ${LOG_ROTATE_KEEP}/" /etc/logrotate.conf
    grep -q '^rotate ' /etc/logrotate.conf || sed -i "1i rotate ${LOG_ROTATE_KEEP}" /etc/logrotate.conf
    grep -q '^compress$' /etc/logrotate.conf || sed -i -E 's/^#[[:space:]]*compress$/compress/' /etc/logrotate.conf
    grep -q '^compress$' /etc/logrotate.conf || sed -i '/^create/a compress' /etc/logrotate.conf
    sed -i '/^maxsize /d' /etc/logrotate.conf
    sed -i "/^compress$/a maxsize ${LOG_MAXSIZE}" /etc/logrotate.conf
    # Hourly maxsize rotation can rotate a file twice in one day: with
    # dateext's default -%Y%m%d suffix the second one collides ("destination
    # already exists") and logrotate fails. Hour-stamped suffixes never do.
    sed -i '/^dateformat /d' /etc/logrotate.conf
    sed -i "/^maxsize /a dateformat -%Y%m%d%H" /etc/logrotate.conf
    grep -q '^daily$' /etc/logrotate.conf || sed -i '1i daily' /etc/logrotate.conf
    # This script's own logs.
    write_file 0644 /etc/logrotate.d/harden-and-audit <<'EOF'
# Managed by harden-and-audit.sh
/var/log/harden-and-audit.log /var/log/harden-and-audit-aideinit.log {
    # Ubuntu's /var/log is group-writable (root:syslog 0775): without "su"
    # logrotate refuses the stanza when it is evaluated on its own.
    su root root
    rotate 4
    size 50M
    missingok
    notifempty
    compress
    create 0600 root root
}
EOF
    configure_log_budget
    # Recreated logs must not be world readable either (dpkg/apt ship 0644).
    for f in /etc/logrotate.conf /etc/logrotate.d/*; do
        [[ -f $f ]] || continue
        backup_file "$f"
        sed -i -E 's/^([[:space:]]*create[[:space:]]+)0?6[0-7][0-7]([[:space:]]|$)/\10640\2/' "$f"
    done
    # Validate against a private copy of the state file: the timer started
    # above may be rotating right now and holds the real state file's lock.
    local lstate lout
    lstate=$(mktemp)
    cp -f /var/lib/logrotate/logrotate.status "$lstate" 2>/dev/null || true
    if ! lout=$(logrotate -d -s "$lstate" /etc/logrotate.conf 2>&1); then
        rm -f "$lstate"
        grep -E '^error:' <<<"$lout" >&2 || printf '%s\n' "$lout" | tail -n 20 >&2
        # Only a parse error (it names a config file and line) is fatal;
        # a missing log, an unreadable olddir and the like are not.
        if grep -qE '^error: /etc/logrotate[^:]*:[0-9]+' <<<"$lout"; then
            die "logrotate configuration is invalid"
        fi
        warn "logrotate reported non-configuration errors (above); the configuration itself parses"
    fi
    rm -f "$lstate"
    systemctl enable logrotate.timer rsyslog.service >/dev/null 2>&1 || true
    if is_rhel; then
        # journal-remote is installed for upload/forwarding only: no listener.
        systemctl mask systemd-journal-remote.socket >/dev/null 2>&1 || true
        systemctl enable --now crond.service >/dev/null 2>&1 || true
    else
        systemctl enable --now cron.service >/dev/null 2>&1 || true
    fi
    systemctl restart systemd-journald.service
    # EL10's sandboxed rsyslog.service cannot start inside a container at all
    # (it fails there before any change); on a host a failure stays fatal.
    if ! systemctl restart rsyslog.service; then
        journalctl -u rsyslog.service --no-pager -n 15 >&2 || true
        host_only "restart rsyslog" false
    fi
}

configure_timesync() {
    step "5.13 time synchronisation"
    local s
    if is_rhel; then
        # chronyd: vendor pool unless NTP_SERVERS is set; runs as user chrony.
        install -d -m 0755 /etc/chrony/sources.d
        if [[ -n $NTP_SERVERS ]]; then
            {
                echo "# Managed by ${SCRIPT_NAME}"
                for s in $NTP_SERVERS; do echo "server ${s} iburst"; done
            } | write_file 0644 /etc/chrony/sources.d/60-harden.sources
        else
            log "chrony keeps the distribution time sources (set NTP_SERVERS to use your enclave's servers)"
        fi
        backup_file /etc/chrony.conf
        grep -q '^sourcedir /etc/chrony/sources.d' /etc/chrony.conf || echo 'sourcedir /etc/chrony/sources.d' >>/etc/chrony.conf
        if [[ -f /etc/sysconfig/chronyd ]]; then
            backup_file /etc/sysconfig/chronyd
            if grep -q '^OPTIONS=' /etc/sysconfig/chronyd; then
                grep -Eq '^OPTIONS=.*-u[[:space:]]+chrony' /etc/sysconfig/chronyd \
                    || sed -i -E 's/^OPTIONS="?([^"]*)"?/OPTIONS="\1 -u chrony"/' /etc/sysconfig/chronyd
            else
                echo 'OPTIONS="-u chrony"' >>/etc/sysconfig/chronyd
            fi
        fi
        systemctl enable chronyd.service >/dev/null 2>&1 || true
        systemctl restart chronyd.service >/dev/null 2>&1 || warn "chronyd did not start (no clock control in containers)"
        return 0
    fi
    if pkg_installed chrony; then
        if [[ -n $NTP_SERVERS ]]; then
            {
                echo "# Managed by ${SCRIPT_NAME}"
                for s in $NTP_SERVERS; do echo "server ${s} iburst"; done
            } | write_file 0644 /etc/chrony/sources.d/60-harden.sources
        else
            # Ubuntu: keep the vendor sources (authenticated NTS on 25.10+).
            log "chrony keeps the distribution time sources (set NTP_SERVERS to use your enclave's servers)"
        fi
        grep -q '^sourcedir /etc/chrony/sources.d' /etc/chrony/chrony.conf || echo 'sourcedir /etc/chrony/sources.d' >>/etc/chrony/chrony.conf
        systemctl enable --now chrony.service >/dev/null 2>&1 || true
        systemctl restart chrony.service || true
    else
        # Ubuntu without NTP_SERVERS: the public pool the CIS content lists as
        # approved (var_multiple_time_servers); the fallback list keeps
        # NTP_FALLBACK_SERVERS (time.nist.gov, the 22.04 profile's approved
        # value) first, then Canonical's servers.
        local ntp=$NTP_SERVERS fallback=$NTP_FALLBACK_SERVERS
        if [[ -z $ntp ]]; then
            ntp="0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
            fallback="${NTP_FALLBACK_SERVERS} ntp.ubuntu.com"
        fi
        write_file 0644 /etc/systemd/timesyncd.conf.d/60-harden.conf <<EOF
# Managed by ${SCRIPT_NAME}
[Time]
NTP=${ntp}
FallbackNTP=${fallback}
EOF
        systemctl unmask systemd-timesyncd.service >/dev/null 2>&1 || true
        systemctl enable systemd-timesyncd.service >/dev/null 2>&1 || true
        systemctl restart systemd-timesyncd.service >/dev/null 2>&1 || warn "systemd-timesyncd did not start (no clock control in containers)"
    fi
}

configure_apparmor() {
    step "5.14 mandatory access control: AppArmor / SELinux enforcing"
    if is_rhel; then
        configure_selinux
        return 0
    fi
    systemctl enable apparmor.service >/dev/null 2>&1 || true
    local p
    local -a enforce=() complain=()
    for p in /etc/apparmor.d/*; do
        [[ -f $p ]] || continue
        # Include-only files (Proxmox VE's lxc-containers pulls in the LXC
        # profiles from /etc/apparmor.d/lxc/) define no profile themselves;
        # aa-enforce rejects them ("doesn't contain a valid profile").
        aa_defines_profile "$p" || continue
        # Profiles shipped as "unconfined" are allow-all by design; enforcing
        # them would block their binaries. Leave those alone.
        grep -Eq 'flags=\([^)]*unconfined' "$p" && continue
        # Profiles the distribution ships disabled (Ubuntu) are loaded in
        # complain mode: confined and logged, without risking a service the
        # vendor chose not to enforce.
        if [[ -e /etc/apparmor.d/disable/${p##*/} ]]; then
            complain+=("$p")
        else
            enforce+=("$p")
        fi
    done
    aa_set_mode aa-enforce "${enforce[@]}"
    aa_set_mode aa-complain "${complain[@]}"
    # reload, not restart: profiles of running confined processes (LXC
    # containers, Docker, libvirt) stay loaded while the set is refreshed.
    host_only "load AppArmor profiles" systemctl reload-or-restart apparmor.service
}

# aa_defines_profile FILE - the file declares at least one profile block
# (a "{" outside comments); include-only and variable files do not.
aa_defines_profile() {
    grep -v '^[[:space:]]*#' "$1" | qgrep '{'
}

# aa_set_mode TOOL FILE... - aa-enforce / aa-complain in one batch; if the
# batch fails, file by file, so one vendor profile the parser rejects is
# reported instead of stopping the run (the others are still applied).
aa_set_mode() {
    local tool=$1 f
    shift
    [[ $# -gt 0 ]] || return 0
    if "$tool" "$@" >/dev/null 2>&1; then
        return 0
    fi
    if in_container; then
        warn "container: '${tool}' could not be applied here (it applies on a real host)"
        return 0
    fi
    local -a bad=()
    for f in "$@"; do
        "$tool" "$f" >/dev/null 2>&1 || bad+=("${f##*/}")
    done
    if [[ ${#bad[@]} -gt 0 ]]; then
        warn "AppArmor: ${tool} failed for ${bad[*]} (left in their current mode; check with: apparmor_parser -QT /etc/apparmor.d/<file>)"
    fi
    return 0
}

# RHEL family: SELinux enforcing with the targeted policy. A host that booted
# with SELinux disabled gets permissive + a full relabel first: enforcing an
# unlabelled filesystem can stop services (and SSH) at the next boot. The
# next run, after that reboot, switches it to enforcing.
configure_selinux() {
    local cfg=/etc/selinux/config want=enforcing cur
    pkg_installed selinux-policy-targeted || dnf_install selinux-policy-targeted
    cur=$(getenforce 2>/dev/null || echo Disabled)
    # Kubernetes nodes: kubeadm/k3s/rke2 installs are often set up with SELinux
    # permissive; raising it can stop kubelet, CNI or hostPath workloads at the
    # next boot. Enforcing is kept where it already is, never raised here.
    if is_k8s && [[ $cur != Enforcing ]]; then
        warn "Kubernetes node: SELinux stays ${cur} (raising it can stop kubelet/CNI pods); install container-selinux and the distribution's k8s SELinux policy, then run with KUBERNETES_MODE=0 or setenforce 1 yourself"
        log "SELinux: ${cur} (left unchanged on a Kubernetes node)"
        return 0
    fi
    if [[ $cur == Disabled ]] && ! in_container; then
        want=permissive
        touch /.autorelabel
        warn "SELinux was disabled: set to permissive with a full relabel at next boot; re-run this script after the reboot to enforce it"
    fi
    [[ -f $cfg ]] || printf 'SELINUX=%s\nSELINUXTYPE=targeted\n' "$want" >"$cfg"
    backup_file "$cfg"
    sed -i -E "s/^SELINUX=.*/SELINUX=${want}/; s/^SELINUXTYPE=.*/SELINUXTYPE=targeted/" "$cfg"
    grep -q '^SELINUX=' "$cfg" || echo "SELINUX=${want}" >>"$cfg"
    grep -q '^SELINUXTYPE=' "$cfg" || echo 'SELINUXTYPE=targeted' >>"$cfg"
    if [[ $cur == Permissive && $want == enforcing ]]; then
        host_only "setenforce 1" setenforce 1
    fi
    if in_container; then
        warn "container: SELinux is a host kernel feature; ${cfg} set to ${want}, it applies on a real host"
    fi
    log "SELinux: ${cur} now, ${want} (targeted) configured"
}

# Cluster peers never get banned: Proxmox corosync ring addresses and,
# when given, the Kubernetes trusted networks.
fail2ban_cluster_peers() {
    local -a peers=()
    local f
    for f in /etc/pve/corosync.conf /etc/corosync/corosync.conf; do
        [[ -r $f ]] || continue
        while read -r a; do peers+=("$a"); done < <(awk '$1 ~ /^ring[0-9]+_addr:$/ {print $2}' "$f")
    done
    if is_k8s && [[ -n $K8S_TRUSTED_CIDRS ]]; then
        # shellcheck disable=SC2206
        peers+=($K8S_TRUSTED_CIDRS)
    fi
    [[ ${#peers[@]} -gt 0 ]] && printf ' %s' "$(printf '%s\n' "${peers[@]}" | sort -u | paste -sd' ')"
    return 0
}

configure_fail2ban() {
    step "5.15 fail2ban (SSH brute-force protection)"
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        warn "fail2ban is not installed (RHEL family: it comes from EPEL; EPEL_ENABLE=${EPEL_ENABLE})"
        return 0
    fi
    local ports
    ports=$(IFS=,; echo "${SSH_PORTS[*]}")
    write_file 0644 /etc/fail2ban/jail.d/60-harden.local <<EOF
# Managed by ${SCRIPT_NAME}
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd
ignoreip = 127.0.0.1/8 ::1 ${FAIL2BAN_IGNOREIP}$(fail2ban_cluster_peers)

[sshd]
enabled  = true
port     = ${ports}
mode     = aggressive
EOF
    # Proxmox VE: brute force against the web UI / API (root@pam lives there).
    if is_pve; then
        write_file 0644 /etc/fail2ban/filter.d/harden-proxmox.conf <<'EOF'
# Managed by harden-and-audit.sh - failed Proxmox VE web UI / API logins.
[Definition]
failregex = pvedaemon\[[0-9]+\]: authentication (verification )?failure; rhost=(::ffff:)?<HOST> user=\S+ msg=.*
ignoreregex =
journalmatch = _SYSTEMD_UNIT=pvedaemon.service
EOF
        cat >>/etc/fail2ban/jail.d/60-harden.local <<'EOF'

[proxmox]
enabled  = true
port     = https,http,8006
filter   = harden-proxmox
EOF
    else
        rm -f /etc/fail2ban/filter.d/harden-proxmox.conf
    fi
    fail2ban-client -t >/dev/null || die "fail2ban configuration test failed"
    systemctl enable fail2ban.service >/dev/null 2>&1 || true
    systemctl restart fail2ban.service
}

configure_mta() {
    step "5.16 mail transfer agent: local-only"
    if pkg_installed exim4-config; then
        backup_file /etc/exim4/update-exim4.conf.conf
        sed -i -E "s/^dc_local_interfaces=.*/dc_local_interfaces='127.0.0.1 ; ::1'/" /etc/exim4/update-exim4.conf.conf
        update-exim4.conf && systemctl restart exim4.service || true
    fi
    if pkg_installed postfix; then
        postconf -e 'inet_interfaces = loopback-only'
        systemctl restart postfix.service || true
    fi
    return 0
}

configure_tmux() {
    step "5.17 tmux session lock"
    write_file 0644 /etc/tmux.conf <<EOF
# Managed by ${SCRIPT_NAME} - lock idle tmux sessions (STIG session lock).
set -g lock-command vlock
set -g lock-after-time ${SHELL_TMOUT}
bind X lock-session
EOF
}

# Distribution-specific AIDE locations (set by aide_paths).
AIDE_CONF=/etc/aide/aide.conf
AIDE_DB=/var/lib/aide/aide.db
aide_paths() {
    if is_rhel; then
        AIDE_CONF=/etc/aide.conf
        AIDE_DB=/var/lib/aide/aide.db.gz
    fi
}

# The bulk/volatile excludes, shared by both families.
aide_bulk_excludes() {
    cat <<'EOF'
# Managed by harden-and-audit.sh: bulk / volatile data kept out of AIDE.
# Container, VM and app-image storage (verified by their own digests/signatures)
!/var/lib/(containerd|docker|containers|kubelet|rancher)(/|$)
!/var/lib/libvirt/images(/|$)
!/var/lib/snapd/(snaps|cache)(/|$)
!/var/lib/flatpak/(repo|app|runtime)(/|$)
!/snap/(?!bin(/|$))[^/]+(/|$)
!/usr/share/ollama/\.ollama/models(/|$)
# AI / LLM model stores (hundreds of GB; weights change by design and carry
# their own content hashes). Without this the baseline on a GPU inference node
# reads ~300 GB and runs for days. Covers the usual runtimes and caches:
# vLLM, Ollama, LocalAI, LM Studio, GPT4All, llama.cpp, text-generation-webui,
# TGI, Triton, NVIDIA NIM, KServe, Hugging Face, ModelScope, torch, whisper.
# (Per-user caches under /root and /home are already excluded above/below.)
!/var/lib/(vllm|ollama|localai|lmstudio|gpt4all|llama\.cpp|llamacpp|text-generation-webui|tgi|triton|nim|huggingface|modelscope|open-webui)(/|$)
!/(opt|srv|data|mnt)/(vllm|ollama|localai|lmstudio|gpt4all|llama\.cpp|llamacpp|text-generation-webui|tgi|triton|nim|huggingface|modelscope)(/|$)
!/opt/nim/\.cache(/|$)
!/(models|data/models|mnt/models|srv/models|opt/models|var/lib/models)(/|$)
!/(root|home/[^/]+)/\.(cache/(huggingface|modelscope|torch|whisper|lm-studio|nim)|ollama|lmstudio)(/|$)
# Model weight files wherever they live (never system binaries: no .bin here,
# which would also match firmware).
!/.*\.(safetensors|gguf|ggml|ggjt|ckpt|pth|pt|onnx|tflite|mlmodel|engine)$
# Caches and scratch space
!/var/cache(/|$)
!/var/tmp(/|$)
!/tmp(/|$)
# Home directories hold user data (repositories, toolchains, models, package
# caches, app profiles), not the system: all of it is skipped except where
# something planted would run - the shell/login dotfiles, .gitconfig, .ssh,
# .config/autostart, systemd user units and .local/bin.
!/(root|home/[^/]+)/(?!(\.ssh|\.config|\.local)(/|$)|\.(bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zshenv|zprofile|zlogin|zlogout|login|logout|inputrc|pam_environment|xprofile|xsession|xsessionrc|xinitrc|gitconfig|forward|rhosts|shosts|netrc)$)[^/]+(/|$)
!/(root|home/[^/]+)/\.local/(?!bin(/|$))[^/]+(/|$)
!/(root|home/[^/]+)/\.config/(?!(autostart|systemd)(/|$))[^/]+(/|$)
# Swap files (contents change with every page out)
!/(swap\.img|swapfile)$
EOF
    cat <<'EOF'
# Kubernetes: etcd data, block storage (Longhorn/OpenEBS), pod and container logs
!/var/lib/(etcd|k0s|longhorn|kubelet)(/|$)
!/var/openebs(/|$)
!/var/snap/microk8s/common(/|$)
!/var/log/(pods|containers)(/|$)
!/run/(containerd|k3s|netns)(/|$)
EOF
    if is_pbs; then
        echo "# Proxmox Backup Server: datastores (chunk stores) and NFS-exported paths"
        local dsp
        while read -r dsp; do [[ -n $dsp ]] && printf '!%s(/|$)\n' "$(sed 's/[.[\*^$()+?{|]/\\&/g' <<<"$dsp")"; done < <(
            { awk '/^[[:space:]]*path[[:space:]]/{print $2}' /etc/proxmox-backup/datastore.cfg 2>/dev/null
              grep -shvE '^[[:space:]]*(#|$)' /etc/exports /etc/exports.d/*.exports | awk '{print $1}'; } | sort -u)
        echo '!/var/log/proxmox-backup(/|$)'
    fi
    if is_pve; then
        cat <<'EOF'
# Proxmox VE: guest storage (VM disks, container root filesystems, backups,
# ISOs), cluster database and metrics, and the volatile parts of /etc/pve
# (virtual status files, daily-rotated auth keys, HA state, locks).
!/var/lib/(vz|lxc|ceph|rrdcached|pve-cluster|pve-manager|pve-firewall|qemu-server)(/|$)
!/mnt/pve(/|$)
!/.*/(subvol|basevol)-[0-9]+-disk-[0-9]+(/|$)
!/etc/pve/(.+/)?\.[^/]+$
!/etc/pve/(priv/)?authkey\.(key|pub)(\.old)?$
!/etc/pve/nodes/[^/]+/lrm_status(\.tmp\.[0-9]+)?$
!/etc/pve/priv/lock(/|$)
!/var/log/pve(/|$)
EOF
        local sp
        while read -r sp; do
            printf '!%s(/|$)\n' "$(sed 's/[][\.*^$+?(){}|]/\\&/g' <<<"$sp")"
        done < <(pve_storage_paths)
    fi
    # Any other active swap file, wherever it lives.
    local sw t
    while read -r sw t _; do
        [[ $t == file && $sw == /* ]] || continue
        printf '!%s$\n' "$(sed 's/[][\.*^$+?(){}|]/\\&/g' <<<"$sw")"
    done < <(tail -n +2 /proc/swaps)
}

configure_aide_config() {
    step "5.18 AIDE configuration (database is built at the end)"
    aide_paths
    if is_rhel; then pkg_install aide; else apt_install aide aide-common; fi
    # Protect the audit toolchain (CIS / STIG). Scanners read these lines
    # from aide.conf itself, with exactly this attribute set.
    local aconf=$AIDE_CONF t
    backup_file "$aconf"
    rm -f /etc/aide/aide.conf.d/99_harden_audit_tools
    sed -i -E "/^# ${MARK}: audit tools$/d; \#^(/usr)?/sbin/(auditctl|auditd|ausearch|aureport|autrace|augenrules)[[:space:]]#d" "$aconf"
    {
        echo "# ${MARK}: audit tools"
        local attrs="p+i+n+u+g+s+b+acl+selinux+xattrs+sha512"
        is_rhel && attrs="p+i+n+u+g+s+b+acl+xattrs+sha512"    # the EL/Fedora content's exact set
        for t in auditctl auditd ausearch aureport autrace augenrules; do
            echo "/usr/sbin/${t} ${attrs}"
        done
    } >>"$aconf"
    # The vendor catch-all (99_aide_root: "/ 0 Full") checksums every byte
    # under /, including container layers, VM disks and caches. On a docker/
    # containerd host that is 100+ GB, so the baseline takes hours and the
    # daily check never finishes; the content also churns constantly, so it
    # would only produce noise. Exclude bulk runtime data, not system files.
    if is_rhel; then
        # EL aide.conf has no conf.d: a managed block at the end of the file.
        sed -i "/^# BEGIN ${MARK} bulk excludes$/,/^# END ${MARK} bulk excludes$/d" "$aconf"
        { echo "# BEGIN ${MARK} bulk excludes"; aide_bulk_excludes; echo "# END ${MARK} bulk excludes"; } >>"$aconf"
    else
        # (Name must match aide.conf's x_include filter: [a-zA-Z0-9_-]+.)
        aide_bulk_excludes | write_file 0644 /etc/aide/aide.conf.d/90_harden_bulk_excludes
    fi
    # EL CIS: aide.conf root-only. (Debian/Ubuntu AIDE 0.19 reads it as _aide.)
    is_rhel && chmod 0600 "$aconf"
    aide --config-check --config "$aconf" >/dev/null 2>&1 || die "AIDE configuration check failed"
    # Ubuntu's aide-common ships dailyaidecheck.{service,timer}, which the
    # Ubuntu CIS content checks: use it rather than adding a second check.
    if is_rhel; then
        # EL CIS (aide_periodic_cron_checking) checks /etc/crontab.
        systemctl disable --now aidecheck.timer aidecheck.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/aidecheck.service /etc/systemd/system/aidecheck.timer
        systemctl daemon-reload
        backup_file /etc/crontab
        sed -i '\#/usr/sbin/aide --check#d' /etc/crontab
        echo "05 4 * * * root /usr/sbin/aide --check" >>/etc/crontab
        log "AIDE: daily check from /etc/crontab"
        return 0
    fi
    if is_ubuntu && systemctl cat dailyaidecheck.timer >/dev/null 2>&1; then
        systemctl disable --now aidecheck.timer aidecheck.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/aidecheck.service /etc/systemd/system/aidecheck.timer
        systemctl daemon-reload
        systemctl enable dailyaidecheck.timer >/dev/null 2>&1 || true
        systemctl start dailyaidecheck.timer >/dev/null 2>&1 || true
        log "AIDE: vendor dailyaidecheck.timer enabled"
        return 0
    fi
    write_file 0644 /etc/systemd/system/aidecheck.service <<EOF
# Managed by ${SCRIPT_NAME}
[Unit]
Description=AIDE file integrity check
ConditionPathExists=${AIDE_DB}

[Service]
Type=oneshot
ExecStart=$(command -v aide) --config ${AIDE_CONF} --check
Nice=19
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
EOF
    write_file 0644 /etc/systemd/system/aidecheck.timer <<'EOF'
# Managed by harden-and-audit.sh
[Unit]
Description=Daily AIDE file integrity check

[Timer]
OnCalendar=*-*-* 05:00:00
RandomizedDelaySec=30m
Persistent=true
Unit=aidecheck.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable aidecheck.service aidecheck.timer >/dev/null 2>&1 || true
    systemctl start aidecheck.timer >/dev/null 2>&1 || true
}

# ============================================================================
# 6. Headless NVIDIA CUDA prerequisites, coturn & media libraries
# ============================================================================
provision_cuda_prereqs() {
    step "6.1 CUDA / DKMS build prerequisites (driver itself is not installed)"
    local -a hdrs=()
    if is_rhel; then
        local -a el=(gcc make kernel-devel kernel-headers elfutils-libelf-devel pkgconf-pkg-config)
        pkg_candidate dkms && el+=(dkms)
        dnf_install "${el[@]}"
        pkg_candidate dkms || warn "dkms is not available$(is_fedora || echo " (it comes from EPEL; EPEL_ENABLE=${EPEL_ENABLE})")"
        if pkg_candidate "kernel-devel-$(uname -r)" || dnf -q list --available "kernel-devel-$(uname -r)" >/dev/null 2>&1; then
            dnf_install "kernel-devel-$(uname -r)"
        else
            warn "kernel-devel-$(uname -r) is not available (running kernel differs from the packaged one); DKMS builds target the installed kernel"
        fi
    elif is_ubuntu; then
        # Headers follow each installed kernel flavour metapackage
        # (linux-image-generic, -virtual, -aws, -azure, -gcp, ...).
        local meta flavour
        while read -r meta; do
            flavour=${meta#linux-image-}
            pkg_candidate "linux-headers-${flavour}" && hdrs+=("linux-headers-${flavour}")
        done < <(dpkg-query -W -f='${db:Status-Status} ${Package}\n' 'linux-image-*' 2>/dev/null \
                 | awk '$1=="installed" && $2 !~ /^linux-image-(unsigned-)?[0-9]/ {print $2}')
        [[ ${#hdrs[@]} -gt 0 ]] || hdrs=(linux-headers-generic)
    elif is_pve; then
        # Proxmox VE: headers for the Proxmox kernels. linux-headers-amd64
        # would pull in Debian's stock kernel (linux-image-amd64), whose DKMS
        # builds can fail and leave dpkg broken on GPU/DKMS nodes.
        if pkg_candidate proxmox-default-headers; then
            hdrs=(proxmox-default-headers)
        else
            warn "Proxmox VE: proxmox-default-headers is not available (Proxmox repository missing?); DKMS builds need the Proxmox kernel headers"
        fi
    else
        hdrs=(linux-headers-amd64)
        [[ $DEB_ARCH == arm64 ]] && hdrs=(linux-headers-arm64)
    fi
    if is_deb; then
        apt_install libc6 libc6-dev gcc make build-essential pkg-config dkms "${hdrs[@]}"
        local running
        running="linux-headers-$(uname -r)"
        is_pve && running="proxmox-headers-$(uname -r)"
        if pkg_candidate "$running"; then
            apt_install "$running"
        else
            warn "${running} is not available from the archive (running kernel differs from the packaged one); DKMS builds target the installed kernel"
        fi
    fi
    write_file 0644 /etc/modprobe.d/60-harden-nouveau.conf <<'EOF'
# Managed by harden-and-audit.sh - the proprietary NVIDIA driver needs nouveau off.
blacklist nouveau
options nouveau modeset=0
EOF
    if command -v update-initramfs >/dev/null 2>&1; then
        host_only "update-initramfs" update-initramfs -u -k all
    elif command -v dracut >/dev/null 2>&1; then
        host_only "dracut" dracut --regenerate-all --force
    fi
}

provision_media_coturn_libs() {
    step "6.2 coturn & real-time media runtime libraries (no coturn, no X11)"
    # Each entry lists alternatives across Debian 12/13 sonames; the first
    # available one is installed. A trailing ~REGEX picks the newest soname
    # on releases not listed explicitly (Ubuntu 22.04/24.04/26.04 ...).
    local -a groups=(
        "libevent-core-2.1-7t64 libevent-core-2.1-7"
        "libevent-extra-2.1-7t64 libevent-extra-2.1-7"
        "libevent-openssl-2.1-7t64 libevent-openssl-2.1-7"
        "libevent-pthreads-2.1-7t64 libevent-pthreads-2.1-7"
        "libhiredis1.1.0 libhiredis0.14 ~^libhiredis[0-9.]+$"
        "libmariadb3"
        "libpq5"
        "libsqlite3-0"
        "sqlite3"
        "libssl3t64 libssl3"
        "libsystemd0"
        "libmicrohttpd12t64 libmicrohttpd12 ~^libmicrohttpd[0-9]+(t64)?$"
        "libopus0"
        "libvpx9 libvpx8 libvpx7 ~^libvpx[0-9]+(t64)?$"
        "libsrtp2-1"
        "libx264-164 ~^libx264-[0-9]+$"
        "libx265-215 libx265-199 ~^libx265-[0-9]+$"
        "libaom3"
        "libdav1d7 libdav1d6 ~^libdav1d[0-9]+$"
        "libogg0"
        "libvorbis0a"
        "libvorbisenc2"
        "libspeex1"
        "libspeexdsp1"
        "libwebp7"
        "libtheora0 libtheora0t64 ~^libtheora[0-9]+(t64)?$"
        "libflac14 libflac12t64 libflac12 ~^libflac[0-9]+(t64)?$"
        "libmp3lame0"
        "libsndfile1"
        "libsamplerate0"
        "libsoxr0"
        "libgsm1"
        "libusrsctp2"
        "libjansson4"
        "libconfig11 libconfig9 ~^libconfig[0-9]+$"
        "libwebsockets19t64 libwebsockets17 libwebsockets16 ~^libwebsockets[0-9]+(t64)?$"
        "libcurl4t64 libcurl4"
    )
    if is_rhel; then
        # RPM names (vendor + EPEL). x264/x265 exist only in RPM Fusion,
        # which is third party and not enabled: reported as unavailable.
        groups=(libevent hiredis mariadb-connector-c libpq sqlite-libs sqlite openssl-libs systemd-libs
            libmicrohttpd opus libvpx libsrtp x264-libs x265-libs libaom libdav1d libogg libvorbis speex speexdsp
            libwebp libtheora flac-libs lame-libs libsndfile libsamplerate soxr gsm usrsctp jansson libconfig
            libwebsockets "libcurl libcurl-minimal")
    fi
    local -a pkgs=() missing=() alts
    local g p
    for g in "${groups[@]}"; do
        # read -a splits without pathname expansion: with nullglob, an
        # unquoted "~^libx264-[0-9]+$" would otherwise vanish.
        read -r -a alts <<<"$g"
        if p=$(first_available "${alts[@]}"); then
            pkgs+=("$p")
        else
            missing+=("$g")
        fi
    done
    [[ ${#missing[@]} -gt 0 ]] && warn "media libraries unavailable on this release: ${missing[*]}"
    pkg_install "${pkgs[@]}"
    pkg_mark_manual "${pkgs[@]}"
    if is_deb && pkg_installed libx11-6 && ! apt-get -s purge libx11-6 2>/dev/null | awk '/^Purg /{print $2}' | qgrep -Ev '^(libx11-6|libx11-xcb1)$'; then
        warn "libx11-6 is still installed only because a non-graphical package depends on it"
    fi
    log "installed ${#pkgs[@]} media/coturn runtime libraries"
}

# ============================================================================
# 7. OpenSCAP
# ============================================================================
install_openscap() {
    step "7.1 OpenSCAP tooling"
    if is_rhel; then
        # Vendor content, matched to the platform (ssg-rl9, ssg-almalinux9, ...).
        dnf_install openscap-scanner scap-security-guide unzip
        command -v oscap >/dev/null 2>&1 || die "no OpenSCAP scanner (oscap) could be installed on ${OS_NAME}"
        log "OpenSCAP: $(oscap --version 2>/dev/null | head -n1); content: scap-security-guide $(rpm -q --qf '%{version}' scap-security-guide)"
        return 0
    fi
    local -a pkgs=(unzip) p
    # Debian 12/13, Ubuntu 24.04+: openscap-scanner/-utils (libopenscap25).
    # Ubuntu 22.04: only libopenscap8 (oscap 1.2.17) and no ssg-* packages.
    local -a wanted=(openscap-scanner openscap-utils libopenscap8 ssg-base)
    if is_ubuntu; then
        wanted+=(ssg-debderived)    # the ssg-* binary package with Ubuntu content
    else
        wanted+=(ssg-debian)
    fi
    for p in "${wanted[@]}"; do
        if pkg_candidate "$p"; then
            pkgs+=("$p")
        else
            log "${p} is not packaged for ${OS_NAME}"
        fi
    done
    apt_install "${pkgs[@]}"
    command -v oscap >/dev/null 2>&1 || die "no OpenSCAP scanner (oscap) could be installed on ${OS_NAME}"
    log "OpenSCAP: $(oscap --version 2>/dev/null | head -n1)"
    # Last package change of the run: nothing unneeded is left behind.
    apt_autoremove
}

# find_datastream NAME - pinned upstream SSG (cache, then download), then
# the packaged content. Prints the path or returns 1.
find_datastream() {
    local name=$1
    local cache=${CACHE_DIR}/ssg-${SSG_VERSION}
    if [[ -f ${cache}/${name} ]]; then
        printf '%s\n' "${cache}/${name}"
        return 0
    fi
    if [[ $SSG_DOWNLOAD == 1 && ! -f ${cache}/.unavailable-${name} ]]; then
        install -d -m 0750 "$cache"
        local zip=${CACHE_DIR}/scap-security-guide-${SSG_VERSION}.zip
        set_curl_retry
        if [[ -f $zip ]] && echo "${SSG_SHA512}  ${zip}" | sha512sum -c --status; then
            :
        elif ! { curl -fsSL --proto '=https' --tlsv1.2 --retry 5 "${CURL_RETRY_ALL[@]}" -o "$zip" "$SSG_URL" \
                 && echo "${SSG_SHA512}  ${zip}" | sha512sum -c --status; }; then
            rm -f "$zip"
            echo "SSG ${SSG_VERSION} download or SHA-512 verification failed" >&2
            zip=""
        fi
        if [[ -n $zip ]]; then
            unzip -o -j -q "$zip" "scap-security-guide-${SSG_VERSION}/${name}" -d "$cache" 2>/dev/null \
                || touch "${cache}/.unavailable-${name}"
            if [[ -f ${cache}/${name} ]]; then
                printf '%s\n' "${cache}/${name}"
                return 0
            fi
        fi
    fi
    if [[ -f /usr/share/xml/scap/ssg/content/${name} ]]; then
        printf '%s\n' "/usr/share/xml/scap/ssg/content/${name}"
        return 0
    fi
    return 1
}

ds_has_profile() {
    oscap info --profiles "$1" 2>/dev/null | qgrep "^xccdf_org\.ssgproject\.content_profile_${2}:"
}

# retarget_datastream SRC DST SRC_CODENAME - copy of an older Ubuntu LTS
# datastream whose platform check (DISTRIB_CODENAME in /etc/lsb-release)
# accepts the running release. Used only when no native content exists.
retarget_datastream() {
    local src=$1 dst=$2 from=$3
    # 1. platform: accept this release's codename.
    # 2. audit 4.1 (Ubuntu 26.04) loads rules.d through audit-rules.service
    #    (ExecStart=augenrules --load), which auditd.service only "Wants";
    #    the 24.04 checks recognise augenrules mode only by the audit 3.x
    #    "Requires=augenrules.service" line and would fail every audit rule.
    sed -e 's/\^DISTRIB_CODENAME='"${from}"'\$/^DISTRIB_CODENAME='"${OS_CODENAME}"'$/g' \
        -e 's#|Requires=augenrules.service)<#|Requires=augenrules.service|Wants=audit-rules.service)<#g' \
        "$src" >"${dst}.tmp"
    qgrep -F "^DISTRIB_CODENAME=${OS_CODENAME}\$" "${dst}.tmp" || { rm -f "${dst}.tmp"; return 1; }
    mv -f "${dst}.tmp" "$dst"
}

# resolve_datastream - print the datastream to scan. Native content for this
# release first; on Ubuntu without native content for SCAP_PROFILE (26.04
# with SSG 0.1.82: empty skeleton) the newest older LTS content, retargeted.
resolve_datastream() {
    local name="ssg-${SSG_PRODUCT}-ds.xml" ds=""
    if [[ -n $SSG_DATASTREAM ]]; then
        [[ -f $SSG_DATASTREAM ]] || die "SSG_DATASTREAM=${SSG_DATASTREAM} does not exist"
        printf '%s\n' "$SSG_DATASTREAM"
        return 0
    fi
    if is_rhel; then
        # Vendor-packaged content first (patched for that vendor's packages
        # and platform CPEs); then RHEL content; then the pinned upstream zip.
        local c
        for c in "/usr/share/xml/scap/ssg/content/${name}" "/usr/share/xml/scap/ssg/content/ssg-rhel${OS_MAJOR}-ds.xml"; do
            if [[ -f $c ]] && ds_has_profile "$c" "$SCAP_PROFILE"; then
                printf '%s\n' "$c"
                return 0
            fi
        done
    fi
    ds=$(find_datastream "$name" || true)
    if [[ -n $ds ]] && ds_has_profile "$ds" "$SCAP_PROFILE"; then
        printf '%s\n' "$ds"
        return 0
    fi
    if is_ubuntu && [[ $SSG_CONTENT_FALLBACK == 1 ]]; then
        local lts num code src dst
        for lts in 2404:noble 2204:jammy; do
            num=${lts%%:*}; code=${lts#*:}
            (( num < OS_NUM )) || continue
            src=$(find_datastream "ssg-ubuntu${num}-ds.xml" || true)
            [[ -n $src ]] && ds_has_profile "$src" "$SCAP_PROFILE" || continue
            dst=${CACHE_DIR}/ssg-${SSG_VERSION}/ssg-ubuntu${num}-ds.retarget-${SSG_PRODUCT}.xml
            # Regenerated every time: cheap, and never stale after an update.
            retarget_datastream "$src" "$dst" "$code" || continue
            echo "no native ${SCAP_PROFILE} content for ${OS_NAME} in SSG ${SSG_VERSION}: scanning with the Ubuntu ${num:0:2}.${num:2} content retargeted to ${OS_CODENAME}" >&2
            printf '%s\n' "$dst"
            return 0
        done
    fi
    # Last resort: whatever exists (scap_eval reports a missing profile).
    [[ -n $ds ]] && { printf '%s\n' "$ds"; return 0; }
    return 1
}

# stdbuf -oL: oscap's per-rule lines reach the log as they happen.
scap_eval_quiet() {
    ( umask 077; stdbuf -oL oscap xccdf eval --profile "$1" --results "$2" --report "$3" "$4" </dev/null >"$5" 2>&1 )
}

# scap_rule_count DS PROFILE_ID - rules the profile selects (SSG datastreams
# carry resolved profiles: one <select> per rule). Prints 0 if unknown.
scap_rule_count() {
    awk -v id="$2" '
        !p && /<([A-Za-z0-9.-]+:)?Profile[[:space:]]/ && index($0, "id=\"" id "\"") { p = 1; next }
        p && /<\/([A-Za-z0-9.-]+:)?Profile>/ { exit }
        p && /<([A-Za-z0-9.-]+:)?select[[:space:]]/ && /selected="true"/ && /content_rule_/ { n++ }
        END { print n + 0 }' "$1" 2>/dev/null || echo 0
}

# Progress probe: rules finished / rules selected, time left, last rule.
SCAP_PROGRESS_LOG=""
SCAP_RULE_TOTAL=0
scap_progress() {
    local ndone last out r
    [[ -f $SCAP_PROGRESS_LOG ]] || return 0
    ndone=$(grep -c '^Result' "$SCAP_PROGRESS_LOG" || true)
    last=$({ grep '^Title' "$SCAP_PROGRESS_LOG" || true; } | tail -n1 | sed -E 's/^Title[[:space:]]+//' | cut -c1-60)
    if (( SCAP_RULE_TOTAL > 0 )); then
        out="${ndone}/${SCAP_RULE_TOTAL} rules ($(( ndone * 100 / SCAP_RULE_TOTAL ))%)"
        r=$(eta "$ndone" "$SCAP_RULE_TOTAL")
        out+="${r:+, ${r}}"
    else
        out="${ndone} rules evaluated"
    fi
    printf '%s%s\n' "$out" "${last:+, last: ${last}}"
}

# scap_eval PROFILE RESULTS REPORT DS - returns oscap's exit status (0 or 2 ok)
scap_eval() {
    local profile=$1 results=$2 report=$3 ds=$4 rc=0
    local pid="xccdf_org.ssgproject.content_profile_${profile}"
    ds_has_profile "$ds" "$profile" || die "profile '${profile}' does not exist in ${ds}"
    log "evaluating profile ${profile} (this can take several minutes)"
    # umask 077: report files must not themselves violate /var/log permission
    # rules while the scan is reading /var/log.
    SCAP_PROGRESS_LOG="${results%.xml}.log"
    SCAP_RULE_TOTAL=$(scap_rule_count "$ds" "$pid")
    if (( SCAP_RULE_TOTAL > 0 )); then log "${SCAP_RULE_TOTAL} rules selected by ${profile}; progress every ${PROGRESS_INTERVAL}s"; fi
    run_with_progress "OpenSCAP ${profile}" scap_progress \
        scap_eval_quiet "$pid" "$results" "$report" "$ds" "$SCAP_PROGRESS_LOG" || rc=$?
    # 0 = all passed, 2 = at least one rule failed; anything else is an error.
    if [[ $rc -ne 0 && $rc -ne 2 ]]; then
        tail -n 20 "${results%.xml}.log" >&2 || true
        die "oscap evaluation of ${profile} failed (exit ${rc})"
    fi
    chmod 0600 "$results" "$report" "${results%.xml}.log"
}

# scap_summarize PROFILE RESULTS SUMMARY - prints "pass_rate xccdf_score"
scap_summarize() {
    local profile=$1 results=$2 summary=$3
    local pass fail err unk na nc info score rate
    count() { grep -c "<result>$1</result>" "$results" || true; }
    pass=$(count pass); fail=$(count fail); err=$(count error); unk=$(count unknown)
    na=$(count notapplicable); nc=$(count notchecked); info=$(count informational)
    score=$(sed -n 's/.*<score system="urn:xccdf:scoring:default"[^>]*>\([0-9.]*\)<\/score>.*/\1/p' "$results" | head -n1)
    rate=$(awk -v p="$pass" -v f="$fail" -v e="$err" -v u="$unk" 'BEGIN { t=p+f+e+u; if (t==0) print "0.00"; else printf "%.2f", (p*100)/t }')
    {
        echo "OpenSCAP compliance summary - $(ts)"
        echo "host:           $(hostname -f 2>/dev/null || hostname)"
        echo "os:             ${OS_NAME}${OS_CODENAME:+ (${OS_CODENAME})}"
        echo "profile:        ${profile}"
        echo "datastream:     ${DS_PATH}"
        if [[ $DS_PATH == *.retarget-* ]]; then
            echo "content note:   no native SSG content for ${OS_NAME}; ${DS_PATH##*/ssg-} evaluated (see docs/EXCEPTIONS.md)"
        fi
        echo "pass:           ${pass}"
        echo "fail:           ${fail}"
        echo "error:          ${err}"
        echo "unknown:        ${unk}"
        echo "notapplicable:  ${na}"
        echo "notchecked:     ${nc}"
        echo "informational:  ${info}"
        echo "pass_rate:      ${rate}%   (pass / (pass+fail+error+unknown))"
        echo "xccdf_score:    ${score:-n/a}   (urn:xccdf:scoring:default)"
        echo "threshold:      ${SCAP_MIN_SCORE}%"
        echo
        echo "Failed rules:"
        awk '/<rule-result /{ match($0, /idref="[^"]*"/); id=substr($0, RSTART+7, RLENGTH-8) } /<result>(fail|error|unknown)<\/result>/{ sub(/^xccdf_org\.ssgproject\.content_rule_/, "", id); print "  - " id }' "$results"
    } >"$summary"
    chmod 0640 "$summary"
    printf '%s %s\n' "$rate" "${score:-0}"
}

# Files appear in /var/log throughout the run (and between scans): bring them
# to 0640-or-stricter right before evaluating. wtmp/btmp/lastlog keep their
# utmp-group write access, as CIS allows.
normalize_log_permissions() {
    find /var/log -type f ! -name 'lastlog*' ! -name '[bw]tmp*' ! -name 'history.log*' ! -name 'eipp.log.xz*' \
        -perm /u+xs,g+wxs,o+rwxt -exec chmod u-xs,g-wxs,o-rwxt {} + 2>/dev/null || true
}

DS_PATH=""
run_scap_audit() {
    step "7.2 OpenSCAP evaluation"
    normalize_log_permissions
    DS_PATH=$(resolve_datastream) || die "no SCAP datastream for ${OS_NAME}: set SSG_DATASTREAM or allow SSG_DOWNLOAD"
    rm -f "${CACHE_DIR}"/scap-security-guide-*.zip
    log "datastream: ${DS_PATH}"
    scap_eval "$SCAP_PROFILE" "$SCAP_RESULTS" "$SCAP_REPORT" "$DS_PATH"
    local rate score
    read -r rate score < <(scap_summarize "$SCAP_PROFILE" "$SCAP_RESULTS" "$SCAP_SUMMARY")
    # Content whose platform does not match this host scores every rule
    # "notapplicable" - an empty, meaningless 0% (or 100%) result.
    if ! awk '/^(pass|fail):/ {n += $2} END {exit !(n > 0)}' "$SCAP_SUMMARY"; then
        die "${DS_PATH##*/} has no applicable rules on ${OS_NAME}: the SCAP content does not match this release"
    fi
    local p
    for p in $SCAP_EXTRA_PROFILES; do
        if ! ds_has_profile "$DS_PATH" "$p"; then
            warn "extra profile '${p}' is not in ${DS_PATH##*/} for ${OS_NAME}: skipped"
            continue
        fi
        scap_eval "$p" "/var/log/scap-results-${p}.xml" "/var/log/scap-report-${p}.html" "$DS_PATH"
        scap_summarize "$p" "/var/log/scap-results-${p}.xml" "/var/log/scap-summary-${p}.txt" >/dev/null
        log "extra profile ${p}: $(awk '/^pass_rate/{print $2}' "/var/log/scap-summary-${p}.txt") pass rate"
    done

    step "7.3 compliance result"
    cat "$SCAP_SUMMARY"
    log "XML results: ${SCAP_RESULTS}"
    log "HTML report: ${SCAP_REPORT}"
    if awk -v r="$rate" -v m="$SCAP_MIN_SCORE" 'BEGIN { exit !(r+0 >= m+0) }'; then
        log "PASS: ${SCAP_PROFILE} pass rate ${rate}% >= ${SCAP_MIN_SCORE}% (XCCDF score ${score})"
        return 0
    fi
    if [[ $SCAP_ENFORCE_MIN == 1 ]]; then
        printf '%s [FATAL] %s pass rate %s%% is below the %s%% target\n' "$(ts)" "$SCAP_PROFILE" "$rate" "$SCAP_MIN_SCORE" >&2
        return 3
    fi
    warn "${SCAP_PROFILE} pass rate ${rate}% is below the ${SCAP_MIN_SCORE}% target"
}

install_scap_timer() {
    step "7.4 recurring compliance scan (weekly)"
    local self
    self=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || true)
    if [[ -f $self ]] && head -n 5 "$self" | qgrep 'harden-and-audit.sh'; then
        [[ $self == /usr/local/sbin/harden-and-audit.sh ]] || install -m 0700 -o root -g root "$self" /usr/local/sbin/harden-and-audit.sh
    else
        warn "script was not run from a file; copy it to /usr/local/sbin/harden-and-audit.sh for the weekly scan"
    fi
    write_file 0644 /etc/systemd/system/scap-audit.service <<'EOF'
# Managed by harden-and-audit.sh
[Unit]
Description=OpenSCAP compliance scan (harden-and-audit)
After=network-online.target

[Service]
Type=oneshot
Environment=SCAP_ENFORCE_MIN=0
ExecStart=/usr/local/sbin/harden-and-audit.sh --scan-only
Nice=19
IOSchedulingClass=idle
EOF
    write_file 0644 /etc/systemd/system/scap-audit.timer <<'EOF'
# Managed by harden-and-audit.sh
[Unit]
Description=Weekly OpenSCAP compliance scan

[Timer]
OnCalendar=Sun *-*-* 04:00:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable scap-audit.timer >/dev/null 2>&1 || true
    systemctl start scap-audit.timer >/dev/null 2>&1 || true
}

readonly AIDE_INIT_LOG=/var/log/harden-and-audit-aideinit.log

# stdin from /dev/null: a prompt must fail, never wait invisibly.
aide_init_quiet() {
    # Lowest CPU/IO priority: the baseline still reads every in-scope file.
    if is_rhel; then
        # EL: no aideinit wrapper; the new database is renamed into place.
        ( umask 077; nice -n 19 ionice -c 3 aide --init --config "$AIDE_CONF" </dev/null >"$AIDE_INIT_LOG" 2>&1 \
            && mv -f /var/lib/aide/aide.db.new.gz "$AIDE_DB" )
    else
        ( umask 077; nice -n 19 ionice -c 3 aideinit -y -f </dev/null >"$AIDE_INIT_LOG" 2>&1 )
    fi
}

# Bytes in use on local disk filesystems: the upper bound of what AIDE reads
# (its exclusions make the real amount smaller, so the estimate is cautious).
AIDE_TOTAL_BYTES=0
# Minus the bulk data 90_harden_bulk_excludes keeps out of AIDE (the same
# paths; home directories whole - their watched dotfiles are a few KB). The
# du runs go in parallel under one time box; container storage that cannot
# be measured in time (hundreds of GB of layers) falls back to docker's own
# accounting.
aide_estimate_total() {
    local total skip=0 d b h i tmp cskip=0 cfail=0 ddf
    local -a dirs=(/var/lib/containerd /var/lib/docker /var/lib/containers /var/lib/kubelet /var/lib/rancher
                   /var/lib/libvirt/images /var/lib/snapd/snaps /var/lib/snapd/cache
                   /var/lib/flatpak/repo /var/lib/flatpak/app /var/lib/flatpak/runtime
                   /usr/share/ollama/.ollama/models /var/cache /var/tmp /tmp /swap.img /swapfile
                   /var/lib/etcd /var/lib/k0s /var/lib/longhorn /var/openebs /var/snap/microk8s/common /var/log/pods)
    if is_pve; then
        dirs+=(/var/lib/vz /var/lib/lxc /var/lib/ceph /var/lib/rrdcached /mnt/pve)
        while read -r d; do dirs+=("$d"); done < <(pve_storage_paths)
    fi
    # Separately mounted container / guest storage is left out of the total.
    total=$(df -l -B1 --output=used,target -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null \
        | awk -v c="$CONTAINER_PATH_RE" -v g="$( is_pve && echo "$PVE_GUEST_PATH_RE")" \
            'NR > 1 && $2 !~ c && (g == "" || $2 !~ g) { s += $1 } END { printf "%d\n", s }')
    for h in /root /home/*; do [[ -d $h ]] && dirs+=("$h"); done
    while read -r d b _; do
        [[ $b == file && $d == /* && $d != /swap.img && $d != /swapfile && $d != /root/* && $d != /home/* ]] && dirs+=("$d")
    done < <(tail -n +2 /proc/swaps 2>/dev/null)
    tmp=$(mktemp -d) || { printf '%d\n' "$total"; return; }
    for i in "${!dirs[@]}"; do
        [[ -e ${dirs[i]} ]] || continue
        { timeout 180 du -sxb "${dirs[i]}" 2>/dev/null | cut -f1 >"$tmp/$i"; } &
    done
    wait
    for i in "${!dirs[@]}"; do
        [[ -e ${dirs[i]} ]] || continue
        b=$(<"$tmp/$i") 2>/dev/null; b=${b:-0}
        case ${dirs[i]} in
            /var/lib/containerd|/var/lib/docker) cskip=$(( cskip + b )); (( b > 0 )) || cfail=1 ;;
            *) skip=$(( skip + b )) ;;
        esac
    done
    rm -rf "$tmp"
    if (( cfail )) && command -v docker >/dev/null 2>&1; then
        ddf=$(timeout 30 docker system df --format '{{.Size}}' 2>/dev/null \
            | sed -E 's/B$//; s/([0-9.]+)([kKMGTP]?)/\1\U\2/' | numfmt --from=si 2>/dev/null \
            | awk '{ s += $1 } END { printf "%d\n", s }')
        (( ${ddf:-0} > cskip )) && cskip=$ddf
    fi
    skip=$(( skip + cskip ))
    (( total > skip )) && total=$(( total - skip ))
    printf '%d\n' "$total"
}

# Progress probe: share of AIDE_TOTAL_BYTES that aide has read so far (all
# aide processes, from /proc/PID/io), time left, and the file now open.
aide_progress() {
    local apid f rd=0 r pct cur="" out apids
    apids=$(pgrep -x aide) || return 0    # finished (closing line) or not started
    for apid in $apids; do
        r=$(awk '/^rchar:/ { print $2 }' /proc/"$apid"/io 2>/dev/null) || r=0
        rd=$(( rd + ${r:-0} ))
        [[ -n $cur ]] && continue
        for f in /proc/"$apid"/fd/*; do
            f=$(readlink "$f") || continue
            case $f in
                /dev/*|/proc/*|pipe:*|socket:*|anon_inode:*|/var/lib/aide/*|/etc/aide/*|/etc/aide.conf|/var/log/*) ;;
                /*) cur=$f; break ;;
            esac
        done
    done
    if (( AIDE_TOTAL_BYTES > 0 && rd > 0 )); then
        pct=$(( rd * 100 / AIDE_TOTAL_BYTES ))
        (( pct <= 99 )) || pct=99
        out="~${pct}% ($(numfmt --to=iec "$rd") of ~$(numfmt --to=iec "$AIDE_TOTAL_BYTES") read)"
        r=$(eta "$rd" "$AIDE_TOTAL_BYTES")
        out+="${r:+, ${r}}"
    elif (( rd == 0 )); then
        out="starting"
    fi
    out+="${cur:+, reading ${cur}}"
    printf '%s\n' "${out#, }"
}

build_aide_database() {
    step "AIDE baseline database (final state)"
    aide_paths
    if [[ $AIDE_INIT != 1 ]]; then
        warn "AIDE_INIT=0: AIDE database not built - run '$(is_rhel && echo "aide --init" || echo "aideinit -y -f")' later"
        return 0
    fi
    if [[ -f $AIDE_DB ]]; then
        log "updating existing AIDE database"
    fi
    AIDE_TOTAL_BYTES=$(aide_estimate_total || echo 0)
    log "AIDE reads and checksums every file on the system (up to ~$(numfmt --to=iec "${AIDE_TOTAL_BYTES:-0}") here): this usually takes 5-30 minutes"
    log "progress is reported every ${PROGRESS_INTERVAL}s; percentage and time left are estimates"
    log "AIDE output: ${AIDE_INIT_LOG}"
    # AIDE >= 0.19 drops to the _aide user via capsh, which needs
    # CAP_SETPCAP/CAP_DAC_READ_SEARCH (absent in unprivileged containers).
    if ! run_with_progress "AIDE baseline" aide_progress aide_init_quiet; then
        tail -n 20 "$AIDE_INIT_LOG" >&2 || true
        in_container || die "aideinit failed (full output: ${AIDE_INIT_LOG})"
        warn "container: 'aideinit' could not be applied here (it applies on a real host)"
    fi
    if [[ -f $AIDE_DB ]]; then
        chmod 0600 /var/lib/aide/aide.db*
    elif ! in_container; then
        die "AIDE database was not created"
    fi
}

# ============================================================================
# Main
# ============================================================================
main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --scan-only) SCAN_ONLY=1 ;;
            --version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION}"; exit 0 ;;
            -h|--help) usage; exit 0 ;;
            *) usage >&2; exit 64 ;;
        esac
        shift
    done

    [[ $PROGRESS_INTERVAL =~ ^[1-9][0-9]*$ ]] || { echo "PROGRESS_INTERVAL must be a positive number of seconds" >&2; exit 64; }
    preflight_root
    install -d -m 0700 -o root -g root "$BACKUP_DIR"
    touch "$LOG_FILE"
    chmod 0600 "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
    log "${SCRIPT_NAME} ${SCRIPT_VERSION} starting (scan-only=${SCAN_ONLY})"
    preflight_os

    if [[ $SCAN_ONLY == 1 ]]; then
        local src=0
        run_scap_audit || src=$?
        exit "$src"
    fi

    # Full run: every step header in this file, minus the two repository
    # steps of the other distributions (Debian / Ubuntu / EL: one runs), plus
    # purge_graphical and harden_file_permissions running twice.
    # tests/assertions.sh checks that the final step number equals this total.
    STEP_TOTAL=$(( $(grep -c '^[[:space:]]*step "' "${BASH_SOURCE[0]}") - 2 + 2 ))

    preflight_admin
    detect_ssh_ports
    preflight_ipv6

    configure_apt_minimal
    configure_repositories
    purge_graphical
    purge_insecure_services
    install_base_stack
    configure_unattended_upgrades

    configure_auditd

    install_fips_provider
    configure_openssl_fips
    configure_grub

    harden_file_permissions
    configure_sysctl
    configure_sshd
    configure_ufw
    configure_pam
    configure_login_defs
    configure_sudo
    configure_banners
    configure_gnome_desktop
    configure_kernel_modules
    configure_mounts
    configure_coredumps
    configure_logging
    configure_timesync
    configure_apparmor
    configure_fail2ban
    configure_mta
    configure_tmux
    configure_aide_config

    provision_cuda_prereqs
    provision_media_coturn_libs
    purge_graphical

    install_openscap
    install_scap_timer
    # re-run permission hardening: packages installed above add files
    harden_file_permissions
    # Audit rules last: setuid/setgid discovery must see every installed
    # package, and -e 2 freezes the rule set until reboot.
    configure_audit_rules
    build_aide_database

    local rc=0
    run_scap_audit || rc=$?

    step "done"
    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        log "warnings raised during the run:"
        local w
        for w in "${WARNINGS[@]}"; do printf '  - %s\n' "$w"; done
    fi
    log "A reboot is required to activate $(kernel_fips_ok && echo 'fips=1, ')audit=1$(is_rhel && echo ', SELinux enforcing') and the other kernel arguments."
    exit "$rc"
}

# Not "main || rc=$?": a function called on the left of || runs with errexit
# and the ERR trap disabled for everything inside it, which silently skipped
# failed commands. main exits with the gate's status itself.
main "$@"
