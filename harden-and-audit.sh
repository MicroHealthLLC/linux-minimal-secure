#!/usr/bin/env bash
# =============================================================================
# harden-and-audit.sh
#
# Transforms a stock Debian 12 (bookworm) / 13 (trixie) or Ubuntu 22.04
# (jammy) / 24.04 (noble) / 26.04 (resolute) installation into a minimal,
# FIPS-ready, SCAP/CIS-Level-2-hardened headless server, then audits itself
# with OpenSCAP and writes XML + HTML compliance reports.
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
# Docs:    README.md, docs/EXCEPTIONS.md, docs/PLAN-UBUNTU.md
# =============================================================================
set -Eeuo pipefail
shopt -s nullglob

readonly SCRIPT_VERSION="1.1.0"
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
: "${ACCOUNT_INACTIVE_DAYS:=45}"
: "${SHELL_TMOUT:=900}"
: "${SSH_LOGLEVEL:=INFO}"            # INFO satisfies CIS/SSG; VERBOSE also logs key fingerprints
: "${FAILLOCK_DENY:=4}"
: "${FAILLOCK_UNLOCK_TIME:=900}"
: "${ALLOW_CONTAINERS:=0}"           # 1 keeps overlayfs + IPv4 forwarding for Docker/Podman hosts
: "${KEEP_IPV6_RA:=auto}"            # auto|0|1 - keep IPv6 router advertisements (SLAAC)
: "${UFW_OUTBOUND_POLICY:=allow}"    # allow|deny (deny adds an explicit egress allow-list)
: "${UFW_EXTRA_OUT:=}"               # extra egress rules for deny mode, e.g. "514/tcp 636/tcp"
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
: "${PROGRESS_INTERVAL:=60}"         # seconds between progress lines during long steps (AIDE, OpenSCAP)
: "${SSG_VERSION:=0.1.82}"
: "${SSG_SHA512:=1caea418f0a5aaef7025e1655ca45a80942ea87ee832b943644ba6f9991b14a6ac5b35dddcd04b754e1fc8fbdee7b7f394507d24b123e821cca0354dc4e03cfd}"
: "${SSG_URL:=https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip}"
: "${SSG_DOWNLOAD:=1}"               # 0 = offline; use SSG_DATASTREAM or packaged content
: "${SSG_DATASTREAM:=}"              # explicit path to an ssg-debianNN-ds.xml
: "${SCAP_PROFILE:=cis_level2_server}"
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
OS_ID=""            # debian | ubuntu
OS_VERSION=""       # 12, 13, 22.04, 24.04, 26.04 ...
OS_CODENAME=""
OS_MAJOR=""         # Debian 12/13; Ubuntu 22/24/26
OS_NUM=0            # comparable number: Debian 12 -> 12, Ubuntu 24.04 -> 2404
OS_NAME=""          # "Debian 12", "Ubuntu 24.04"
SSG_PRODUCT=""      # debian12, ubuntu2404 ...
DEB_ARCH=""
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

  (no option)   Harden this Debian 12/13 or Ubuntu 22.04/24.04/26.04 host,
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
    if [[ -e $f && ! -e $dest ]]; then
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

pkg_installed() { [[ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null || true)" == installed ]]; }

pkg_candidate() {
    local c
    c=$(apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')
    [[ -n $c && $c != "(none)" ]]
}

# first_available PKG... - print the first package that has an apt candidate.
# An entry "~REGEX" matches package names instead; the newest name (version
# sort) with a candidate wins - this tracks soname bumps across releases.
first_available() {
    local p m
    for p in "$@"; do
        if [[ $p == "~"* ]]; then
            while read -r m; do
                if pkg_candidate "$m"; then
                    printf '%s\n' "$m"
                    return 0
                fi
            done < <(apt-cache pkgnames 2>/dev/null | grep -E "${p#\~}" | sort -rV || true)
        elif pkg_candidate "$p"; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    return 1
}

apt_install() {
    apt-get install -y -q --no-install-recommends \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
}

apt_update() {
    apt-get update -q -o Acquire::Retries=5
}

# Purge PACKAGES only when apt would not remove anything outside the given
# set (dependency-aware - protects packages that merely link to X11 libs).
safe_purge() {
    local -a wanted=("$@") keep=() removed=()
    local pkg
    [[ ${#wanted[@]} -eq 0 ]] && return 0
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
        apt-get purge -y -q "${keep[@]}"
    fi
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
    [[ -n $OS_CODENAME ]] || die "cannot determine the ${OS_ID} codename"
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
            die "unsupported distribution '${OS_ID}' (Debian 12/13 or Ubuntu 22.04/24.04/26.04 required)"
            ;;
    esac
    DEB_ARCH=$(dpkg --print-architecture)
    UID_MIN_VALUE=$(awk '/^[[:space:]]*UID_MIN[[:space:]]/{print $2}' /etc/login.defs 2>/dev/null || true)
    UID_MIN_VALUE=${UID_MIN_VALUE:-1000}
    log "${OS_NAME} (${OS_CODENAME}) ${DEB_ARCH}; container=$(in_container && echo yes || echo no)"
}

# Interactive accounts that may log in (UID >= UID_MIN, real shell, not locked).
interactive_users() {
    awk -F: -v min="$UID_MIN_VALUE" '$3 >= min && $3 != 65534 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd
}

preflight_admin() {
    step "preflight: anti-lockout administrator check"
    if [[ $HARDEN_SKIP_ADMIN_CHECK == 1 ]]; then
        warn "HARDEN_SKIP_ADMIN_CHECK=1: root SSH login will be disabled without verifying another administrator exists"
        return 0
    fi
    local u home hash ok=0
    local -a members
    IFS=',' read -r -a members <<<"$(getent group sudo | cut -d: -f4)"
    for u in "${members[@]}"; do
        [[ -z $u ]] && continue
        id "$u" >/dev/null 2>&1 || continue
        [[ $(id -u "$u") -ge $UID_MIN_VALUE ]] || continue
        home=$(getent passwd "$u" | cut -d: -f6)
        hash=$(getent shadow "$u" | cut -d: -f2)
        if [[ -s ${home}/.ssh/authorized_keys || $hash == \$* ]]; then
            log "administrator '${u}' (sudo group, has $( [[ -s ${home}/.ssh/authorized_keys ]] && echo 'SSH key' || echo 'password')) will retain access"
            ok=1
        fi
    done
    if [[ $ok -ne 1 ]]; then
        die "no non-root member of group 'sudo' with an SSH key or password exists. Root SSH login is about to be disabled, which would lock you out. Create one first, e.g.: adduser admin && usermod -aG sudo admin"
    fi
    if [[ $SSH_DISABLE_PASSWORD == 1 ]]; then
        for u in "${members[@]}"; do
            [[ -z $u ]] && continue
            home=$(getent passwd "$u" | cut -d: -f6)
            [[ -s ${home}/.ssh/authorized_keys ]] || die "SSH_DISABLE_PASSWORD=1 but sudo user '${u}' has no authorized_keys"
        done
    fi
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
    step "1.1 apt: never install recommends/suggests"
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

purge_graphical() {
    step "1.2 purge graphical stack (display managers, desktops, X11, Wayland, Mesa)"
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
    local -a candidates
    mapfile -t candidates < <(dpkg-query -W -f='${db:Status-Status} ${Package}\n' 2>/dev/null | awk '$1=="installed"{print $2}' | grep -E "$re" || true)
    if [[ ${#candidates[@]} -eq 0 ]]; then
        log "no graphical packages installed"
    else
        log "graphical candidates: ${candidates[*]}"
        safe_purge "${candidates[@]}"
    fi
    apt-get autoremove --purge -y -q
    local -a residual
    mapfile -t residual < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1=="rc"{print $2}')
    if [[ ${#residual[@]} -gt 0 ]]; then
        dpkg --purge "${residual[@]}" >/dev/null
    fi
    systemctl set-default multi-user.target >/dev/null
}

purge_insecure_services() {
    step "1.3 remove legacy / insecure network services"
    local -a legacy=(telnet telnetd inetutils-telnet inetutils-telnetd rsh-client rsh-server rsh-redone-client
        rsh-redone-server talk talkd inetutils-talk inetutils-talkd tftp tftp-hpa tftpd tftpd-hpa atftpd
        xinetd openbsd-inetd inetutils-inetd nis ypserv ypbind yp-tools ftp tnftp inetutils-ftp inetutils-ftpd vsftpd
        avahi-daemon avahi-autoipd cups cups-daemon cups-browsed rpcbind nfs-kernel-server isc-dhcp-server
        kea-dhcp4-server kea-dhcp6-server snmpd squid slapd ldap-utils autofs bluez dnsmasq)
    local -a present=() p
    for p in "${legacy[@]}"; do
        pkg_installed "$p" && present+=("$p")
    done
    if [[ ${#present[@]} -gt 0 ]]; then
        safe_purge "${present[@]}"
    else
        log "no legacy network services installed"
    fi
    # rsync is a common admin tool: keep the client but never run the daemon.
    disable_service rsync.service bluetooth.service avahi-daemon.service avahi-daemon.socket cups.service \
        cups.socket rpcbind.service rpcbind.socket nfs-server.service snmpd.service
    # STIG: no Ctrl-Alt-Del reboot, no debug shell.
    systemctl mask ctrl-alt-del.target debug-shell.service >/dev/null 2>&1 || true
    if is_ubuntu; then
        purge_ubuntu_telemetry
    fi
    local srv
    for srv in apache2 nginx bind9 samba dovecot-core squid vsftpd slapd; do
        if pkg_installed "$srv"; then
            warn "application server '${srv}' is installed and was left in place; CIS expects it removed if not required"
        fi
    done
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
    step "2.1 official Debian repositories (stable, -updates, -security)"
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

install_base_stack() {
    step "2.2 install the hardened base server stack"
    local -a pkgs=(openssh-server openssh-client tmux curl git ufw iptables fail2ban python3-systemd
        libpam-pwquality libpam-modules libpam-runtime auditd audispd-plugins unattended-upgrades
        sudo rsyslog rsyslog-gnutls logrotate cron acl vlock apparmor apparmor-utils unzip perl
        procps iproute2 kmod e2fsprogs)
    local opt
    opt=$(first_available libpam-apparmor) && pkgs+=("$opt")
    if pkg_installed chrony; then
        log "chrony is installed - it stays the time synchronisation service"
    else
        pkgs+=(systemd-timesyncd)
    fi
    apt_install "${pkgs[@]}"
    log "installing pending security updates"
    apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade
}

configure_unattended_upgrades() {
    step "2.3 unattended security upgrades (daily, mandatory)"
    # Owner policy: automatic distro security updates are NOT optional. There
    # is deliberately no opt-out variable, and the run fails on a real host if
    # they are not effectively enabled (masked timers, overriding apt.conf.d).
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
        origins='#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
        "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu";
        "origin=UbuntuESMApps,archive=${distro_codename}-apps-security";
        "origin=UbuntuESM,archive=${distro_codename}-infra-security";
};'
        check='Unattended-Upgrade::Origins-Pattern:: "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu"'
    else
        origins='#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
};'
        check='Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security,label=Debian-Security"'
    fi
    {
        echo "// Managed by ${SCRIPT_NAME} - apply official ${OS_ID^} security updates daily."
        printf '%s\n' "$origins"
        cat <<'EOF'
#clear Unattended-Upgrade::Package-Blacklist;
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
## the owner's no-halt policy.
-D
-b 8192
--backlog_wait_time 60000
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
-w /etc/network/ -p wa -k system-locale
-w /etc/NetworkManager -p wa -k system-locale

## --- Mandatory access control (AppArmor)
-w /etc/apparmor -p wa -k MAC-policy
-w /etc/apparmor.d -p wa -k MAC-policy

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
    # Ubuntu CIS also audits extended-attribute changes made as root (auid=0).
    if is_ubuntu; then
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
    mapfile -t mounts < <(findmnt -rn -o TARGET,FSTYPE | awk '$2 ~ /^(ext[234]|xfs|btrfs|overlay|zfs|f2fs|jfs|reiserfs)$/ {print $1}' | sort -u)
    [[ ${#mounts[@]} -eq 0 ]] && mounts=(/)
    mapfile -t files < <(for m in "${mounts[@]}"; do find "$m" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null || true; done | sort -u)
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
    else
        augenrules --load
    fi
    if systemctl is-active --quiet auditd; then
        # auditd refuses manual stop (RefuseManualStop); SIGHUP reloads its config.
        systemctl kill -s HUP auditd.service
    else
        systemctl start auditd.service
    fi
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
    step "4.1 kernel command line: fips=1, audit, AppArmor, memory hardening"
    if [[ ! -f /etc/default/grub ]]; then
        warn "GRUB is not installed (/etc/default/grub missing): kernel arguments (fips=1, audit=1, ...) must be set in this host's bootloader manually"
        return 0
    fi
    backup_file /etc/default/grub
    # GRUB_CMDLINE_LINUX applies to every boot entry, including recovery;
    # fips=1 is also put in the default (non-recovery) string, as required.
    local -a kargs=(fips=1 audit=1 audit_backlog_limit=8192 apparmor=1 security=apparmor
        slab_nomerge=yes pti=on page_alloc.shuffle=1 vsyscall=none init_on_alloc=1
        spectre_v2=on spec_store_bypass_disable=seccomp rng_core.default_quality=500)
    grub_set_args GRUB_CMDLINE_LINUX_DEFAULT fips=1
    grub_set_args GRUB_CMDLINE_LINUX "${kargs[@]}"
    grep -E '^GRUB_CMDLINE_LINUX=' /etc/default/grub | qgrep 'fips=1' || die "fips=1 was not written to GRUB_CMDLINE_LINUX"
    grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | qgrep 'fips=1' || die "fips=1 was not written to GRUB_CMDLINE_LINUX_DEFAULT"
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
                    lines+=("${var}=\"\${${var}} fips=1\"")
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
    local cfg
    for cfg in /boot/grub/grub.cfg /boot/grub/user.cfg /boot/efi/EFI/debian/grub.cfg /boot/efi/EFI/ubuntu/grub.cfg; do
        if [[ -f $cfg ]]; then
            chown root:root "$cfg"
            chmod 0400 "$cfg"
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
    step "4.2 build & install the validated OpenSSL ${FIPS_OPENSSL_VERSION} FIPS provider"
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
        curl -fsSL --proto '=https' --tlsv1.2 --retry 5 -o "$tarball" "$FIPS_OPENSSL_URL"
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
    step "4.3 OpenSSL: activate the FIPS provider alongside the default provider"
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
    awk -v block="$block" -v mark="$MARK" '
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
    chown root:shadow /etc/shadow /etc/gshadow
    chmod 0640 /etc/shadow /etc/gshadow
    local f
    for f in /etc/passwd- /etc/group-; do
        [[ -f $f ]] && { chown root:root "$f"; chmod 0644 "$f"; }
    done
    # Backup copies of the password databases: nobody needs to read them.
    [[ -f /etc/shadow- ]] && { chown root:shadow /etc/shadow-; chmod 0000 /etc/shadow-; }
    # CIS Debian 12 and Ubuntu expect group shadow here, CIS Debian 13 root.
    if [[ -f /etc/gshadow- ]]; then
        if is_debian && (( OS_MAJOR >= 13 )); then chown root:root /etc/gshadow-; else chown root:shadow /etc/gshadow-; fi
        chmod 0000 /etc/gshadow-
    fi
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
    for f in /var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/messages /var/log/user.log /var/log/cron.log; do
        [[ -f $f ]] && chgrp adm "$f"
    done
    for f in /var/log/wtmp /var/log/btmp /var/log/lastlog; do
        [[ -f $f ]] && chgrp utmp "$f"
    done

    # World-writable regular files on local filesystems lose o+w.
    local m
    while read -r m; do
        find "$m" -xdev -type f -perm -0002 -exec chmod o-w {} + 2>/dev/null || true
        find "$m" -xdev -type d -perm -0002 ! -perm -1000 -exec chmod +t {} + 2>/dev/null || true
    done < <(findmnt -rn -o TARGET,FSTYPE | awk '$2 ~ /^(ext[234]|xfs|btrfs|overlay|zfs|f2fs)$/ {print $1}')

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
    write_file 0644 /etc/sysctl.d/60-harden.conf <<EOF
# Managed by ${SCRIPT_NAME} - CIS Debian L2 / ANSSI BP-028 / DISA STIG aligned.

# --- IPv4: no routing, no redirects, no source routing, spoofing protection
net.ipv4.ip_forward = ${fwd}
net.ipv4.conf.all.forwarding = ${fwd}
net.ipv4.conf.default.forwarding = ${fwd}
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
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_local = 0
net.ipv4.conf.all.route_localnet = 0
net.ipv4.conf.all.shared_media = 0
net.ipv4.conf.default.shared_media = 0
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.all.arp_ignore = 2
net.ipv4.conf.all.drop_gratuitous_arp = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ip_local_port_range = 32768 65535

# --- IPv6: no routing, no redirects, no source routing, no router advertisements
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
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
net.ipv6.conf.all.max_addresses = 1
net.ipv6.conf.default.max_addresses = 1

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
        sed -E 's/^(-?net\.ipv4\.conf\.[a-z*]+\.rp_filter[[:space:]]*=[[:space:]]*).*/\11/' /usr/lib/sysctl.d/50-default.conf \
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
    local pwauth="# PasswordAuthentication: unchanged (set SSH_DISABLE_PASSWORD=1 for key-only)"
    [[ $SSH_DISABLE_PASSWORD == 1 ]] && pwauth="PasswordAuthentication no"
    local block
    block=$(cat <<EOF
# BEGIN ${MARK} managed block - first match wins in sshd, keep this at the top
LogLevel ${SSH_LOGLEVEL}
PermitRootLogin no
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
ClientAliveCountMax 3
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
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
RekeyLimit 1G 1h
# END ${MARK} managed block
EOF
)
    local keys
    keys=$(sed -n '/^# BEGIN/,/^# END/p' <<<"$block" | awk '!/^#/ && NF {print $1}' | sort -u | paste -sd'|')
    local tmp
    tmp=$(mktemp "${cfg}.XXXXXX")
    {
        printf '%s\n\n' "$block"
        # Drop the previous managed block; comment out managed keys elsewhere.
        sed "/^# BEGIN ${MARK} managed block/,/^# END ${MARK} managed block/d" "$cfg" \
            | sed -E "s/^([[:space:]]*(${keys})[[:space:]].*)/# overridden by ${MARK}: \1/I"
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
    for f in /etc/ssh/ssh_host_*_key; do chown root:root "$f"; chmod 0600 "$f"; done
    for f in /etc/ssh/ssh_host_*_key.pub; do chown root:root "$f"; chmod 0644 "$f"; done
    systemctl enable ssh.service >/dev/null 2>&1 || true
    if systemctl is-active --quiet ssh.service; then
        systemctl reload ssh.service
    else
        # Socket activation (Ubuntu 22.10+): ssh.socket holds the listener and
        # hands it to ssh.service, which then reads the new configuration.
        systemctl start ssh.service
    fi
    log "sshd reloaded (existing sessions are not interrupted)"
}

configure_ufw() {
    step "5.4 UFW host firewall (default deny inbound)"
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
    ufw allow in on lo >/dev/null
    ufw allow out on lo >/dev/null
    ufw deny in from 127.0.0.0/8 >/dev/null
    ufw deny in from ::1 >/dev/null
    if [[ $UFW_OUTBOUND_POLICY == deny ]]; then
        local r
        for r in 53/udp 53/tcp 67/udp 547/udp 123/udp 80/tcp 443/tcp $UFW_EXTRA_OUT; do
            ufw allow out "$r" comment 'egress allow-list (harden-and-audit)' >/dev/null
        done
        ufw default deny outgoing >/dev/null
    else
        ufw default allow outgoing >/dev/null
    fi
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
    write_file 0644 /etc/security/faillock.conf <<EOF
# Managed by ${SCRIPT_NAME} - temporary lockout (auto-unlocks; never permanent).
dir = /var/run/faillock
audit
silent
deny = ${FAILLOCK_DENY}
fail_interval = 900
unlock_time = ${FAILLOCK_UNLOCK_TIME}
even_deny_root
root_unlock_time = ${FAILLOCK_UNLOCK_TIME}
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

    # su is restricted to members of the (empty) sugroup: admins use sudo.
    getent group sugroup >/dev/null || groupadd -r sugroup
    backup_file /etc/pam.d/su
    if ! grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*group=sugroup' /etc/pam.d/su; then
        sed -i -E '/^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so/d' /etc/pam.d/su
        sed -i '0,/^# auth       required   pam_wheel.so$/s//# auth       required   pam_wheel.so\nauth       required   pam_wheel.so use_uid group=sugroup/' /etc/pam.d/su
        grep -q 'group=sugroup' /etc/pam.d/su || printf 'auth       required   pam_wheel.so use_uid group=sugroup\n' >>/etc/pam.d/su
    fi
    # shadow group must have no members (CIS)
    if [[ -n $(getent group shadow | cut -d: -f4) ]]; then
        gpasswd -M '' shadow >/dev/null
    fi
}

configure_login_defs() {
    step "5.6 password aging, umask, account inactivity"
    local f=/etc/login.defs
    set_kv "$f" PASS_MAX_DAYS "$PASS_MAX_DAYS" $'\t'
    set_kv "$f" PASS_MIN_DAYS "$PASS_MIN_DAYS" $'\t'
    set_kv "$f" PASS_WARN_AGE "$PASS_WARN_AGE" $'\t'
    set_kv "$f" UMASK 027 $'\t\t'
    set_kv "$f" ENCRYPT_METHOD YESCRYPT ' '
    set_kv "$f" LOGIN_RETRIES 3 $'\t\t'
    set_kv "$f" LOGIN_TIMEOUT 60 $'\t\t'
    set_kv "$f" HOME_MODE 0750 $'\t\t'
    useradd -D -f "$ACCOUNT_INACTIVE_DAYS"
    # Apply aging to existing accounts that have a usable password - except
    # where that would expire the password immediately (lockout risk).
    local today u hash lastchg
    today=$(( $(date +%s) / 86400 ))
    while IFS=: read -r u hash lastchg _; do
        [[ $hash == \$* ]] || continue
        if [[ -n $lastchg && $lastchg =~ ^[0-9]+$ && $(( lastchg + PASS_MAX_DAYS )) -lt $today ]]; then
            warn "password of '${u}' is older than ${PASS_MAX_DAYS} days: aging NOT applied to avoid immediate expiry - change it, then re-run"
            continue
        fi
        if [[ -z $lastchg || $lastchg -gt $today ]]; then
            chage -d "$today" "$u"
        fi
        chage --maxdays "$PASS_MAX_DAYS" --mindays "$PASS_MIN_DAYS" --warndays "$PASS_WARN_AGE" --inactive "$ACCOUNT_INACTIVE_DAYS" "$u"
    done < /etc/shadow

    # Interactive shells: umask 027, idle timeout.
    if is_ubuntu; then
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
    for f in /etc/profile /etc/bash.bashrc; do
        backup_file "$f"
        sed -i -E 's/^([[:space:]]*umask[[:space:]]+0?(0[0-2][0-6]|[0-2][0-6]))[[:space:]]*$/# \1  (superseded by harden-and-audit)/' "$f"
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
    step "5.8 DoD Notice and Consent banner"
    local banner
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
    if [[ -n ${BANNER_FILE:-} && -r ${BANNER_FILE:-} ]]; then
        banner=$(cat "$BANNER_FILE")
    fi
    printf '%s\n' "$banner" | write_file 0644 /etc/issue
    printf '%s\n' "$banner" | write_file 0644 /etc/issue.net
    printf 'Authorized use only. All activity may be monitored and reported.\n' | write_file 0644 /etc/motd
    # Dynamic MOTD must not disclose kernel/OS details.
    [[ -f /etc/update-motd.d/10-uname ]] && chmod 0644 /etc/update-motd.d/10-uname
    return 0
}

configure_kernel_modules() {
    step "5.9 disable unneeded filesystems, protocols and USB storage"
    local -a mods=(cramfs freevxfs hfs hfsplus jffs2 udf usb-storage dccp rds sctp tipc atm can firewire-core firewire-ohci)
    [[ $ALLOW_CONTAINERS != 1 ]] && mods+=(overlay overlayfs)
    # Ubuntu CIS also disables squashfs, which every snap is mounted from:
    # only where snapd is absent.
    if is_ubuntu; then
        if pkg_installed snapd; then
            log "squashfs stays available: snapd is installed (snaps are squashfs images)"
        else
            mods+=(squashfs)
        fi
    fi
    {
        echo "# Managed by ${SCRIPT_NAME}"
        local m
        for m in "${mods[@]}"; do
            echo "install ${m} /bin/false"
            echo "blacklist ${m}"
        done
    } | write_file 0644 /etc/modprobe.d/60-harden-blacklist.conf
    if [[ $ALLOW_CONTAINERS != 1 ]]; then
        log "overlayfs disabled (set ALLOW_CONTAINERS=1 on Docker/Podman hosts)"
    fi
}

configure_mounts() {
    step "5.10 /tmp, /var/tmp, /dev/shm: nodev,nosuid,noexec"
    backup_file /etc/fstab
    local opts="nodev,nosuid,noexec"
    # /tmp
    if grep -Eq '^[^#[:space:]]+[[:space:]]+/tmp[[:space:]]' /etc/fstab; then
        awk -v o="$opts" '$2=="/tmp" && $1 !~ /^#/ { n=split(o,a,","); for (i=1;i<=n;i++) if ($4 !~ "(^|,)"a[i]"(,|$)") $4=$4","a[i] } {print}' /etc/fstab >/etc/fstab.tmp
        cat /etc/fstab.tmp >/etc/fstab && rm -f /etc/fstab.tmp
    else
        local unit=/usr/lib/systemd/system/tmp.mount
        [[ -f $unit ]] || unit=/usr/share/systemd/tmp.mount
        if [[ -f $unit ]]; then
            write_file 0644 /etc/systemd/system/tmp.mount <<'EOF'
# Managed by harden-and-audit.sh
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
Options=mode=1777,strictatime,nosuid,nodev,noexec,size=50%%,nr_inodes=1m

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
    printf 'tmpfs\t/dev/shm\ttmpfs\tdefaults,%s,size=50%%\t0\t0\n' "$opts" >>/etc/fstab
    # /var/tmp: honour a dedicated partition; otherwise bind it onto itself
    # to enforce the mount options (does not add space isolation).
    if grep -Eq '^[^#[:space:]]+[[:space:]]+/var/tmp[[:space:]]' /etc/fstab; then
        awk -v o="$opts" '$2=="/var/tmp" && $1 !~ /^#/ { n=split(o,a,","); for (i=1;i<=n;i++) if ($4 !~ "(^|,)"a[i]"(,|$)") $4=$4","a[i] } {print}' /etc/fstab >/etc/fstab.tmp
        cat /etc/fstab.tmp >/etc/fstab && rm -f /etc/fstab.tmp
    else
        printf '/var/tmp\t/var/tmp\tnone\tbind,%s\t0\t0\n' "$opts" >>/etc/fstab
    fi
    systemctl daemon-reload

    # Apply now where safe.
    host_only "remount /dev/shm" mount -o remount,"$opts" /dev/shm
    if ! findmnt -n /var/tmp >/dev/null; then
        host_only "bind-mount /var/tmp" mount --bind /var/tmp /var/tmp
    fi
    host_only "remount /var/tmp" mount -o remount,bind,"$opts" /var/tmp
    if findmnt -n /tmp >/dev/null; then
        host_only "remount /tmp" mount -o remount,"$opts" /tmp
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
       -o -regex '.*\.[0-9]+(\.log)?' -o -regex '.*-[0-9]{8}(\.log)?' \) \
    -printf '%T@ %s %p\0' | sort -zn)
msg="pruned ${n} rotated log file(s), freed $(numfmt --to=iec $(( start - used ))); /var/log now $(numfmt --to=iec "$used"), $(free_pct)% free"
if over; then msg+=" - STILL OVER BUDGET: live logs alone exceed it"; fi
logger -t harden-log-budget -p user.warning "$msg"
echo "$msg"
EOF
    } | write_file 0700 /usr/local/sbin/harden-log-budget
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
    rsyslogd -N1 >/dev/null 2>&1 || die "rsyslog configuration is invalid"
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
    logrotate -d /etc/logrotate.conf >/dev/null 2>&1 || die "logrotate configuration is invalid"
    systemctl enable logrotate.timer rsyslog.service >/dev/null 2>&1 || true
    systemctl enable --now cron.service >/dev/null 2>&1 || true
    systemctl restart systemd-journald.service
    systemctl restart rsyslog.service
}

configure_timesync() {
    step "5.13 time synchronisation"
    local s
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
    step "5.14 AppArmor enforcing"
    systemctl enable apparmor.service >/dev/null 2>&1 || true
    local p
    local -a enforce=() complain=()
    for p in /etc/apparmor.d/*; do
        [[ -f $p ]] || continue
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
    if [[ ${#enforce[@]} -gt 0 ]]; then
        host_only "aa-enforce" aa-enforce "${enforce[@]}" >/dev/null
    fi
    if [[ ${#complain[@]} -gt 0 ]]; then
        host_only "aa-complain" aa-complain "${complain[@]}" >/dev/null
    fi
    host_only "start AppArmor" systemctl restart apparmor.service
}

configure_fail2ban() {
    step "5.15 fail2ban (SSH brute-force protection)"
    local ports
    ports=$(IFS=,; echo "${SSH_PORTS[*]}")
    write_file 0644 /etc/fail2ban/jail.d/60-harden.local <<EOF
# Managed by ${SCRIPT_NAME}
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd
ignoreip = 127.0.0.1/8 ::1 ${FAIL2BAN_IGNOREIP}

[sshd]
enabled  = true
port     = ${ports}
mode     = aggressive
EOF
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

configure_aide_config() {
    step "5.18 AIDE configuration (database is built at the end)"
    apt_install aide aide-common
    # Protect the audit toolchain (CIS / STIG). Scanners read these lines
    # from aide.conf itself, with exactly this attribute set.
    local aconf=/etc/aide/aide.conf t
    backup_file "$aconf"
    rm -f /etc/aide/aide.conf.d/99_harden_audit_tools
    sed -i -E "/^# ${MARK}: audit tools$/d; \#^(/usr)?/sbin/(auditctl|auditd|ausearch|aureport|autrace|augenrules)[[:space:]]#d" "$aconf"
    {
        echo "# ${MARK}: audit tools"
        for t in auditctl auditd ausearch aureport autrace augenrules; do
            echo "/usr/sbin/${t} p+i+n+u+g+s+b+acl+selinux+xattrs+sha512"
        done
    } >>"$aconf"
    # The vendor catch-all (99_aide_root: "/ 0 Full") checksums every byte
    # under /, including container layers, VM disks and caches. On a docker/
    # containerd host that is 100+ GB, so the baseline takes hours and the
    # daily check never finishes; the content also churns constantly, so it
    # would only produce noise. Exclude bulk runtime data, not system files.
    # (Name must match aide.conf's x_include filter: [a-zA-Z0-9_-]+.)
    write_file 0644 /etc/aide/aide.conf.d/90_harden_bulk_excludes <<'EOF'
# Managed by harden-and-audit.sh: bulk / volatile data kept out of AIDE.
# Container and VM storage (images are verified by their runtime digests)
!/var/lib/(containerd|docker|containers|kubelet|rancher)(/|$)
!/var/lib/libvirt/images(/|$)
!/var/lib/snapd/(snaps|cache)(/|$)
# Caches and scratch space
!/var/cache(/|$)
!/var/tmp(/|$)
!/tmp(/|$)
# Home directories hold user data (repositories, package caches, app
# profiles), not the system. Still watched: the shell dotfiles, .ssh,
# .config/autostart, systemd user units and .local/bin - where something
# planted would run.
!/(root|home/[^/]+)/[^.][^/]*(/|$)
!/(root|home/[^/]+)/\.(cache|npm|pnpm-store|yarn|bun|deno|nvm|pyenv|cargo|rustup|go|gradle|m2|terraform\.d|vscode-server|mozilla|var)(/|$)
!/(root|home/[^/]+)/\.local/(share|lib|state)(/|$)
!/(root|home/[^/]+)/\.config/(?!(autostart|systemd)(/|$))[^/]+(/|$)
# Swap files (contents change with every page out)
!/(swap\.img|swapfile)$
EOF
    # Any other active swap file, wherever it lives.
    local sw
    while read -r sw t _; do
        [[ $t == file && $sw == /* ]] || continue
        printf '!%s$\n' "$(sed 's/[][\.*^$+?(){}|]/\\&/g' <<<"$sw")"
    done < <(tail -n +2 /proc/swaps) >>/etc/aide/aide.conf.d/90_harden_bulk_excludes
    aide --config-check --config "$aconf" >/dev/null 2>&1 || die "AIDE configuration check failed"
    # Ubuntu's aide-common ships dailyaidecheck.{service,timer}, which the
    # Ubuntu CIS content checks: use it rather than adding a second check.
    if is_ubuntu && systemctl cat dailyaidecheck.timer >/dev/null 2>&1; then
        systemctl disable --now aidecheck.timer aidecheck.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/aidecheck.service /etc/systemd/system/aidecheck.timer
        systemctl daemon-reload
        systemctl enable dailyaidecheck.timer >/dev/null 2>&1 || true
        systemctl start dailyaidecheck.timer >/dev/null 2>&1 || true
        log "AIDE: vendor dailyaidecheck.timer enabled"
        return 0
    fi
    write_file 0644 /etc/systemd/system/aidecheck.service <<'EOF'
# Managed by harden-and-audit.sh
[Unit]
Description=AIDE file integrity check
ConditionPathExists=/var/lib/aide/aide.db

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --config /etc/aide/aide.conf --check
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
    if is_ubuntu; then
        # Headers follow each installed kernel flavour metapackage
        # (linux-image-generic, -virtual, -aws, -azure, -gcp, ...).
        local meta flavour
        while read -r meta; do
            flavour=${meta#linux-image-}
            pkg_candidate "linux-headers-${flavour}" && hdrs+=("linux-headers-${flavour}")
        done < <(dpkg-query -W -f='${db:Status-Status} ${Package}\n' 'linux-image-*' 2>/dev/null \
                 | awk '$1=="installed" && $2 !~ /^linux-image-(unsigned-)?[0-9]/ {print $2}')
        [[ ${#hdrs[@]} -gt 0 ]] || hdrs=(linux-headers-generic)
    else
        hdrs=(linux-headers-amd64)
        [[ $DEB_ARCH == arm64 ]] && hdrs=(linux-headers-arm64)
    fi
    apt_install libc6 libc6-dev gcc make build-essential pkg-config dkms "${hdrs[@]}"
    local running
    running="linux-headers-$(uname -r)"
    if pkg_candidate "$running"; then
        apt_install "$running"
    else
        warn "${running} is not available from the archive (running kernel differs from the packaged one); DKMS builds target the installed kernel"
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
    apt_install "${pkgs[@]}"
    apt-mark manual "${pkgs[@]}" >/dev/null
    if pkg_installed libx11-6 && ! apt-get -s purge libx11-6 2>/dev/null | awk '/^Purg /{print $2}' | qgrep -Ev '^(libx11-6|libx11-xcb1)$'; then
        warn "libx11-6 is still installed only because a non-graphical package depends on it"
    fi
    log "installed ${#pkgs[@]} media/coturn runtime libraries"
}

# ============================================================================
# 7. OpenSCAP
# ============================================================================
install_openscap() {
    step "7.1 OpenSCAP tooling"
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
        if [[ -f $zip ]] && echo "${SSG_SHA512}  ${zip}" | sha512sum -c --status; then
            :
        elif ! { curl -fsSL --proto '=https' --tlsv1.2 --retry 5 -o "$zip" "$SSG_URL" \
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
        echo "os:             ${OS_NAME} (${OS_CODENAME})"
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
    ( umask 077; nice -n 19 ionice -c 3 aideinit -y -f </dev/null >"$AIDE_INIT_LOG" 2>&1 )
}

# Bytes in use on local disk filesystems: the upper bound of what AIDE reads
# (its exclusions make the real amount smaller, so the estimate is cautious).
AIDE_TOTAL_BYTES=0
# Minus the bulk data 90_harden_bulk_excludes keeps out of AIDE (same paths,
# as globs; each du is time-boxed so a huge tree cannot stall the estimate).
aide_estimate_total() {
    local total skip=0 d b h
    local -a dirs=(/var/lib/containerd /var/lib/docker /var/lib/containers /var/lib/kubelet /var/lib/rancher
                   /var/lib/libvirt/images /var/lib/snapd/snaps /var/lib/snapd/cache /var/cache /var/tmp /tmp
                   /swap.img /swapfile)
    total=$(df -l -B1 --output=used -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null \
        | awk 'NR > 1 { s += $1 } END { printf "%d\n", s }')
    for h in /root /home/*; do
        [[ -d $h ]] || continue
        for d in "$h"/[!.]* "$h"/.{cache,npm,pnpm-store,yarn,bun,deno,nvm,pyenv,cargo,rustup,go,gradle,m2,terraform.d,vscode-server,mozilla,var} \
                 "$h"/.local/{share,lib,state} "$h"/.config/*; do
            case ${d##*/.config/} in autostart|systemd) [[ $d == */.config/* ]] && continue ;; esac
            dirs+=("$d")
        done
    done
    while read -r d b _; do
        [[ $b == file && $d == /* && $d != /swap.img && $d != /swapfile ]] && dirs+=("$d")
    done < <(tail -n +2 /proc/swaps 2>/dev/null)
    for d in "${dirs[@]}"; do
        [[ -e $d ]] || continue
        b=$(timeout 20 du -sxb "$d" 2>/dev/null | cut -f1) || continue
        skip=$(( skip + ${b:-0} ))
    done
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
                /dev/*|/proc/*|pipe:*|socket:*|anon_inode:*|/var/lib/aide/*|/etc/aide/*|/var/log/*) ;;
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
    if [[ $AIDE_INIT != 1 ]]; then
        warn "AIDE_INIT=0: AIDE database not built - run 'aideinit -y -f' later"
        return 0
    fi
    if [[ -f /var/lib/aide/aide.db ]]; then
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
    if [[ -f /var/lib/aide/aide.db ]]; then
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
        return "$src"
    fi

    # Full run: every step header in this file, minus the repository step
    # of the other distribution, plus purge_graphical and
    # harden_file_permissions running twice. tests/assertions.sh checks that
    # the final step number equals this total.
    STEP_TOTAL=$(( $(grep -c '^[[:space:]]*step "' "${BASH_SOURCE[0]}") - 1 + 2 ))

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
    log "A reboot is required to activate fips=1, audit=1 and the other kernel arguments."
    return "$rc"
}

rc=0
main "$@" || rc=$?
exit "$rc"
