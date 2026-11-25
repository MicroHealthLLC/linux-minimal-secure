#!/usr/bin/env bash
# =============================================================================
# tests/run-ci.sh <distro> <version>   e.g. debian 12, ubuntu 24.04, rocky 9,
#                                       almalinux 10, centos 9 (CentOS Stream)
# tests/run-ci.sh <12|13>                         (shorthand for debian)
#
# End-to-end test of harden-and-audit.sh inside a systemd-booted container
# that looks like a minimal server install to OpenSCAP:
#   1. build + boot the test image          4. functional assertions
#   2. seed an SSH key for the admin         5. second run (idempotence)
#   3. run the hardening script              6. SCAP score gate + artifacts
#
# Environment:
#   CI_PRIVILEGED   1 = --privileged (default on GitHub Actions; the runner is
#                   ephemeral). 0 = CAP_SYS_ADMIN/NET_ADMIN only, so a
#                   developer workstation's kernel settings are never touched.
#   SCAP_MIN_SCORE  gate threshold for the CIS L2 Server pass rate (default 90)
#   RUN_TWICE       1 = re-run the script to prove idempotence (default 1)
#   OUT_DIR         artifact directory (default ./artifacts/<distro><ver>)
#   SCAP_EXTRA      informational profile(s) (default: anssi_bp28_high on
#                   Debian, stig on Ubuntu and the RHEL family)
# =============================================================================
set -Eeuo pipefail

usage() { echo "usage: tests/run-ci.sh <debian|ubuntu|rocky|almalinux|centos|fedora> <version> [desktop|proxmox|k8s]   (or: tests/run-ci.sh <12|13>)" >&2; exit 64; }
VARIANT=""
case $# in
    1) DISTRO=debian; VER=$1 ;;
    2) DISTRO=$1; VER=$2 ;;
    3) DISTRO=$1; VER=$2; VARIANT=$3; [[ $VARIANT =~ ^(desktop|proxmox|k8s)$ ]] || usage ;;
    *) usage ;;
esac
FAMILY=deb
DOCKERFILE=Dockerfile
BASE_IMAGE="${DISTRO}:${VER}"
case $DISTRO in
    debian) [[ $VER =~ ^[0-9]+$ ]] || usage; DEFAULT_EXTRA=anssi_bp28_high ;;
    ubuntu) [[ $VER =~ ^[0-9]+\.[0-9]+$ ]] || usage; DEFAULT_EXTRA=stig ;;
    rocky|almalinux|centos|fedora)
        [[ $VER =~ ^[0-9]+$ ]] || usage
        FAMILY=rhel; DOCKERFILE=Dockerfile.el; DEFAULT_EXTRA=stig
        case $DISTRO in
            rocky)     BASE_IMAGE="rockylinux/rockylinux:${VER}" ;;
            almalinux) BASE_IMAGE="almalinux:${VER}" ;;
            centos)    BASE_IMAGE="quay.io/centos/centos:stream${VER}" ;;
            fedora)    BASE_IMAGE="fedora:${VER}"; DEFAULT_EXTRA="" ;;   # no STIG content for Fedora
        esac
        ;;
    *) usage ;;
esac
# Proxmox VE runs on Debian 12 (PVE 8) and 13 (PVE 9) only.
[[ $VARIANT == proxmox && ! ( $DISTRO == debian && $VER =~ ^1[23]$ ) ]] && usage
TAG="${DISTRO}${VER/./}${VARIANT}"      # debian12, ubuntu2404, fedora45desktop
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMG="dms-test:${TAG}"
NAME="dms-ci-${TAG}"
OUT_DIR=${OUT_DIR:-${REPO}/artifacts/${TAG}}
SCAP_EXTRA=${SCAP_EXTRA-$DEFAULT_EXTRA}
SCAP_MIN_SCORE=${SCAP_MIN_SCORE:-90}
RUN_TWICE=${RUN_TWICE:-1}
if [[ -z ${CI_PRIVILEGED:-} ]]; then
    if [[ ${GITHUB_ACTIONS:-} == true ]]; then CI_PRIVILEGED=1; else CI_PRIVILEGED=0; fi
fi

log() { printf '\n[run-ci %s] %s\n' "$TAG" "$*"; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
# KEEP_CONTAINER=1 leaves the hardened container running for inspection.
[[ ${KEEP_CONTAINER:-0} == 1 ]] || trap cleanup EXIT

mkdir -p "$OUT_DIR"

log "building test image ${IMG}"
docker build --build-arg "BASE_IMAGE=${BASE_IMAGE}" --build-arg "DESKTOP=$([[ $VARIANT == desktop ]] && echo 1 || echo 0)" \
    --build-arg "VARIANT=$([[ $VARIANT =~ ^(proxmox|k8s)$ ]] && echo "$VARIANT")" \
    -f "${REPO}/tests/${DOCKERFILE}" -t "$IMG" "${REPO}/tests"

cleanup
run_flags=(--detach --name "$NAME" --hostname "ci-${TAG}" --tmpfs /run --tmpfs /run/lock
           --cgroupns=private)
# Container runtimes inside the test container need a real filesystem for
# their storage (overlay on the container's own overlay root is refused).
# (Docker 29+ keeps image layers in containerd's snapshotter: /var/lib/containerd.)
[[ $VARIANT == k8s ]] && run_flags+=(--volume /var/lib/docker --volume /var/lib/containerd --volume /var/lib/containers)
if [[ $CI_PRIVILEGED == 1 ]]; then
    run_flags+=(--privileged)
else
    # DAC_READ_SEARCH: EL's unix_chkpwd keeps only this capability to read the
    # 0000 shadow file; without it PAM's account phase denies every login.
    run_flags+=(--cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add NET_RAW --cap-add DAC_READ_SEARCH --security-opt apparmor=unconfined)
fi
# Ubuntu runners load an AppArmor profile for unix_chkpwd that attaches BY
# PATH, also to the EL helper inside a privileged container, and lacks what
# EL's 0000 shadow file needs (PAM's account phase then denies every SSH
# login). A real EL host has no AppArmor: unload the profile on the
# ephemeral CI runner only.
if [[ $FAMILY == rhel && $CI_PRIVILEGED == 1 && ${GITHUB_ACTIONS:-} == true && -f /etc/apparmor.d/unix-chkpwd ]]; then
    sudo apparmor_parser -R /etc/apparmor.d/unix-chkpwd 2>/dev/null || true
    log "unloaded the runner's AppArmor unix-chkpwd profile (EL test only)"
fi
log "booting container (privileged=${CI_PRIVILEGED})"
docker run "${run_flags[@]}" "$IMG" >/dev/null

for _ in $(seq 1 60); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    [[ $state == running || $state == degraded ]] && break
    sleep 2
done
log "systemd state: ${state:-unknown}"

# Copy (not bind-mount) the sources so every file on the "host" is owned by a
# local account, exactly as on a real server.
docker exec "$NAME" install -d -m 0755 /src
docker cp "${REPO}/harden-and-audit.sh" "${NAME}:/src/harden-and-audit.sh"
docker cp "${REPO}/tests" "${NAME}:/src/tests"
docker exec "$NAME" chown -R root:root /src

log "seeding SSH key for the sudo administrator (anti-lockout probe)"
docker exec -e FAMILY="$FAMILY" "$NAME" bash -euo pipefail -c '
    if [ "$FAMILY" = rhel ]; then
        dnf -y -q install openssh-clients >/dev/null
    else
        # Proxmox look-alike: the enterprise repository answers 401 until the
        # script switches to no-subscription, so this update may fail.
        apt-get update -qq >/dev/null 2>&1 || true
        apt-get install -y -qq --no-install-recommends openssh-client >/dev/null
    fi
    install -d -m 0700 -o ciadmin -g ciadmin /home/ciadmin/.ssh
    ssh-keygen -q -t ecdsa -b 384 -N "" -f /root/ciadmin_key
    install -m 0600 -o ciadmin -g ciadmin /root/ciadmin_key.pub /home/ciadmin/.ssh/authorized_keys
    ssh-keygen -q -t ecdsa -b 384 -N "" -f /root/root_key
    # Pre-existing TMOUT settings read after 60-harden.sh (field report:
    # "-bash: TMOUT: readonly variable" at every login).
    printf "TMOUT=600\nexport TMOUT\n" >/etc/profile.d/zz-ci-tmout.sh
    printf "\nexport TMOUT=1200\n" >>/root/.bashrc
    install -d -m 0700 /root/.ssh
    # Proxmox look-alike: authorized_keys links into /etc/pve/priv; append.
    if [ -L /root/.ssh/authorized_keys ]; then
        cat /root/root_key.pub >>/root/.ssh/authorized_keys
    else
        install -m 0600 /root/root_key.pub /root/.ssh/authorized_keys
    fi
'

run_script() {
    local label=$1
    log "running harden-and-audit.sh (${label})"
    set +e
    docker exec \
        -e SCAP_EXTRA_PROFILES="${SCAP_EXTRA}" \
        -e SCAP_ENFORCE_MIN=0 \
        -e AIDE_INIT="${AIDE_INIT:-1}" \
        -e PROGRESS_INTERVAL=10 \
        -e PVE_FIREWALL_ENABLE="$([[ $VARIANT == proxmox ]] && echo 1 || echo 0)" \
        -e PVE_ROOT_PASSWORD_FROM="$([[ $VARIANT == proxmox ]] && echo '192.168.0.0/16, 172.16.0.0/12')" \
        "$NAME" bash /src/harden-and-audit.sh 2>&1 | tee "${OUT_DIR}/harden-${label}.log"
    local rc=${PIPESTATUS[0]}
    set -e
    if [[ $rc -ne 0 ]]; then
        echo "harden-and-audit.sh (${label}) exited with ${rc}" >&2
        return "$rc"
    fi
}

collect() {
    log "collecting artifacts into ${OUT_DIR}"
    local f
    local f p
    local -a files=(scap-results.xml scap-report.html scap-summary.txt scap-results.log harden-and-audit.log)
    for p in $SCAP_EXTRA; do
        files+=("scap-results-${p}.xml" "scap-report-${p}.html" "scap-summary-${p}.txt")
    done
    for f in "${files[@]}"; do
        docker cp "${NAME}:/var/log/${f}" "${OUT_DIR}/${f}" >/dev/null 2>&1 || true
    done
}

rc=0
run_script first || rc=$?
collect
if [[ $rc -ne 0 ]]; then
    exit "$rc"
fi

log "functional assertions"
docker exec -e CI_PRIVILEGED="$CI_PRIVILEGED" "$NAME" bash /src/tests/assertions.sh 2>&1 | tee "${OUT_DIR}/assertions.log"
[[ ${PIPESTATUS[0]} -eq 0 ]] || { echo "functional assertions failed" >&2; exit 1; }

if [[ $RUN_TWICE == 1 ]]; then
    AIDE_INIT=0 run_script second
    collect
    log "functional assertions after second run"
    docker exec -e CI_PRIVILEGED="$CI_PRIVILEGED" "$NAME" bash /src/tests/assertions.sh 2>&1 | tee "${OUT_DIR}/assertions-second.log"
    [[ ${PIPESTATUS[0]} -eq 0 ]] || { echo "functional assertions failed after second run" >&2; exit 1; }
fi

# ---------------------------------------------------------------------------
# Score gate
# ---------------------------------------------------------------------------
field() { awk -v k="$1:" '$1==k {print $2}' "$2" 2>/dev/null | tr -d '%'; }
S="${OUT_DIR}/scap-summary.txt"
cis_rate=$(field pass_rate "$S")
cis_score=$(field xccdf_score "$S")
cis_pass=$(field pass "$S")
cis_fail=$(field fail "$S")
case $DISTRO in
    debian)    os_label="Debian ${VER}" ;;
    ubuntu)    os_label="Ubuntu ${VER}" ;;
    rocky)     os_label="Rocky Linux ${VER}" ;;
    almalinux) os_label="AlmaLinux ${VER}" ;;
    centos)    os_label="CentOS Stream ${VER}" ;;
    fedora)    os_label="Fedora ${VER}" ;;
esac
[[ $VARIANT == desktop ]] && os_label+=" desktop"
[[ $VARIANT == proxmox ]] && os_label="Proxmox VE $([[ $VER == 12 ]] && echo 8 || echo 9) (${os_label})"
[[ $VARIANT == k8s ]] && os_label+=" + containers/Kubernetes"
profile_label() {
    case $1 in
        anssi_bp28_high) echo "ANSSI BP-028 High" ;;
        stig) echo "DISA STIG" ;;
        *) echo "$1" ;;
    esac
}

gate=FAIL
awk -v r="$cis_rate" -v m="$SCAP_MIN_SCORE" 'BEGIN { exit !(r+0 >= m+0) }' && gate=PASS

extra_note=""
{
    echo "### ${os_label} - harden-and-audit.sh"
    echo
    note=$(sed -n 's/^content note:[[:space:]]*//p' "$S")
    [[ -n $note ]] && { echo "> ${note}"; echo; }
    echo "| Profile | Pass | Fail | Pass rate | XCCDF score | Gate (≥ ${SCAP_MIN_SCORE}%) |"
    echo "|---|---|---|---|---|---|"
    echo "| CIS ${os_label} Level 2 $([[ $VARIANT == desktop ]] && echo Workstation || echo Server) | ${cis_pass} | ${cis_fail} | **${cis_rate}%** | ${cis_score} | **${gate}** |"
    for p in $SCAP_EXTRA; do
        E="${OUT_DIR}/scap-summary-${p}.txt"
        if [[ -f $E ]]; then
            echo "| $(profile_label "$p") (informational) | $(field pass "$E") | $(field fail "$E") | $(field pass_rate "$E")% | $(field xccdf_score "$E") | n/a |"
            extra_note+="; $(profile_label "$p") $(field pass_rate "$E")%"
        else
            echo "| $(profile_label "$p") (informational) | - | - | not available for this release | - | n/a |"
        fi
    done
    echo
    echo "<details><summary>Failed CIS rules</summary>"
    echo
    sed -n '/^Failed rules:/,$p' "$S" | tail -n +2
    echo
    echo "</details>"
} >"${OUT_DIR}/summary.md"
cat "${OUT_DIR}/summary.md"
[[ -n ${GITHUB_STEP_SUMMARY:-} ]] && cat "${OUT_DIR}/summary.md" >>"$GITHUB_STEP_SUMMARY"

if [[ $gate != PASS ]]; then
    echo "CIS Level 2 Server pass rate ${cis_rate}% is below ${SCAP_MIN_SCORE}%" >&2
    exit 1
fi
log "PASS: CIS L2 $([[ $VARIANT == desktop ]] && echo Workstation || echo Server) ${cis_rate}% (XCCDF ${cis_score})${extra_note}"
