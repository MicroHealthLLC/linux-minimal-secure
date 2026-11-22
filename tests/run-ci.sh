#!/usr/bin/env bash
# =============================================================================
# tests/run-ci.sh <debian|ubuntu> <version>     e.g. debian 12, ubuntu 24.04
# tests/run-ci.sh <12|13>                         (shorthand for debian)
#
# End-to-end test of harden-and-audit.sh inside a systemd-booted Debian or
# Ubuntu container that looks like a netinst server to OpenSCAP:
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
#                   Debian, stig on Ubuntu)
#   HARDEN_PROFILE  server (default) | workstation: seeds a GDM/Wayland
#                   desktop that must survive, gates on CIS L2 Workstation
#   ADMIN_ACCESS    ssh (default) | none: no SSH server, no anti-lockout probe
# =============================================================================
set -Eeuo pipefail

usage() { echo "usage: tests/run-ci.sh <debian|ubuntu> <version>   (or: tests/run-ci.sh <12|13>)" >&2; exit 64; }
case $# in
    1) DISTRO=debian; VER=$1 ;;
    2) DISTRO=$1; VER=$2 ;;
    *) usage ;;
esac
case $DISTRO in
    debian) [[ $VER =~ ^[0-9]+$ ]] || usage; DEFAULT_EXTRA=anssi_bp28_high ;;
    ubuntu) [[ $VER =~ ^[0-9]+\.[0-9]+$ ]] || usage; DEFAULT_EXTRA=stig ;;
    *) usage ;;
esac
HARDEN_PROFILE=${HARDEN_PROFILE:-server}
ADMIN_ACCESS=${ADMIN_ACCESS:-ssh}
case $HARDEN_PROFILE in server|workstation) ;; *) usage ;; esac
case $ADMIN_ACCESS in ssh|none) ;; *) usage ;; esac
TAG="${DISTRO}${VER/./}"                # debian12, ubuntu2404
[[ $HARDEN_PROFILE == workstation ]] && TAG+="ws"
[[ $ADMIN_ACCESS == none ]] && TAG+="-nossh"
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
seed=0
[[ $HARDEN_PROFILE == workstation ]] && seed=1
docker build --build-arg "BASE_IMAGE=${DISTRO}:${VER}" --build-arg "SEED_WORKSTATION=${seed}" -t "$IMG" "${REPO}/tests"

cleanup
run_flags=(--detach --name "$NAME" --hostname "ci-${TAG}" --tmpfs /run --tmpfs /run/lock
           --cgroupns=private)
if [[ $CI_PRIVILEGED == 1 ]]; then
    run_flags+=(--privileged)
else
    run_flags+=(--cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add NET_RAW --security-opt apparmor=unconfined)
fi
# Podman (also behind a "docker" shim, whose --version says "docker") only
# mounts a writable cgroup tree for systemd when asked. Docker never gets the
# flag: its `version` output does not name Podman.
if docker version 2>/dev/null | grep -qi podman; then
    run_flags+=(--systemd=always)
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

if [[ $ADMIN_ACCESS == ssh ]]; then
log "seeding SSH key for the sudo administrator (anti-lockout probe)"
docker exec "$NAME" bash -euo pipefail -c '
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends openssh-client >/dev/null
    install -d -m 0700 -o ciadmin -g ciadmin /home/ciadmin/.ssh
    ssh-keygen -q -t ecdsa -b 384 -N "" -f /root/ciadmin_key
    install -m 0600 -o ciadmin -g ciadmin /root/ciadmin_key.pub /home/ciadmin/.ssh/authorized_keys
    ssh-keygen -q -t ecdsa -b 384 -N "" -f /root/root_key
    install -d -m 0700 /root/.ssh
    install -m 0600 /root/root_key.pub /root/.ssh/authorized_keys
'
fi

run_script() {
    local label=$1
    log "running harden-and-audit.sh (${label})"
    set +e
    docker exec \
        -e SCAP_EXTRA_PROFILES="${SCAP_EXTRA}" \
        -e SCAP_ENFORCE_MIN=0 \
        -e HARDEN_PROFILE="${HARDEN_PROFILE}" \
        -e ADMIN_ACCESS="${ADMIN_ACCESS}" \
        -e AIDE_INIT="${AIDE_INIT:-1}" \
        -e PROGRESS_INTERVAL=10 \
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
docker exec -e CI_PRIVILEGED="$CI_PRIVILEGED" -e HARDEN_PROFILE="$HARDEN_PROFILE" -e ADMIN_ACCESS="$ADMIN_ACCESS" "$NAME" bash /src/tests/assertions.sh 2>&1 | tee "${OUT_DIR}/assertions.log"
[[ ${PIPESTATUS[0]} -eq 0 ]] || { echo "functional assertions failed" >&2; exit 1; }

if [[ $RUN_TWICE == 1 ]]; then
    AIDE_INIT=0 run_script second
    collect
    log "functional assertions after second run"
    docker exec -e CI_PRIVILEGED="$CI_PRIVILEGED" -e HARDEN_PROFILE="$HARDEN_PROFILE" -e ADMIN_ACCESS="$ADMIN_ACCESS" "$NAME" bash /src/tests/assertions.sh 2>&1 | tee "${OUT_DIR}/assertions-second.log"
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
    debian) os_label="Debian ${VER}" ;;
    ubuntu) os_label="Ubuntu ${VER}" ;;
esac
bench="Server"
[[ $HARDEN_PROFILE == workstation ]] && bench="Workstation"
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
    echo "### ${os_label} - harden-and-audit.sh (HARDEN_PROFILE=${HARDEN_PROFILE}, ADMIN_ACCESS=${ADMIN_ACCESS})"
    echo
    note=$(sed -n 's/^content note:[[:space:]]*//p' "$S")
    [[ -n $note ]] && { echo "> ${note}"; echo; }
    echo "| Profile | Pass | Fail | Pass rate | XCCDF score | Gate (≥ ${SCAP_MIN_SCORE}%) |"
    echo "|---|---|---|---|---|---|"
    echo "| CIS ${os_label} Level 2 ${bench} | ${cis_pass} | ${cis_fail} | **${cis_rate}%** | ${cis_score} | **${gate}** |"
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
    echo "CIS Level 2 ${bench} pass rate ${cis_rate}% is below ${SCAP_MIN_SCORE}%" >&2
    exit 1
fi
log "PASS: CIS L2 ${bench} ${cis_rate}% (XCCDF ${cis_score})${extra_note}"
