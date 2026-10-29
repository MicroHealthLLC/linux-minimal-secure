#!/usr/bin/env bash
# =============================================================================
# tests/run-ci.sh DEBIAN_VERSION
#
# End-to-end test of harden-and-audit.sh inside a systemd-booted Debian
# container that looks like a netinst server to OpenSCAP:
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
#   OUT_DIR         artifact directory (default ./artifacts/debian<ver>)
# =============================================================================
set -Eeuo pipefail

VER=${1:?usage: tests/run-ci.sh <12|13>}
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMG="dms-test:debian${VER}"
NAME="dms-ci-debian${VER}"
OUT_DIR=${OUT_DIR:-${REPO}/artifacts/debian${VER}}
SCAP_MIN_SCORE=${SCAP_MIN_SCORE:-90}
RUN_TWICE=${RUN_TWICE:-1}
if [[ -z ${CI_PRIVILEGED:-} ]]; then
    if [[ ${GITHUB_ACTIONS:-} == true ]]; then CI_PRIVILEGED=1; else CI_PRIVILEGED=0; fi
fi

log() { printf '\n[run-ci debian%s] %s\n' "$VER" "$*"; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
# KEEP_CONTAINER=1 leaves the hardened container running for inspection.
[[ ${KEEP_CONTAINER:-0} == 1 ]] || trap cleanup EXIT

mkdir -p "$OUT_DIR"

log "building test image ${IMG}"
docker build --build-arg "DEBIAN_VERSION=${VER}" -t "$IMG" "${REPO}/tests"

cleanup
run_flags=(--detach --name "$NAME" --hostname "ci-debian${VER}" --tmpfs /run --tmpfs /run/lock
           --cgroupns=private)
if [[ $CI_PRIVILEGED == 1 ]]; then
    run_flags+=(--privileged)
else
    run_flags+=(--cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add NET_RAW --security-opt apparmor=unconfined)
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

run_script() {
    local label=$1
    log "running harden-and-audit.sh (${label})"
    set +e
    docker exec \
        -e SCAP_EXTRA_PROFILES="anssi_bp28_high" \
        -e SCAP_ENFORCE_MIN=0 \
        -e AIDE_INIT="${AIDE_INIT:-1}" \
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
    for f in scap-results.xml scap-report.html scap-summary.txt scap-results.log \
             scap-results-anssi_bp28_high.xml scap-report-anssi_bp28_high.html scap-summary-anssi_bp28_high.txt; do
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
field() { awk -v k="$1:" '$1==k {print $2}' "$2" | tr -d '%'; }
cis_rate=$(field pass_rate "${OUT_DIR}/scap-summary.txt")
cis_score=$(field xccdf_score "${OUT_DIR}/scap-summary.txt")
cis_pass=$(field pass "${OUT_DIR}/scap-summary.txt")
cis_fail=$(field fail "${OUT_DIR}/scap-summary.txt")
anssi_rate=$(field pass_rate "${OUT_DIR}/scap-summary-anssi_bp28_high.txt" 2>/dev/null || echo n/a)
anssi_score=$(field xccdf_score "${OUT_DIR}/scap-summary-anssi_bp28_high.txt" 2>/dev/null || echo n/a)

gate=FAIL
awk -v r="$cis_rate" -v m="$SCAP_MIN_SCORE" 'BEGIN { exit !(r+0 >= m+0) }' && gate=PASS

{
    echo "### Debian ${VER} - harden-and-audit.sh"
    echo
    echo "| Profile | Pass | Fail | Pass rate | XCCDF score | Gate (≥ ${SCAP_MIN_SCORE}%) |"
    echo "|---|---|---|---|---|---|"
    echo "| CIS Debian ${VER} Level 2 Server | ${cis_pass} | ${cis_fail} | **${cis_rate}%** | ${cis_score} | **${gate}** |"
    echo "| ANSSI BP-028 High (informational) | $(field pass "${OUT_DIR}/scap-summary-anssi_bp28_high.txt") | $(field fail "${OUT_DIR}/scap-summary-anssi_bp28_high.txt") | ${anssi_rate}% | ${anssi_score} | n/a |"
    echo
    echo "<details><summary>Failed CIS rules</summary>"
    echo
    sed -n '/^Failed rules:/,$p' "${OUT_DIR}/scap-summary.txt" | tail -n +2
    echo
    echo "</details>"
} >"${OUT_DIR}/summary.md"
cat "${OUT_DIR}/summary.md"
[[ -n ${GITHUB_STEP_SUMMARY:-} ]] && cat "${OUT_DIR}/summary.md" >>"$GITHUB_STEP_SUMMARY"

if [[ $gate != PASS ]]; then
    echo "CIS Level 2 Server pass rate ${cis_rate}% is below ${SCAP_MIN_SCORE}%" >&2
    exit 1
fi
log "PASS: CIS L2 Server ${cis_rate}% (XCCDF ${cis_score}); ANSSI BP-028 High ${anssi_rate}%"
