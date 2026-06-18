#!/usr/bin/env bash
#
# validate-ueransim-mod.sh — end-to-end validation of the modified UERANSIM
# features (tools/ueransim/patches) against the running 5GC.
#
# Prerequisite: the stack is up with the modified image, e.g. `make ueransim`.
#
# Sub-commands:
#   ursp        URSP delivery round-trip: AMF sends MANAGE UE POLICY COMMAND,
#               modded UE replies MANAGE UE POLICY COMPLETE (AMF logs the ACK).
#   ursp-cli    nr-cli introspection: ursp-show + ursp-match on the UE.
#   ursp-steer  URSP-steered additional PDU session via nr-cli ursp-establish.
#   qos-mod     NW-initiated QoS modification: SMF 0xCB -> UE 0xCC round-trip.
#   all         run every check in sequence.
#
set -euo pipefail

UE_CONTAINER="${UE_CONTAINER:-ueransim-ue}"
SUPI="${SUPI:-imsi-001010000000001}"
AMF_MGMT="${AMF_MGMT:-http://localhost:9002}"
SMF_MGMT="${SMF_MGMT:-https://localhost:8004}"

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red() { printf '\033[31m%s\033[0m\n' "$*"; }
hr() { printf -- '----------------------------------------------------------------\n'; }

# Wait until `docker logs <c>` contains <pattern> (up to <secs>). Returns 0/1.
# Uses `grep -c` (consumes all input) rather than `grep -q` (closes the pipe early),
# because under `set -o pipefail` the early close sends SIGPIPE to `docker logs` and
# the pipeline would report failure even on a match.
wait_for_log() {
    local c="$1" pat="$2" secs="${3:-30}" n
    for _ in $(seq 1 "$secs"); do
        n=$(docker logs "$c" 2>&1 | grep -cE "$pat" || true)
        if [ "${n:-0}" -gt 0 ]; then return 0; fi
        sleep 1
    done
    return 1
}

check_ursp() {
    hr; green "[ursp] URSP delivery round-trip (TS 24.501 Annex D)"
    # The policy is pushed at registration; force a fresh push to be deterministic.
    curl -fsS -X POST "$AMF_MGMT/amf/v1/ue-contexts/$SUPI/push-policies" >/dev/null 2>&1 || true

    if wait_for_log amf "UE policy container sent|ursp_version" 20; then
        green "  ✓ AMF sent the UE policy container (MANAGE UE POLICY COMMAND)"
    else
        red "  ✗ AMF did not send a UE policy container"; return 1
    fi

    if wait_for_log amf "MANAGE UE POLICY COMPLETE received" 20; then
        green "  ✓ AMF received MANAGE UE POLICY COMPLETE — modded UE acknowledged URSP"
    else
        red "  ✗ no MANAGE UE POLICY COMPLETE (is the modified UERANSIM image running?)"; return 1
    fi

    if docker logs "$UE_CONTAINER" 2>&1 | grep -qi "URSP policy received"; then
        green "  ✓ UE applied the URSP rules (no 'Unhandled payload container type [5]')"
    else
        red "  ! UE log did not show 'URSP policy received' (check $UE_CONTAINER)"
    fi
}

check_ursp_cli() {
    hr; green "[ursp-cli] nr-cli URSP introspection"
    echo "  ursp-show:"
    docker exec "$UE_CONTAINER" nr-cli "$SUPI" -e "ursp-show" | sed 's/^/    /'
    echo "  ursp-match ims:"
    docker exec "$UE_CONTAINER" nr-cli "$SUPI" -e "ursp-match ims" | sed 's/^/    /'
}

check_ursp_steer() {
    hr; green "[ursp-steer] URSP-steered additional PDU session (TS 23.503 §6.6.2)"
    local target="${1:-ims}"
    docker exec "$UE_CONTAINER" nr-cli "$SUPI" -e "ursp-establish $target" | sed 's/^/    /'
    if wait_for_log "$UE_CONTAINER" "PDU Session establishment is successful" 30; then
        green "  ✓ UE established the URSP-steered session for '$target'"
    else
        red "  ✗ no successful establishment for '$target'"; return 1
    fi
}

check_qos_mod() {
    hr; green "[qos-mod] NW-initiated QoS modification round-trip (TS 23.502 §4.3.3.2)"
    # Ensure a session exists.
    docker exec "$UE_CONTAINER" nr-cli "$SUPI" -e "ps-establish IPv4 --dnn internet" >/dev/null 2>&1 || true
    sleep 3
    curl -fsSk -X POST "$SMF_MGMT/nsmf-management/v1/sessions/1/qos" \
        -H 'Content-Type: application/json' \
        -d '{"5qi":7,"reason":"validate-ueransim-mod"}' >/dev/null 2>&1 || true

    if wait_for_log "$UE_CONTAINER" "QoS modified by the network|Modification Complete" 25; then
        green "  ✓ UE handled PDU SESSION MODIFICATION COMMAND (0xCB) and replied COMPLETE (0xCC)"
    else
        red "  ✗ UE did not handle the modification command"; return 1
    fi
    if wait_for_log amf "Modification Complete received" 15; then
        green "  ✓ AMF received the modification complete — loop closed"
    else
        red "  ! AMF did not log the modification complete"
    fi
}

case "${1:-all}" in
    ursp) check_ursp ;;
    ursp-cli) check_ursp_cli ;;
    ursp-steer) check_ursp_steer "${2:-ims}" ;;
    qos-mod) check_qos_mod ;;
    all)
        check_ursp || true
        check_ursp_cli || true
        check_ursp_steer ims || true
        check_qos_mod || true
        ;;
    *) echo "usage: $0 {ursp|ursp-cli|ursp-steer [target]|qos-mod|all}" >&2; exit 2 ;;
esac
hr; green "validate-ueransim-mod: done"
