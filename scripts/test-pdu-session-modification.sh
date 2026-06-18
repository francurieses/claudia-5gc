#!/usr/bin/env bash
# test-pdu-session-modification.sh — end-to-end test for PDU Session Modification
# UE-requested (TS 23.502 §4.3.3.1).
#
# Prerequisites: `make ueransim` has been run and all containers are healthy.
#
# Exit codes: 0 = all checks passed, 1 = one or more checks failed.
#
# Usage:
#   ./scripts/test-pdu-session-modification.sh [IMSI]
#
# Example:
#   ./scripts/test-pdu-session-modification.sh imsi-001010000000001

set -euo pipefail

IMSI="${1:-imsi-001010000000001}"
UE_CONTAINER="ueransim-ue"
PASS=0
FAIL=0

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[INFO]\033[0m %s\n' "$*"; }

check() {
    local desc="$1"; shift
    if eval "$@"; then
        green "  PASS: $desc"
        PASS=$(( PASS + 1 ))
    else
        red   "  FAIL: $desc"
        FAIL=$(( FAIL + 1 ))
    fi
}

# ---- 0. Preflight -------------------------------------------------------
info "Checking containers are running..."
for svc in amf smf upf "$UE_CONTAINER"; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${svc}$"; then
        red "Container '$svc' is not running. Run 'make ueransim' first."
        exit 1
    fi
done

# ---- 1. Verify UE is registered and session is established --------------
info "Verifying UE registration and PDU session..."
ue_status=$(docker exec "$UE_CONTAINER" nr-cli "$IMSI" -e "status" 2>/dev/null || true)
check "UE is MM-REGISTERED"       echo "$ue_status" | grep -q "MM-REGISTERED"
check "UE session 1 is active"    echo "$ue_status" | grep -q "PDU Session\|uesimtun0"

# ---- 2. Record baseline ping (data plane before modification) -----------
info "Checking data plane before modification..."
PING_IFACE="uesimtun0"
pre_ping=$(docker exec "$UE_CONTAINER" \
    ping -c 4 -I "$PING_IFACE" -W 2 8.8.8.8 2>&1 || true)
check "Baseline ping via $PING_IFACE succeeds" \
    echo "$pre_ping" | grep -q "0% packet loss\|0 packets lost"

# ---- 3. Capture log watermark before triggering modification ------------
AMF_LOG_LINES_BEFORE=$(docker logs amf 2>&1 | wc -l)
SMF_LOG_LINES_BEFORE=$(docker logs smf 2>&1 | wc -l)

# ---- 4. Trigger PDU Session Modification via UERANSIM ------------------
info "Triggering PDU Session Modification for $IMSI session 1..."
mod_out=$(docker exec "$UE_CONTAINER" nr-cli "$IMSI" -e "ps-modify 1" 2>&1 || true)
info "nr-cli output: $mod_out"
sleep 2   # allow procedure to complete (typical latency <500 ms)

# ---- 5. Verify AMF log contains procedure trace ------------------------
AMF_LOG_NEW=$(docker logs amf 2>&1 | tail -n +"$AMF_LOG_LINES_BEFORE")
check "AMF logged PDU Session Modification procedure" \
    echo "$AMF_LOG_NEW" | grep -q "PDUSessionModification\|ModifySMContext\|0xC9\|ModificationRequest"
check "AMF logged sending NGAP Modify Request (ProcCode=26)" \
    echo "$AMF_LOG_NEW" | grep -q "PDUSessionResourceModifyRequest\|ProcedureCode.*26\|pdu_session_id"

# ---- 6. Verify SMF log -----------------------------------------------
SMF_LOG_NEW=$(docker logs smf 2>&1 | tail -n +"$SMF_LOG_LINES_BEFORE")
check "SMF logged accepting modification (0xCB response)" \
    echo "$SMF_LOG_NEW" | grep -q "ModifySMContext\|accepting modification\|0xCB\|ModificationCommand"

# ---- 7. Verify UE completed modification --------------------------------
sleep 1
ue_status_after=$(docker exec "$UE_CONTAINER" nr-cli "$IMSI" -e "status" 2>/dev/null || true)
check "UE still MM-REGISTERED after modification" \
    echo "$ue_status_after" | grep -q "MM-REGISTERED"
check "PDU session 1 still active after modification" \
    echo "$ue_status_after" | grep -q "PDU Session\|uesimtun0"

# ---- 8. Verify data plane after modification (no regression) -----------
info "Checking data plane after modification..."
post_ping=$(docker exec "$UE_CONTAINER" \
    ping -c 4 -I "$PING_IFACE" -W 2 8.8.8.8 2>&1 || true)
check "Post-modification ping via $PING_IFACE succeeds" \
    echo "$post_ping" | grep -q "0% packet loss\|0 packets lost"

# ---- 9. Verify Modification Complete (0xCC) was received by AMF --------
check "AMF logged receiving Modification Complete (0xCC)" \
    echo "$AMF_LOG_NEW" | grep -q "ModificationComplete\|0xCC\|Modification Complete"

# ---- Summary ------------------------------------------------------------
echo ""
echo "=============================="
printf "  Results: %d passed, %d failed\n" "$PASS" "$FAIL"
echo "=============================="

if [ "$FAIL" -eq 0 ]; then
    green "PDU Session Modification e2e test PASSED"
    exit 0
else
    red "PDU Session Modification e2e test FAILED ($FAIL checks failed)"
    echo ""
    info "Debugging hints:"
    echo "  docker logs amf | jq 'select(.procedure==\"PDUSessionModification\")'"
    echo "  docker logs smf | jq 'select(.procedure==\"SmContextUpdate\")'"
    echo "  docker exec $UE_CONTAINER nr-cli $IMSI -e 'status'"
    echo "  ./scripts/pcap-control.sh list amf   # PCAP for Wireshark"
    exit 1
fi
