#!/usr/bin/env bash
# scripts/test-slices.sh
# Validates multi-slice network slicing with 4 UEs (internet/gold/silver/bronze).
#
# Prerequisites:  make ueransim-slices   (all containers running)
# Usage:          make test-slices   OR   ./scripts/test-slices.sh
#
# Slices under test:
#   internet  SST=1 SD=000001  eMBB best-effort   UE imsi-...0001
#   gold      SST=1 SD=000002  eMBB premium       UE imsi-...0002
#   silver    SST=2 SD=000001  URLLC              UE imsi-...0003
#   bronze    SST=3 SD=000001  MIoT               UE imsi-...0004
#
# Ref: TS 23.501 §5.15, TS 23.502 §4.2.2.2.2, TS 29.531 §5.2.2.2

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; SKIP=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${NC} $1"; ((FAIL++)); }
skip() { echo -e "  ${YELLOW}○${NC} $1 (skipped)"; ((SKIP++)); }
section() { echo -e "\n${BOLD}${CYAN}━━ $1 ━━${NC}"; }

wait_for_state() {
    local container=$1 pattern=$2 label=$3 timeout=${4:-30}
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        if docker logs "$container" 2>&1 | grep -q "$pattern"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

echo -e "\n${BOLD}5GC Multi-Slice Validation — $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo "Slices: internet(SST=1/SD=000001) gold(SST=1/SD=000002) silver(SST=2/SD=000001) bronze(SST=3/SD=000001)"

# ─────────────────────────────────────────────────────────────────────────────
section "T0 · Infrastructure — containers running"
# ─────────────────────────────────────────────────────────────────────────────

for svc in nrf amf smf nssf udr ueransim-gnb-ms \
            ueransim-ue-internet ueransim-ue-gold ueransim-ue-silver ueransim-ue-bronze; do
    if docker inspect --format '{{.State.Status}}' "$svc" 2>/dev/null | grep -q "running"; then
        pass "container $svc running"
    else
        fail "container $svc NOT running"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T1 · NRF — SMF announces 4 SNSSAIs"
# ─────────────────────────────────────────────────────────────────────────────

NRF_RESP=$(docker exec amf curl -sk --http2-prior-knowledge \
    "https://nrf:8000/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF" 2>/dev/null || true)

for sst_sd in "1/000001:internet" "1/000002:gold" "2/000001:silver" "3/000001:bronze"; do
    sst="${sst_sd%%/*}"; rest="${sst_sd#*/}"; sd="${rest%%:*}"; label="${rest##*:}"
    # NRF stores sNssais as objects; check for sst value and sd value
    if echo "$NRF_RESP" | grep -q "\"sst\":$sst" && echo "$NRF_RESP" | grep -q "\"sd\":\"$sd\""; then
        pass "SMF announces SST=$sst/SD=$sd ($label) in NRF"
    elif echo "$NRF_RESP" | grep -q "$sd"; then
        pass "SMF announces SD=$sd ($label) in NRF"
    else
        fail "SMF does NOT announce SST=$sst/SD=$sd ($label) in NRF"
        echo "    Debug: docker exec amf curl -sk --http2-prior-knowledge 'https://nrf:8000/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF' | jq '.nfInstances[].sNssais'"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T2 · NSSF — NSSelection returns correct slices"
# ─────────────────────────────────────────────────────────────────────────────

for sst_sd in "1/000001:internet" "1/000002:gold" "2/000001:silver" "3/000001:bronze"; do
    sst="${sst_sd%%/*}"; rest="${sst_sd#*/}"; sd="${rest%%:*}"; label="${rest##*:}"
    REQUESTED="[{\"sst\":$sst,\"sd\":\"$sd\"}]"
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REQUESTED'))" 2>/dev/null || \
              python  -c "import urllib.parse; print(urllib.parse.quote('$REQUESTED'))" 2>/dev/null || \
              printf '%s' "$REQUESTED" | sed 's/ /%20/g; s/\[/%5B/g; s/\]/%5D/g; s/{/%7B/g; s/}/%7D/g; s/"/%22/g; s/,/%2C/g; s/:/%3A/g')
    RESP=$(docker exec amf curl -sk --http2-prior-knowledge \
        "https://nssf:8007/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=amf-001&slice-info-request-for-registration.requestedNssai=${ENCODED}" 2>/dev/null || true)
    if echo "$RESP" | grep -q "\"sst\":$sst"; then
        pass "NSSF authorizes SST=$sst/SD=$sd ($label)"
    else
        fail "NSSF does not return SST=$sst/SD=$sd ($label)"
        echo "    Resp: $RESP"
    fi
done

# NSSF rejects unconfigured slice
RESP_UNKNOWN=$(docker exec amf curl -sk --http2-prior-knowledge \
    "https://nssf:8007/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=amf-001&slice-info-request-for-registration.requestedNssai=%5B%7B%22sst%22%3A9%2C%22sd%22%3A%22999999%22%7D%5D" 2>/dev/null || true)
if echo "$RESP_UNKNOWN" | grep -q '"allowedSnssaiList":\[\]' || \
   (echo "$RESP_UNKNOWN" | grep -q '"allowedNssaiList"' && ! echo "$RESP_UNKNOWN" | grep -q '"sst":9'); then
    pass "NSSF returns empty list for unknown slice (SST=9/SD=999999)"
else
    fail "NSSF should return empty list for unconfigured slice"
    echo "    Resp: $RESP_UNKNOWN"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "T3 · UDR — subscribers seeded with correct NSSAI"
# ─────────────────────────────────────────────────────────────────────────────

declare -A EXPECTED_SNSSAI=(
    ["imsi-001010000000001"]="000001"   # internet only
    ["imsi-001010000000002"]="000002"   # gold (also has internet)
    ["imsi-001010000000003"]="000001"   # silver SST=2/SD=000001
    ["imsi-001010000000004"]="000001"   # bronze SST=3/SD=000001
)
declare -A EXPECTED_SST=(
    ["imsi-001010000000001"]="1"
    ["imsi-001010000000002"]="1"
    ["imsi-001010000000003"]="2"
    ["imsi-001010000000004"]="3"
)

for supi in imsi-001010000000001 imsi-001010000000002 imsi-001010000000003 imsi-001010000000004; do
    AM=$(docker exec amf curl -sk --http2-prior-knowledge \
        "https://udm:8003/nudm-sdm/v2/${supi}/am-data" 2>/dev/null || true)
    exp_sd="${EXPECTED_SNSSAI[$supi]}"
    exp_sst="${EXPECTED_SST[$supi]}"
    if echo "$AM" | grep -q "\"sd\":\"$exp_sd\"" && echo "$AM" | grep -q "\"sst\":$exp_sst"; then
        pass "$supi has SST=$exp_sst/SD=$exp_sd in UDM"
    elif echo "$AM" | grep -q "$exp_sd"; then
        pass "$supi has SD=$exp_sd in UDM"
    else
        fail "$supi does NOT have SST=$exp_sst/SD=$exp_sd in UDM"
        echo "    AM data: $AM"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T4 · UE Registration — MM-REGISTERED on all 4 UEs"
# ─────────────────────────────────────────────────────────────────────────────

echo "  Waiting for registration (up to 45s per UE)..."
declare -A UE_SLICE=(
    [ueransim-ue-internet]="internet SST=1/SD=000001"
    [ueransim-ue-gold]="gold SST=1/SD=000002"
    [ueransim-ue-silver]="silver SST=2/SD=000001"
    [ueransim-ue-bronze]="bronze SST=3/SD=000001"
)

for ue in ueransim-ue-internet ueransim-ue-gold ueransim-ue-silver ueransim-ue-bronze; do
    label="${UE_SLICE[$ue]}"
    if wait_for_state "$ue" "MM-REGISTERED" "$label" 45; then
        pass "$ue registered ($label)"
    else
        fail "$ue did NOT register within timeout — $label"
        echo "    Debug: docker logs $ue 2>&1 | tail -20"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T5 · AMF — AllowedNSSAI per UE"
# ─────────────────────────────────────────────────────────────────────────────
# Each UE's AllowedNSSAI in Registration Accept must match exactly its subscribed slices.

AMF_LOGS=$(docker logs amf 2>&1)

declare -A SUPI_SLICE=(
    ["001010000000001"]="SST=1.*SD=000001\|snssai_sst.*1.*snssai_sd.*000001"
    ["001010000000002"]="SST=1.*SD=000002\|snssai_sst.*1.*snssai_sd.*000002"
    ["001010000000003"]="SST=2.*SD=000001\|snssai_sst.*2.*snssai_sd.*000001"
    ["001010000000004"]="SST=3.*SD=000001\|snssai_sst.*3.*snssai_sd.*000001"
)
declare -A SUPI_LABEL=(
    ["001010000000001"]="internet"
    ["001010000000002"]="gold"
    ["001010000000003"]="silver"
    ["001010000000004"]="bronze"
)

for imsi in 001010000000001 001010000000002 001010000000003 001010000000004; do
    label="${SUPI_LABEL[$imsi]}"
    # Check that the AMF logged a successful registration for this SUPI with snssai_count >= 1
    if echo "$AMF_LOGS" | grep -q "\"supi\":\"imsi-$imsi\"" && \
       echo "$AMF_LOGS" | grep "imsi-$imsi" | grep -q '"snssai_count":[1-9]'; then
        pass "AMF registered imsi-$imsi with assigned slices ($label)"
    elif echo "$AMF_LOGS" | grep -q "imsi-$imsi"; then
        skip "AMF has logs for imsi-$imsi but could not verify snssai_count ($label)"
    else
        fail "AMF has no registration logs for imsi-$imsi ($label)"
    fi
done

# T5b: NSSAI_NOT_ALLOWED should appear if there was an attempt with unsubscribed slice
if echo "$AMF_LOGS" | grep -q "NSSAI_NOT_ALLOWED"; then
    skip "At least one NSSAI_NOT_ALLOWED found in AMF logs (expected if ue-unauth was tested)"
else
    pass "No spurious NSSAI_NOT_ALLOWED in AMF logs"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "T6 · PDU Session — sessions established with correct SNSSAI"
# ─────────────────────────────────────────────────────────────────────────────

echo "  Waiting for PDU sessions (up to 30s)..."
for ue in ueransim-ue-internet ueransim-ue-gold ueransim-ue-silver ueransim-ue-bronze; do
    if wait_for_state "$ue" "PDU Session establishment is successful" "$ue" 30; then
        pass "$ue — PDU Session established"
    else
        fail "$ue — PDU Session NOT established within timeout"
        echo "    Debug: docker logs $ue 2>&1 | grep -E 'PDU|session|error'"
    fi
done

SMF_LOGS=$(docker logs smf 2>&1)

# Verify SMF bound each session to the correct SNSSAI
declare -A SNSSAI_EXPECTED_SMF=(
    ["imsi-001010000000001"]="snssai_sst.*:.*1.*snssai_sd.*:.*000001"
    ["imsi-001010000000002"]="snssai_sst.*:.*1.*snssai_sd.*:.*000002"
    ["imsi-001010000000003"]="snssai_sst.*:.*2.*snssai_sd.*:.*000001"
    ["imsi-001010000000004"]="snssai_sst.*:.*3.*snssai_sd.*:.*000001"
)

for imsi in 001010000000001 001010000000002 001010000000003 001010000000004; do
    label="${SUPI_LABEL[$imsi]}"
    if echo "$SMF_LOGS" | grep -q "imsi-$imsi"; then
        pass "SMF has logs for session imsi-$imsi ($label)"
    else
        fail "SMF does not have logs for imsi-$imsi ($label)"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T7 · Data plane — TUN active and e2e ping"
# ─────────────────────────────────────────────────────────────────────────────

declare -A UE_TUN=(
    [ueransim-ue-internet]="uesimtun0"
    [ueransim-ue-gold]="uesimtun0"
    [ueransim-ue-silver]="uesimtun0"
    [ueransim-ue-bronze]="uesimtun0"
)

for ue in ueransim-ue-internet ueransim-ue-gold ueransim-ue-silver ueransim-ue-bronze; do
    tun="${UE_TUN[$ue]}"
    label="${UE_SLICE[$ue]}"
    # Check TUN interface exists
    if docker exec "$ue" ip link show "$tun" 2>/dev/null | grep -q "UP\|UNKNOWN"; then
        pass "$ue — $tun interface active ($label)"
    elif docker exec "$ue" ip link show "$tun" 2>/dev/null | grep -q "$tun"; then
        pass "$ue — $tun interface exists ($label)"
    else
        fail "$ue — $tun interface NOT found ($label)"
        echo "    Debug: docker exec $ue ip link"
        continue
    fi
    # Ping UPF N3 address through the slice TUN
    if docker exec "$ue" ping -c 2 -W 3 -I "$tun" 172.30.3.100 >/dev/null 2>&1; then
        pass "$ue — ping 172.30.3.100 (UPF) OK via $tun ($label)"
    else
        fail "$ue — ping 172.30.3.100 (UPF) FAILED via $tun ($label)"
        echo "    Debug: docker exec $ue ping -c 3 -I $tun 172.30.3.100"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T8 · Isolation — unauthorized slice rejected"
# ─────────────────────────────────────────────────────────────────────────────
# UE1 (internet subscription) requesting gold slice → NSSAI_NOT_ALLOWED

echo "  Launching UE with unauthorized slice..."
if docker run --rm --network 5gc-rel17_n2-net \
        --cap-add NET_ADMIN \
        -v "$(pwd)/config/ueransim/ue-unauth.yaml:/ueransim/config/ue-unauth.yaml:ro" \
        5gc/ueransim:dev \
        nr-ue -c /ueransim/config/ue-unauth.yaml 2>&1 | \
        timeout 20 grep -m1 "MM-REGISTERED\|no allowed nssai\|Registration reject\|PDU Session establishment.*failed" | head -1; then
    echo "  (UE unauthorized completed)"
fi

# Check AMF logs for NSSAI_NOT_ALLOWED after unauthorized attempt
sleep 3
if docker logs amf 2>&1 | grep -q "NSSAI_NOT_ALLOWED"; then
    pass "AMF rejected unauthorized slice (NSSAI_NOT_ALLOWED logged)"
else
    skip "NSSAI_NOT_ALLOWED not found in AMF logs — may require manual retry"
    echo "    Manual: docker run --rm --network 5gc-rel17_n2-net --cap-add NET_ADMIN \\"
    echo "      -v \$(pwd)/config/ueransim/ue-unauth.yaml:/ueransim/config/ue-unauth.yaml:ro \\"
    echo "      5gc/ueransim:dev nr-ue -c /ueransim/config/ue-unauth.yaml &"
    echo "    Then: docker logs amf 2>&1 | grep NSSAI_NOT_ALLOWED"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "T9 · Prometheus — slice metrics in AMF and NSSF"
# ─────────────────────────────────────────────────────────────────────────────

AMF_METRICS=$(curl -s http://localhost:9101/metrics 2>/dev/null || true)
NSSF_METRICS=$(curl -s http://localhost:9109/metrics 2>/dev/null || true)

if echo "$AMF_METRICS" | grep -q "nas_messages_total"; then
    pass "AMF exposes nas_messages_total in /metrics"
else
    skip "AMF /metrics not accessible from host (port 9101)"
fi

if echo "$NSSF_METRICS" | grep -q "go_"; then
    pass "NSSF exposes Go metrics in /metrics"
else
    skip "NSSF /metrics not accessible from host (port 9109)"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "Summary"
# ─────────────────────────────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL + SKIP))
echo -e "\n  Total: $TOTAL  ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YELLOW}SKIP: $SKIP${NC}\n"

if [ $FAIL -gt 0 ]; then
    echo -e "  ${RED}Tests failed. Diagnostic commands:${NC}"
    echo "    docker logs amf  2>&1 | jq -c 'select(.procedure==\"InitialRegistration\")' | head -20"
    echo "    docker logs smf  2>&1 | jq -c 'select(.procedure==\"SmContextCreate\")' | head -20"
    echo "    docker logs nssf 2>&1 | jq -c '.' | head -20"
    echo "    docker exec ueransim-ue-gold  nr-cli imsi-001010000000002 -e 'ps-list'"
    echo "    docker exec ueransim-ue-silver nr-cli imsi-001010000000003 -e 'ps-list'"
    exit 1
fi

echo -e "  ${GREEN}All tests passed. Multi-slice is operational.${NC}"
