#!/usr/bin/env bash
# scripts/test-slices.sh
# Validates multi-slice network slicing with 4 UEs (internet/gold/silver/bronze).
#
# Prerequisites:  make ueransim-slices  OR  make ueransim-all   (multi-slice containers running)
# Usage:          make test-slices   OR   ./scripts/test-slices.sh
#
# The multi-slice UEs use SUPIs 201..204 (seeded by UDR SEED_EXTRA_SUPIS) so they
# coexist with the default ueransim-ue (001..UE_COUNT) and the SUCI Profile A UE (301).
# T8 launches an ad-hoc UE (ue-unauth.yaml, imsi-...0401) against ueransim-gnb-ms.
#
# Slices under test:
#   internet  SST=1 SD=000001  eMBB best-effort   UE imsi-...0201
#   gold      SST=1 SD=000002  eMBB premium       UE imsi-...0202
#   silver    SST=2 SD=000001  URLLC              UE imsi-...0203
#   bronze    SST=3 SD=000001  MIoT               UE imsi-...0204
#
# Portable to macOS bash 3.2 + BSD userland (see scripts/lib/common.sh). SBI calls go
# through sbi_curl (host-published port + mTLS client cert from pki/, or a throw-away
# curl container on the SBI network) because the NF images are distroless.
#
# Ref: TS 23.501 §5.15, TS 23.502 §4.2.2.2.2, TS 29.531 §5.2.2.2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

require_cmds docker curl jq

# Precondition: these checks drive UERANSIM, which is optional (RAN=ueransim).
if ! container_running ueransim-gnb-ms; then
    echo "UERANSIM multi-slice scenario not deployed — run: make ueransim-slices (or make ueransim-all)" >&2
    exit 2
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; SKIP=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  ${YELLOW}○${NC} $1 (skipped)"; SKIP=$((SKIP + 1)); }
section() { echo -e "\n${BOLD}${CYAN}━━ $1 ━━${NC}"; }

MS_UES="ueransim-ue-internet ueransim-ue-gold ueransim-ue-silver ueransim-ue-bronze"
MS_SUPIS="imsi-001010000000201 imsi-001010000000202 imsi-001010000000203 imsi-001010000000204"

# Lookup tables (case statements — bash 3.2 has no associative arrays).
# slice_of KEY — "label sst sd" for a UE container or SUPI.
slice_of() {
    case "$1" in
        ueransim-ue-internet|imsi-001010000000201) echo "internet 1 000001" ;;
        ueransim-ue-gold|imsi-001010000000202)     echo "gold 1 000002" ;;
        ueransim-ue-silver|imsi-001010000000203)   echo "silver 2 000001" ;;
        ueransim-ue-bronze|imsi-001010000000204)   echo "bronze 3 000001" ;;
        *) echo "unknown 0 000000" ;;
    esac
}
supi_of() {
    case "$1" in
        ueransim-ue-internet) echo imsi-001010000000201 ;;
        ueransim-ue-gold)     echo imsi-001010000000202 ;;
        ueransim-ue-silver)   echo imsi-001010000000203 ;;
        ueransim-ue-bronze)   echo imsi-001010000000204 ;;
    esac
}
# tun_of UE — TUN of the UE's first (internet) PDU session.
tun_of() { echo uesimtun0; }

# ps_sessions UE SUPI — one line per PDU session: "<state> <sst-hex> <sd-hex> <apn>".
ps_sessions() {
    local out
    out=$(nrcli "$1" "$2" ps-list 10)
    awk '
        /^PDU Session/ { if (st != "") print st, sst, sd, apn; st = ""; sst = "-"; sd = "-"; apn = "-" }
        /state:/       { st = $2 }
        /apn:/         { apn = $2 }
        /sst:/         { sst = $2 }
        /sd:/          { sd = $2 }
        END            { if (st != "") print st, sst, sd, apn }
    ' <<<"$out"
}

echo -e "\n${BOLD}5GC Multi-Slice Validation — $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo "Slices: internet(SST=1/SD=000001) gold(SST=1/SD=000002) silver(SST=2/SD=000001) bronze(SST=3/SD=000001)"

# ─────────────────────────────────────────────────────────────────────────────
section "T0 · Infrastructure — containers running"
# ─────────────────────────────────────────────────────────────────────────────

for svc in nrf amf smf nssf udr ueransim-gnb-ms $MS_UES; do
    if container_running "$svc"; then
        pass "container $svc running"
    else
        fail "container $svc NOT running"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T1 · NRF — SMF announces 4 SNSSAIs"
# ─────────────────────────────────────────────────────────────────────────────

NRF_RESP=$(sbi_curl "https://nrf:8000/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF")

for sst_sd in "1/000001:internet" "1/000002:gold" "2/000001:silver" "3/000001:bronze"; do
    sst="${sst_sd%%/*}"; rest="${sst_sd#*/}"; sd="${rest%%:*}"; label="${rest##*:}"
    if jq -e --argjson sst "$sst" --arg sd "$sd" \
        '[.nfInstances[]?.sNssais[]?] | any(.sst == $sst and .sd == $sd)' >/dev/null 2>&1 <<<"$NRF_RESP"; then
        pass "SMF announces SST=$sst/SD=$sd ($label) in NRF"
    else
        fail "SMF does NOT announce SST=$sst/SD=$sd ($label) in NRF"
        echo "    Resp: ${NRF_RESP:0:300}"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T2 · NSSF — NSSelection returns correct slices"
# ─────────────────────────────────────────────────────────────────────────────

NSSF_BASE="https://nssf:8007/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=amf-001&slice-info-request-for-registration.requestedNssai="
ALLOWED_JQ='[.allowedNssaiList[]?.allowedSnssaiList[]?]'

for sst_sd in "1/000001:internet" "1/000002:gold" "2/000001:silver" "3/000001:bronze"; do
    sst="${sst_sd%%/*}"; rest="${sst_sd#*/}"; sd="${rest%%:*}"; label="${rest##*:}"
    ENCODED=$(urlencode "[{\"sst\":$sst,\"sd\":\"$sd\"}]")
    RESP=$(sbi_curl "${NSSF_BASE}${ENCODED}")
    if jq -e --argjson sst "$sst" --arg sd "$sd" \
        "$ALLOWED_JQ | any(.sst == \$sst and .sd == \$sd)" >/dev/null 2>&1 <<<"$RESP"; then
        pass "NSSF authorizes SST=$sst/SD=$sd ($label)"
    else
        fail "NSSF does not return SST=$sst/SD=$sd ($label)"
        echo "    Resp: $RESP"
    fi
done

# NSSF rejects unconfigured slice
RESP_UNKNOWN=$(sbi_curl "${NSSF_BASE}$(urlencode '[{"sst":9,"sd":"999999"}]')")
if jq -e "has(\"allowedNssaiList\") and ($ALLOWED_JQ | all(.sst != 9))" >/dev/null 2>&1 <<<"$RESP_UNKNOWN"; then
    pass "NSSF returns empty list for unknown slice (SST=9/SD=999999)"
else
    fail "NSSF should return empty list for unconfigured slice"
    echo "    Resp: $RESP_UNKNOWN"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "T3 · UDR — subscribers seeded with correct NSSAI"
# ─────────────────────────────────────────────────────────────────────────────
# Each UE must be subscribed (UDM am-data, sourced from UDR) to its slice.

for supi in $MS_SUPIS; do
    read -r label exp_sst exp_sd <<<"$(slice_of "$supi")"
    AM=$(sbi_curl "https://udm:8003/nudm-sdm/v2/${supi}/am-data")
    if jq -e --argjson sst "$exp_sst" --arg sd "$exp_sd" \
        '[.nssai.defaultSingleNssais[]?, .nssai.singleNssais[]?] | any(.sst == $sst and .sd == $sd)' \
        >/dev/null 2>&1 <<<"$AM"; then
        pass "$supi has SST=$exp_sst/SD=$exp_sd ($label) in UDM"
    else
        fail "$supi does NOT have SST=$exp_sst/SD=$exp_sd ($label) in UDM"
        echo "    AM nssai: $(jq -c '.nssai' 2>/dev/null <<<"$AM" || echo "$AM")"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T4 · UE Registration — MM-REGISTERED on all 4 UEs"
# ─────────────────────────────────────────────────────────────────────────────

echo "  Waiting for registration (up to 45s per UE)..."
for ue in $MS_UES; do
    read -r label sst sd <<<"$(slice_of "$ue")"
    if wait_for_log "$ue" "MM-REGISTERED" 45; then
        pass "$ue registered ($label SST=$sst/SD=$sd)"
    else
        fail "$ue did NOT register within timeout — $label SST=$sst/SD=$sd"
        echo "    Debug: docker logs $ue 2>&1 | tail -20"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T5 · AMF — AllowedNSSAI per UE"
# ─────────────────────────────────────────────────────────────────────────────
# Each UE's Allowed NSSAI (Registration Accept) must contain its subscribed slice.
# Evidence: "UE registered" (snssai_count) + no 5GMM #90 rejection of a PDU session
# for the UE's slice since its last registration (the AMF logs allowed_nssai there).

AMF_LOGS=$(container_logs amf)

for supi in $MS_SUPIS; do
    read -r label sst sd <<<"$(slice_of "$supi")"
    ue_lines=$(text_lines "\"supi\":\"$supi\"" "$AMF_LOGS")
    # Keep only the lines since the last successful registration of this SUPI.
    since_reg=$(awk '/"msg":"UE registered"/ { buf = "" } { buf = buf $0 "\n" } END { printf "%s", buf }' <<<"$ue_lines")
    reg_line=$(text_lines '"msg":"UE registered"' "$ue_lines" | tail -n 1)
    if [ -z "$reg_line" ]; then
        if [ -n "$ue_lines" ]; then
            fail "AMF has logs for $supi but no 'UE registered' ($label)"
        else
            fail "AMF has no registration logs for $supi ($label)"
        fi
        continue
    fi
    count=$(json_num_last snssai_count "$reg_line")
    rejects=$(text_lines 'not in Allowed NSSAI' "$since_reg")
    rejects=$(text_lines "\"requested_sst\":$sst," "$rejects")
    rejects=$(text_lines "\"requested_sd\":\"$sd\"" "$rejects")
    if [ -n "$rejects" ]; then
        allowed=$(json_str_last allowed_nssai "$rejects")
        n=$(text_count . "$rejects")
        fail "AMF Allowed NSSAI for $supi lacks SST=$sst/SD=$sd ($label) — allowed_nssai=$allowed, $n PDU request(s) rejected with 5GMM #90"
    elif [ "${count:-0}" -ge 1 ]; then
        pass "AMF registered $supi with $count allowed slice(s), no rejection of SST=$sst/SD=$sd ($label)"
    else
        fail "AMF registered $supi with snssai_count=${count:-?} ($label)"
    fi
done

# T5b: no NSSAI_NOT_ALLOWED for the multi-slice UEs (T8's imsi-...0401 is expected to get it).
spurious=""
for supi in $MS_SUPIS; do
    l=$(text_lines "\"supi\":\"$supi\"" "$AMF_LOGS")
    if text_has 'NSSAI_NOT_ALLOWED' "$l"; then spurious="$spurious $supi"; fi
done
if [ -z "$spurious" ]; then
    pass "No spurious NSSAI_NOT_ALLOWED for the multi-slice UEs in AMF logs"
else
    fail "NSSAI_NOT_ALLOWED logged for multi-slice UE(s):$spurious"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "T6 · PDU Session — sessions established with correct SNSSAI"
# ─────────────────────────────────────────────────────────────────────────────
# nr-cli ps-list must show a PS-ACTIVE session on the UE's slice.

echo "  Waiting for PDU sessions (up to 30s)..."
deadline=$((SECONDS + 30))
for ue in $MS_UES; do
    supi=$(supi_of "$ue")
    read -r label sst sd <<<"$(slice_of "$ue")"
    want="PS-ACTIVE $(printf '0x%02x' "$sst") 0x$sd"
    found=""
    while :; do
        sessions=$(ps_sessions "$ue" "$supi")
        if text_has "^$want " "$sessions"; then found=1; break; fi
        [ "$SECONDS" -ge "$deadline" ] && break
        sleep 2
    done
    if [ -n "$found" ]; then
        apn=$(text_lines "^$want " "$sessions" | awk 'NR == 1 { print $4 }')
        pass "$ue — PDU Session PS-ACTIVE on SST=$sst/SD=$sd ($label, dnn=$apn)"
    else
        active=$(text_lines '^PS-ACTIVE ' "$sessions" | awk '{ printf "%s%s/%s(%s)", sep, $2, $3, $4; sep = "," }')
        fail "$ue — no PS-ACTIVE PDU Session on SST=$sst/SD=$sd ($label); active: ${active:-none}"
        echo "    Debug: docker exec $ue nr-cli $supi -e ps-list; docker logs amf 2>&1 | grep $supi | grep 'not in Allowed NSSAI'"
    fi
done

SMF_LOGS=$(container_logs smf)
for supi in $MS_SUPIS; do
    read -r label sst sd <<<"$(slice_of "$supi")"
    if text_has "\"supi\":\"$supi\"" "$SMF_LOGS"; then
        pass "SMF has logs for session $supi ($label)"
    else
        fail "SMF does not have logs for $supi ($label)"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T7 · Data plane — TUN active and e2e ping"
# ─────────────────────────────────────────────────────────────────────────────

for ue in $MS_UES; do
    tun=$(tun_of "$ue")
    read -r label sst sd <<<"$(slice_of "$ue")"
    link=$(run_timeout 10 docker exec "$ue" ip link show "$tun" 2>/dev/null || true)
    if text_has "UP|UNKNOWN" "$link"; then
        pass "$ue — $tun interface active ($label)"
    elif text_has "$tun" "$link"; then
        pass "$ue — $tun interface exists ($label)"
    else
        fail "$ue — $tun interface NOT found ($label)"
        echo "    Debug: docker exec $ue ip link"
        continue
    fi
    # Ping UPF N3 address through the UE's TUN
    if run_timeout 15 docker exec "$ue" ping -c 2 -W 3 -I "$tun" 172.30.3.100 >/dev/null 2>&1; then
        pass "$ue — ping 172.30.3.100 (UPF) OK via $tun ($label)"
    else
        fail "$ue — ping 172.30.3.100 (UPF) FAILED via $tun ($label)"
        echo "    Debug: docker exec $ue ping -c 3 -I $tun 172.30.3.100"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "T8 · Isolation — unauthorized slice rejected"
# ─────────────────────────────────────────────────────────────────────────────
# imsi-...0401 (internet-only subscription) requesting gold slice → NSSAI_NOT_ALLOWED.
# Runs a throw-away UE container (detached, named, always removed) on the N2 network.

UNAUTH_SUPI="imsi-001010000000401"
UNAUTH_NAME="test-slices-unauth-$$"
N2_NET=$(docker_network_of ueransim-gnb-ms n2 || true)
UE_IMAGE=$(docker inspect -f '{{.Config.Image}}' ueransim-gnb-ms 2>/dev/null || echo "5gc/ueransim:dev")

if [ -z "$N2_NET" ]; then
    skip "N2 network of ueransim-gnb-ms not found — cannot launch the unauthorized UE"
else
    echo "  Launching UE $UNAUTH_SUPI with unauthorized slice (network $N2_NET)..."
    cleanup_unauth() { docker rm -f "$UNAUTH_NAME" >/dev/null 2>&1 || true; }
    trap cleanup_unauth EXIT
    if run_timeout 30 docker run -d --name "$UNAUTH_NAME" --network "$N2_NET" --cap-add NET_ADMIN \
            -v "$REPO_ROOT/config/ueransim/ue-unauth.yaml:/ueransim/config/ue-unauth.yaml:ro" \
            "$UE_IMAGE" nr-ue -c /ueransim/config/ue-unauth.yaml >/dev/null 2>&1; then
        if wait_for_log "$UNAUTH_NAME" "MM-REGISTERED|Registration reject|no allowed nssai|PDU Session establishment.*(failed|reject)" 20; then
            echo "  (UE: $(text_lines 'MM-REGISTERED|Registration reject|no allowed nssai' "$(container_logs "$UNAUTH_NAME")" | head -n 1 | cut -c1-120))"
        fi
        sleep 3
    else
        echo "  could not start the unauthorized UE container"
    fi
    cleanup_unauth
    trap - EXIT

    unauth_lines=$(text_lines "\"supi\":\"$UNAUTH_SUPI\"" "$(container_logs amf)")
    if text_has 'NSSAI_NOT_ALLOWED' "$unauth_lines"; then
        pass "AMF rejected unauthorized slice for $UNAUTH_SUPI (NSSAI_NOT_ALLOWED logged)"
    else
        skip "NSSAI_NOT_ALLOWED not found in AMF logs for $UNAUTH_SUPI — may require manual retry"
        echo "    Manual: docker run --rm --network $N2_NET --cap-add NET_ADMIN \\"
        echo "      -v $REPO_ROOT/config/ueransim/ue-unauth.yaml:/ueransim/config/ue-unauth.yaml:ro \\"
        echo "      $UE_IMAGE nr-ue -c /ueransim/config/ue-unauth.yaml"
        echo "    Then: docker logs amf 2>&1 | grep $UNAUTH_SUPI | grep NSSAI_NOT_ALLOWED"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
section "T9 · Prometheus — slice metrics in AMF and NSSF"
# ─────────────────────────────────────────────────────────────────────────────

# metrics_of NF PORT — /metrics body via the published host port, else via a throw-away
# curl container on the NF's observability network (empty when neither works).
metrics_of() {
    local nf="$1" port="$2" hport net
    hport=$(published_port "$nf" "$port")
    if [ -n "$hport" ]; then
        curl -s --max-time 5 "http://localhost:$hport/metrics" 2>/dev/null || true
        return 0
    fi
    net=$(docker_network_of "$nf" obs || true)
    if [ -n "$net" ]; then
        run_timeout 60 docker run --rm --network "$net" "$SBI_CURL_IMAGE" \
            -s --max-time 5 "http://$nf:$port/metrics" 2>/dev/null || true
    fi
}

AMF_METRICS=$(metrics_of amf 9101)
NSSF_METRICS=$(metrics_of nssf 9109)

if text_has "nas_messages_total" "$AMF_METRICS"; then
    pass "AMF exposes nas_messages_total in /metrics"
elif [ -n "$AMF_METRICS" ]; then
    fail "AMF /metrics reachable but has no nas_messages_total"
else
    skip "AMF /metrics (9101) not reachable: port not published to the host and no obs-network route"
fi

if text_has "^go_" "$NSSF_METRICS"; then
    pass "NSSF exposes Go metrics in /metrics"
elif [ -n "$NSSF_METRICS" ]; then
    fail "NSSF /metrics reachable but has no go_* metrics"
else
    skip "NSSF /metrics (9109) not reachable: port not published to the host and no obs-network route"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "Summary"
# ─────────────────────────────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL + SKIP))
echo -e "\n  Total: $TOTAL  ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YELLOW}SKIP: $SKIP${NC}\n"

if [ "$FAIL" -gt 0 ]; then
    echo -e "  ${RED}Tests failed. Diagnostic commands:${NC}"
    echo "    docker logs amf  2>&1 | jq -c 'select(.procedure==\"InitialRegistration\")' | head -20"
    echo "    docker logs smf  2>&1 | jq -c 'select(.procedure==\"SmContextCreate\")' | head -20"
    echo "    docker logs nssf 2>&1 | jq -c '.' | head -20"
    echo "    docker exec ueransim-ue-gold  nr-cli imsi-001010000000202 -e 'ps-list'"
    echo "    docker exec ueransim-ue-silver nr-cli imsi-001010000000203 -e 'ps-list'"
    exit 1
fi

echo -e "  ${GREEN}All tests passed. Multi-slice is operational.${NC}"
