#!/usr/bin/env bash
# scripts/ueransim-status.sh
# Read-only status summary of every UERANSIM scenario (make ueransim-status).
#
#   1. Container state of each UERANSIM service, grouped by scenario
#      (default / multi-slice / SUCI Profile A).
#   2. gNBs registered at the AMF (AMF management API GET /amf/v1/ran/gnbs,
#      plain HTTP :9002) — gNB-ID, name, state, SCTP peer, UE counts.
#   3. Per-gNB NGAP state and per-UE RM/CM/MM state + PDU sessions via nr-cli.
#
# Never starts, stops or restarts anything. Always exits 0 (it is a report).
#
# Never hangs: every docker exec / nr-cli / curl call is time-bounded (STATUS_CMD_TIMEOUT
# seconds, default 8) — nr-cli blocks while a UE/gNB is (re)starting. Portable to macOS
# bash 3.2 + BSD userland (helpers in scripts/lib/common.sh).
#
# Env:
#   AMF_MGMT  AMF management base URL (default: http://localhost:<host port published
#             for amf:9002>, i.e. http://localhost:9002). The AMF image is distroless,
#             so there is no in-container curl fallback.
#   STATUS_CMD_TIMEOUT  per-command limit in seconds (default 8).
#
# Ref: TS 38.413 §8.7.1 (NG Setup), TS 24.501 §5.1.3 (5GMM states).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

T="${STATUS_CMD_TIMEOUT:-8}"

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; NC='\033[0m'

section() { echo -e "\n${BOLD}${CYAN}━━ $1 ━━${NC}"; }

# scenario|container|role  (role: gnb | ue)
SERVICES=(
    "default|ueransim-gnb|gnb"
    "default|ueransim-ue|ue"
    "multi-slice|ueransim-gnb-ms|gnb"
    "multi-slice|ueransim-ue-internet|ue"
    "multi-slice|ueransim-ue-gold|ue"
    "multi-slice|ueransim-ue-silver|ue"
    "multi-slice|ueransim-ue-bronze|ue"
    "suci-profile-a|ueransim-ue-profile-a|ue"
)

container_state() {
    local st
    st=$(docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null) || st="absent"
    printf '%s' "$st"
}

colour_state() {
    case "$1" in
        running) printf "${GREEN}%-10s${NC}" "$1" ;;
        absent)  printf "${YELLOW}%-10s${NC}" "$1" ;;
        *)       printf "${RED}%-10s${NC}" "$1" ;;
    esac
}

if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found on PATH" >&2
    exit 0
fi

if [ -z "${AMF_MGMT:-}" ]; then
    _amf_port=$(published_port amf 9002)
    AMF_MGMT="http://localhost:${_amf_port:-9002}"
fi

# nrc CONTAINER NR-CLI-ARGS... — time-bounded nr-cli (empty output on error); prints
# "timeout" when it did not answer within $T seconds (see nr_cli_bounded).
nrc() {
    local rc=0
    nr_cli_bounded "$T" "$@" 2>/dev/null || rc=$?
    [ "$rc" -eq 124 ] && echo "timeout"
    return 0
}

echo -e "${BOLD}UERANSIM status — $(date '+%Y-%m-%d %H:%M:%S')${NC}"

# ─────────────────────────────────────────────────────────────────────────────
section "Containers"
# ─────────────────────────────────────────────────────────────────────────────
printf "  %-16s %-24s %-5s %s\n" "SCENARIO" "CONTAINER" "ROLE" "STATE"
# Space-separated lists (not arrays: bash 3.2 + set -u errors on "${empty[@]}").
RUNNING_GNBS=""; RUNNING_UES=""
for entry in "${SERVICES[@]}"; do
    IFS='|' read -r scen ctr role <<<"$entry"
    st=$(container_state "$ctr")
    printf "  %-16s %-24s %-5s " "$scen" "$ctr" "$role"; colour_state "$st"; echo
    if [ "$st" = "running" ]; then
        if [ "$role" = "gnb" ]; then RUNNING_GNBS="$RUNNING_GNBS $ctr"; else RUNNING_UES="$RUNNING_UES $ctr"; fi
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "AMF gNB registry (GET /amf/v1/ran/gnbs)"
# ─────────────────────────────────────────────────────────────────────────────
GNBS_JSON=$(curl -s --max-time 3 "$AMF_MGMT/amf/v1/ran/gnbs" 2>/dev/null || true)
if [ -z "$GNBS_JSON" ]; then
    echo -e "  ${YELLOW}AMF management API unreachable at $AMF_MGMT (is the core up? amf:9002 published?)${NC}"
elif command -v python3 >/dev/null 2>&1; then
    printf '%s' "$GNBS_JSON" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception as e:
    print("  could not parse AMF response:", e); sys.exit(0)
gnbs = d.get("gnbs") or []
if not gnbs:
    print("  no gNB registered"); sys.exit(0)
print("  %-10s %-26s %-13s %-34s %s" % ("GNB-ID", "RAN-NODE-NAME", "STATE", "SCTP-PEER", "UEs(conn/idle)"))
dup = {}
for g in gnbs:
    rn = g.get("ran_node") or {}
    gid = rn.get("gnb_id_hex") or str(rn.get("gnb_id", "?"))
    sc = g.get("sctp") or {}
    peer = ",".join(sc.get("remote_addrs") or []) + (":%s" % sc.get("remote_port") if sc.get("remote_port") else "")
    ues = g.get("ues") or {}
    st = g.get("state", "?")
    if st != "DISCONNECTED":
        dup[gid] = dup.get(gid, 0) + 1
    print("  %-10s %-26s %-13s %-34s %s/%s" % (gid, (g.get("ran_node_name") or "-")[:26], st, peer[:34],
          ues.get("connected", 0), ues.get("idle", 0)))
ready = sum(1 for g in gnbs if g.get("state") == "NG_READY")
print("  NG_READY: %d" % ready)
for gid, n in dup.items():
    if n > 1:
        print("  WARNING: gNB-ID %s registered %d times (duplicate NCI/gNB-ID)" % (gid, n))
'
else
    echo "  (python3 not found — raw response)"
    echo "  $GNBS_JSON"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "gNB NGAP state (nr-cli)"
# ─────────────────────────────────────────────────────────────────────────────
if [ -z "$RUNNING_GNBS" ]; then
    echo "  no UERANSIM gNB running"
fi
for ctr in $RUNNING_GNBS; do
    dump=$(nrc "$ctr" --dump)
    node=$(awk 'NR == 1 { print $1 }' <<<"$dump")
    if [ -z "$node" ] || [ "$node" = "timeout" ]; then
        echo -e "  $ctr: ${YELLOW}nr-cli --dump returned no node (timeout ${T}s or still starting)${NC}"
        continue
    fi
    st=$(nrc "$ctr" "$node" -e status)
    ngap=$(awk -F': *' '/is-ngap-up/ {print $2}' <<<"$st")
    [ -z "$ngap" ] && [ "$st" = "timeout" ] && ngap="? (nr-cli status timed out after ${T}s)"
    printf "  %-24s node=%-28s is-ngap-up=%s\n" "$ctr" "$node" "${ngap:-?}"
done

# ─────────────────────────────────────────────────────────────────────────────
section "UEs (nr-cli status / ps-list)"
# ─────────────────────────────────────────────────────────────────────────────
if [ -z "$RUNNING_UES" ]; then
    echo "  no UERANSIM UE running"
else
    printf "  %-22s %-20s %-14s %-14s %-30s %s\n" "CONTAINER" "SUPI" "RM" "CM" "MM" "PDU(active: addresses)"
fi
for ctr in $RUNNING_UES; do
    imsis=$(nrc "$ctr" --dump)
    if [ -z "$imsis" ] || [ "$imsis" = "timeout" ]; then
        printf "  %-22s ${YELLOW}%s${NC}\n" "$ctr" "nr-cli --dump returned no UE (timeout ${T}s or still starting)"
        continue
    fi
    for imsi in $imsis; do
        st=$(nrc "$ctr" "$imsi" -e status)
        if [ "$st" = "timeout" ]; then
            # Don't stack more timeouts on a wedged nr-cli (worst case stays bounded).
            printf "  %-22s %-20s ${YELLOW}%s${NC}\n" "$ctr" "$imsi" "nr-cli status timed out after ${T}s"
            continue
        fi
        rm=$(awk -F': *' '/^rm-state/ {print $2}' <<<"$st")
        cm=$(awk -F': *' '/^cm-state/ {print $2}' <<<"$st")
        mm=$(awk -F': *' '/^mm-state/ {print $2}' <<<"$st")
        ps=$(nrc "$ctr" "$imsi" -e ps-list)
        active=$(grep -c 'state: PS-ACTIVE' <<<"$ps" || true)
        addrs=$(awk -F': *' '/address:/ {print $2}' <<<"$ps" | paste -sd, -)
        printf "  %-22s %-20s %-14s %-14s %-30s %s\n" "$ctr" "$imsi" "${rm:-?}" "${cm:-?}" "${mm:-?}" \
            "${active}${addrs:+: $addrs}"
    done
done

echo
echo "Validate: make test-slices · make validate-ursp · make ueransim-mod-e2e"
exit 0
