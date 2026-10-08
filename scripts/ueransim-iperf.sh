#!/usr/bin/env bash
# scripts/ueransim-iperf.sh
# Per-UE user-plane performance test (make ueransim-iperf) — backlog UERAN-002.
#
# For every running UERANSIM UE container and every PDU session with an IPv4
# address, runs iperf3 bound to the session's uesimtunN address toward a
# throw-away iperf3 server on the N6 data network behind the UPF:
#
#   UE uesimtunN --GTP-U/N3--> gNB --> UPF (upfgtpN, MASQUERADE) --N6--> iperf3 -s
#
#   - TCP UL, TCP DL (-R), UDP UL and UDP DL (-R) at IPERF_UDP_BW.
#   - Binding to the tun IP (-B) forces the tun path: UERANSIM installs the
#     policy rule `from <tun ip> lookup rt_uesimtunN` (default dev uesimtunN).
#   - Path proof: the UPF masquerades UE-pool traffic leaving N6, so every
#     connection the server accepts must come from the UPF's N6 address. Any
#     other peer means the traffic bypassed the UPF and the run FAILS.
#
# Servers are NOT compose services: one `docker run --rm -d` container per N6
# bridge (5gc-n6 for the internet/default DNNs, 5gc-n6-ims for the ims DNN),
# always removed on exit (trap). Read-only for the dataplane: nothing in the
# UPF/SMF/compose is touched — it only measures.
#
# Env:
#   IPERF_DURATION   seconds per individual run          (default 5)
#   IPERF_MIN_MBPS   min TCP UL/DL Mbps per session      (default 1)
#   IPERF_UDP_BW     UDP target bitrate (iperf3 -b)      (default 10M)
#   IPERF_MAX_LOSS   max UDP loss % (empty = no check)   (default empty)
#   UES              UE containers, space/comma separated (default: every
#                    running container named ueransim-ue*)
#   IPERF_CLIENT     netshoot = throw-away container sharing the UE netns
#                    (default; works with UE images that predate iperf3);
#                    image = `docker exec <ue> iperf3` (needs the rebuilt image)
#   IPERF_IMAGE      image for servers / netshoot clients (default nicolaka/netshoot)
#   IPERF_JSON_DIR   keep raw iperf3 --json results here (default: temp, deleted)
#
# Exit: 0 all OK · 1 a run failed, TCP < IPERF_MIN_MBPS, loss > IPERF_MAX_LOSS,
#       path check failed or no testable session · 2 no UERANSIM UE running.
#
# Ref: TS 23.501 §5.6 (user plane / PDU sessions), TS 29.281 (GTP-U).
# Bash 3.2 compatible (macOS host): no associative arrays, no GNU timeout.

set -uo pipefail

IPERF_DURATION="${IPERF_DURATION:-5}"
IPERF_MIN_MBPS="${IPERF_MIN_MBPS:-1}"
IPERF_UDP_BW="${IPERF_UDP_BW:-10M}"
IPERF_MAX_LOSS="${IPERF_MAX_LOSS:-}"
IPERF_CLIENT="${IPERF_CLIENT:-netshoot}"
IPERF_IMAGE="${IPERF_IMAGE:-nicolaka/netshoot}"
UES="${UES:-}"

N6_NET="5gc-n6"
N6_IMS_NET="5gc-n6-ims"
UPF_CONTAINER="upf"
# Watchdog per run: iperf duration + connect/teardown slack (+ image start).
RUN_TIMEOUT=$((IPERF_DURATION + 25))

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${CYAN}[iperf]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[iperf] WARN:${NC} $*" >&2; }
err()  { echo -e "${RED}[iperf] ERROR:${NC} $*" >&2; }

for bin in docker jq awk; do
    command -v "$bin" >/dev/null 2>&1 || { err "missing dependency: $bin"; exit 1; }
done
case "$IPERF_CLIENT" in netshoot|image) ;; *) err "IPERF_CLIENT must be netshoot|image"; exit 1 ;; esac

RUN_ID="$$"
SRV_N6="ueransim-iperf-srv-n6-${RUN_ID}"
SRV_IMS="ueransim-iperf-srv-ims-${RUN_ID}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ueransim-iperf.XXXXXX")"
JSON_DIR="${IPERF_JSON_DIR:-$WORK/json}"
mkdir -p "$JSON_DIR"

cleanup() {
    docker rm -f "$SRV_N6" "$SRV_IMS" >/dev/null 2>&1 || true
    # Any client container left behind by a watchdog race.
    docker ps -aq --filter "name=ueransim-iperf-cli-${RUN_ID}-" 2>/dev/null \
        | xargs docker rm -f >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ---------------------------------------------------------------- UE discovery
if [ -n "$UES" ]; then
    UE_LIST="$(echo "$UES" | tr ',' ' ')"
else
    UE_LIST="$(docker ps --format '{{.Names}}' | grep -E '^ueransim-ue' | sort | tr '\n' ' ')"
fi
RUNNING=""
for ue in $UE_LIST; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$ue" 2>/dev/null)" = "true" ]; then
        RUNNING="$RUNNING $ue"
    else
        warn "$ue is not running — skipped"
    fi
done
if [ -z "${RUNNING// /}" ]; then
    err "no UERANSIM UE container running (start one with: make ueransim / make ueransim-all)"
    exit 2
fi

# Session table, one line per testable session:
#   container|supi|dnn|snssai|tun|ip
SESSIONS="$WORK/sessions"
: > "$SESSIONS"
for ue in $RUNNING; do
    # tun ifaces with an IPv4 address: "uesimtun0 10.60.0.3"
    if [ "$IPERF_CLIENT" = "image" ] && ! docker exec "$ue" sh -c 'command -v iperf3' >/dev/null 2>&1; then
        warn "$ue: iperf3 not in the UE image (container predates tools/ueransim/Dockerfile iperf3; rebuild with make ueransim-build-only or use IPERF_CLIENT=netshoot) — skipped"
        continue
    fi
    TUNS="$(docker exec "$ue" ip -4 -o addr show 2>/dev/null \
        | awk '$2 ~ /^uesimtun/ { split($4, a, "/"); print $2, a[1] }')"
    if [ -z "$TUNS" ]; then
        warn "$ue: no uesimtun interface with an IPv4 address — skipped"
        continue
    fi
    # address -> supi|dnn|snssai from nr-cli ps-list of every SUPI in the container.
    MAP="$WORK/map-$ue"
    : > "$MAP"
    for supi in $(docker exec "$ue" nr-cli --dump 2>/dev/null); do
        docker exec "$ue" nr-cli "$supi" -e ps-list 2>/dev/null | awk -v supi="$supi" '
            function flush() { if (addr != "") print addr "|" supi "|" (apn == "" ? "?" : apn) "|" sst (sd == "" ? "" : "/" sd) }
            /^PDU Session/ { flush(); addr = ""; apn = ""; sst = ""; sd = ""; next }
            $1 == "apn:"     { apn = $2 }
            $1 == "sst:"     { sst = $2; sub(/^0x0*/, "", sst); if (sst == "") sst = "0" }
            $1 == "sd:"      { sd = $2; sub(/^0x/, "", sd) }
            $1 == "address:" { addr = $2 }
            END { flush() }' >> "$MAP"
    done
    echo "$TUNS" | while read -r tun ip; do
        [ -n "$ip" ] || continue
        line="$(awk -F'|' -v ip="$ip" '$1 == ip { print; exit }' "$MAP")"
        if [ -n "$line" ]; then
            supi="$(echo "$line" | cut -d'|' -f2)"
            dnn="$(echo "$line" | cut -d'|' -f3)"
            snssai="$(echo "$line" | cut -d'|' -f4)"
        else
            supi="?"; dnn="?"; snssai="?"
            warn "$ue: $tun ($ip) not found in nr-cli ps-list (stale tun?) — testing anyway on $N6_NET"
        fi
        echo "$ue|$supi|$dnn|$snssai|$tun|$ip" >> "$SESSIONS"
    done
done
if [ ! -s "$SESSIONS" ]; then
    err "no testable session: no running UE has a PDU session with an IPv4 uesimtun address (see warnings above)"
    exit 1
fi

# ------------------------------------------------------------------- servers
container_ip() {  # container network
    docker inspect -f "{{with index .NetworkSettings.Networks \"$2\"}}{{.IPAddress}}{{end}}" "$1" 2>/dev/null
}

start_server() {  # name network -> prints server IP
    local name="$1" net="$2" ip i
    docker run --rm -d --name "$name" --network "$net" "$IPERF_IMAGE" iperf3 -s --forceflush >/dev/null 2>&1 || return 1
    for i in 1 2 3 4 5 6 7 8 9 10; do
        ip="$(container_ip "$name" "$net")"
        if [ -n "$ip" ] && docker logs "$name" 2>&1 | grep -q 'Server listening'; then
            echo "$ip"; return 0
        fi
        sleep 0.5
    done
    return 1
}

need_ims=0
awk -F'|' '$3 == "ims" { f = 1 } END { exit !f }' "$SESSIONS" && need_ims=1

docker network inspect "$N6_NET" >/dev/null 2>&1 || { err "docker network $N6_NET not found (core not up?)"; exit 1; }
SRV_N6_IP="$(start_server "$SRV_N6" "$N6_NET")" || { err "cannot start iperf3 server on $N6_NET"; exit 1; }
UPF_N6_IP="$(container_ip "$UPF_CONTAINER" "$N6_NET")"
log "iperf3 server on $N6_NET: $SRV_N6_IP (UPF N6: ${UPF_N6_IP:-?})"

SRV_IMS_IP=""; UPF_IMS_IP=""
if [ "$need_ims" = 1 ]; then
    if docker network inspect "$N6_IMS_NET" >/dev/null 2>&1 \
        && SRV_IMS_IP="$(start_server "$SRV_IMS" "$N6_IMS_NET")"; then
        UPF_IMS_IP="$(container_ip "$UPF_CONTAINER" "$N6_IMS_NET")"
        log "iperf3 server on $N6_IMS_NET: $SRV_IMS_IP (UPF N6-ims: ${UPF_IMS_IP:-?})"
    else
        warn "no iperf3 server on $N6_IMS_NET — ims sessions will use $N6_NET"
        SRV_IMS_IP=""
    fi
fi

# ------------------------------------------------------------------- clients
# run_iperf ue tun_ip server_ip outfile [iperf3 args...] — returns 0 if a JSON
# result without .error was produced. Watchdog kills runs over RUN_TIMEOUT.
CLI_SEQ=0
run_iperf() {
    local ue="$1" bind="$2" srv="$3" out="$4" wd rc attempt name
    shift 4
    for attempt in 1 2 3; do
        CLI_SEQ=$((CLI_SEQ + 1))
        name="ueransim-iperf-cli-${RUN_ID}-${CLI_SEQ}"
        if [ "$IPERF_CLIENT" = "netshoot" ]; then
            docker run --rm --name "$name" --network "container:$ue" "$IPERF_IMAGE" \
                iperf3 -c "$srv" -B "$bind" -t "$IPERF_DURATION" --connect-timeout 5000 -J "$@" \
                > "$out" 2>"$out.err" &
            rc=$!
            ( sleep "$RUN_TIMEOUT"; docker rm -f "$name" >/dev/null 2>&1 ) &
        else
            docker exec "$ue" iperf3 -c "$srv" -B "$bind" -t "$IPERF_DURATION" --connect-timeout 5000 -J "$@" \
                > "$out" 2>"$out.err" &
            rc=$!
            ( sleep "$RUN_TIMEOUT"; docker exec "$ue" pkill -f "iperf3 -c $srv -B $bind" >/dev/null 2>&1 ) &
        fi
        wd=$!
        wait "$rc"
        kill "$wd" 2>/dev/null; wait "$wd" 2>/dev/null
        if jq -e '.end and (.error == null)' "$out" >/dev/null 2>&1; then
            return 0
        fi
        # Server still busy with the previous test: back off and retry.
        if grep -qi 'busy' "$out" "$out.err" 2>/dev/null; then sleep 2; continue; fi
        return 1
    done
    return 1
}

run_error() {  # outfile -> short error text
    local e
    e="$(jq -r '.error // empty' "$1" 2>/dev/null)"
    [ -n "$e" ] || e="$(cat "$1.err" "$1" 2>/dev/null | tr '\n' ' ' | cut -c1-120)"
    [ -n "$e" ] || e="no result (watchdog timeout ${RUN_TIMEOUT}s?)"
    echo "$e"
}

# iperf3 >= 3.11 reports the receiver side in .end.sum_received; 3.9 (the
# Ubuntu 22.04 UE image) only has .end.sum for UDP (with server-side loss/jitter).
mbps_tcp() { jq -r '(.end.sum_received // .end.sum).bits_per_second / 1e6 | . * 100 | round / 100' "$1" 2>/dev/null; }
udp_fields() {  # -> "mbps loss jitter"
    jq -r '(.end.sum_received // .end.sum) | "\(.bits_per_second / 1e6 * 100 | round / 100) \(.lost_percent * 100 | round / 100) \(.jitter_ms * 1000 | round / 1000)"' "$1"
}
lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 < b + 0) }'; }

RESULTS="$WORK/results"
FAILS="$WORK/fails"
: > "$RESULTS"; : > "$FAILS"
N_SESS="$(wc -l < "$SESSIONS" | tr -d ' ')"
log "testing $N_SESS session(s): ${IPERF_DURATION}s per run, UDP ${IPERF_UDP_BW}, min TCP ${IPERF_MIN_MBPS} Mbps, client=${IPERF_CLIENT}"

idx=0
while IFS='|' read -r ue supi dnn snssai tun ip; do
    idx=$((idx + 1))
    srv="$SRV_N6_IP"
    [ "$dnn" = "ims" ] && [ -n "$SRV_IMS_IP" ] && srv="$SRV_IMS_IP"
    log "[$idx/$N_SESS] $ue $supi dnn=$dnn $tun $ip -> $srv"
    base="$JSON_DIR/${ue}_${tun}"
    tcp_ul="FAIL"; tcp_dl="FAIL"; udp_ul="FAIL - -"; udp_dl="FAIL - -"
    if run_iperf "$ue" "$ip" "$srv" "$base.tcp-ul.json" </dev/null; then
        tcp_ul="$(mbps_tcp "$base.tcp-ul.json")"; [ -n "$tcp_ul" ] || tcp_ul="FAIL"
        [ "$tcp_ul" = "FAIL" ] && echo "$ue $tun: TCP UL: unparsable iperf3 JSON" >> "$FAILS"
        [ "$tcp_ul" != "FAIL" ] && lt "$tcp_ul" "$IPERF_MIN_MBPS" && echo "$ue $tun: TCP UL $tcp_ul Mbps < $IPERF_MIN_MBPS" >> "$FAILS"
    else
        echo "$ue $tun: TCP UL failed: $(run_error "$base.tcp-ul.json")" >> "$FAILS"
    fi
    if run_iperf "$ue" "$ip" "$srv" "$base.tcp-dl.json" -R </dev/null; then
        tcp_dl="$(mbps_tcp "$base.tcp-dl.json")"; [ -n "$tcp_dl" ] || tcp_dl="FAIL"
        [ "$tcp_dl" = "FAIL" ] && echo "$ue $tun: TCP DL: unparsable iperf3 JSON" >> "$FAILS"
        [ "$tcp_dl" != "FAIL" ] && lt "$tcp_dl" "$IPERF_MIN_MBPS" && echo "$ue $tun: TCP DL $tcp_dl Mbps < $IPERF_MIN_MBPS" >> "$FAILS"
    else
        echo "$ue $tun: TCP DL failed: $(run_error "$base.tcp-dl.json")" >> "$FAILS"
    fi
    if run_iperf "$ue" "$ip" "$srv" "$base.udp-ul.json" -u -b "$IPERF_UDP_BW" </dev/null; then
        udp_ul="$(udp_fields "$base.udp-ul.json")"
        [ -n "$udp_ul" ] || { udp_ul="FAIL - -"; echo "$ue $tun: UDP UL: unparsable iperf3 JSON" >> "$FAILS"; }
    else
        echo "$ue $tun: UDP UL failed: $(run_error "$base.udp-ul.json")" >> "$FAILS"
    fi
    if run_iperf "$ue" "$ip" "$srv" "$base.udp-dl.json" -u -b "$IPERF_UDP_BW" -R </dev/null; then
        udp_dl="$(udp_fields "$base.udp-dl.json")"
        [ -n "$udp_dl" ] || { udp_dl="FAIL - -"; echo "$ue $tun: UDP DL: unparsable iperf3 JSON" >> "$FAILS"; }
    else
        echo "$ue $tun: UDP DL failed: $(run_error "$base.udp-dl.json")" >> "$FAILS"
    fi
    if [ -n "$IPERF_MAX_LOSS" ]; then
        for pair in "UL:$udp_ul" "DL:$udp_dl"; do
            dir="${pair%%:*}"; loss="$(echo "${pair#*:}" | awk '{print $2}')"
            [ "$loss" = "-" ] && continue
            lt "$IPERF_MAX_LOSS" "$loss" && echo "$ue $tun: UDP $dir loss $loss% > $IPERF_MAX_LOSS%" >> "$FAILS"
        done
    fi
    echo "$ue|$supi|$dnn|$snssai|$tun|$ip|$tcp_ul|$tcp_dl|$udp_ul|$udp_dl" >> "$RESULTS"
done < "$SESSIONS"

# ---------------------------------------------------------------- path check
# Every connection a server accepted must come from the UPF's N6 address
# (UPF MASQUERADE of the UE pool) — proves the traffic crossed the UPF.
path_check() {  # server_name upf_ip net
    local peers bad
    peers="$(docker logs "$1" 2>&1 | awk '/Accepted connection from/ { sub(/,$/, "", $4); print $4 }' | sort -u | tr '\n' ' ')"
    log "$3 server accepted connections from: ${peers:-none}"
    for p in $peers; do
        if [ -n "$2" ] && [ "$p" != "$2" ]; then bad="$bad $p"; fi
    done
    if [ -n "${bad:-}" ]; then
        echo "path check $3: peer(s)$bad are not the UPF N6 address $2 — traffic bypassed the UPF" >> "$FAILS"
    fi
}
path_check "$SRV_N6" "$UPF_N6_IP" "$N6_NET"
[ -n "$SRV_IMS_IP" ] && path_check "$SRV_IMS" "$UPF_IMS_IP" "$N6_IMS_NET"

# --------------------------------------------------------------------- report
echo
echo -e "${BOLD}━━ UERANSIM per-UE iperf3 report (${IPERF_DURATION}s/run, UDP ${IPERF_UDP_BW}) ━━${NC}"
{
    echo "CONTAINER|SUPI|DNN|S-NSSAI|TUN|IP|TCP_UL_Mbps|TCP_DL_Mbps|UDP_UL_Mbps|UL_loss%|UL_jit_ms|UDP_DL_Mbps|DL_loss%|DL_jit_ms"
    # UDP columns hold "mbps loss jitter" — split them, "-" for missing.
    awk -F'|' '{
        nu = split($9, u, " "); nd = split($10, d, " ")
        for (i = nu + 1; i <= 3; i++) u[i] = "-"
        for (i = nd + 1; i <= 3; i++) d[i] = "-"
        print $1 "|" $2 "|" $3 "|" $4 "|" $5 "|" $6 "|" $7 "|" $8 "|" u[1] "|" u[2] "|" u[3] "|" d[1] "|" d[2] "|" d[3]
    }' "$RESULTS"
} | column -t -s '|'
echo

if [ -s "$FAILS" ]; then
    echo -e "${RED}${BOLD}FAIL${NC} ($(wc -l < "$FAILS" | tr -d ' ') issue(s)):"
    sed 's/^/  - /' "$FAILS"
    [ -n "${IPERF_JSON_DIR:-}" ] && echo "Raw iperf3 JSON: $JSON_DIR"
    exit 1
fi
echo -e "${GREEN}${BOLD}PASS${NC}: $N_SESS session(s), every TCP run >= ${IPERF_MIN_MBPS} Mbps, all traffic via the UPF N6 address"
[ -n "${IPERF_JSON_DIR:-}" ] && echo "Raw iperf3 JSON: $JSON_DIR"
exit 0
