#!/usr/bin/env bash
# scripts/perf/upf-perf-matrix.sh — UE-bound throughput matrix through the UPF (Objectives 2 and 3).
#   UE uesimtunN --N3--> gNB --> UPF --N6--> target (public internet | iperf3-dn | iperf3-upf-local)
# Usage: upf-perf-matrix.sh --target public|dn|upf-local [--server host:port] [--ues N] [--multi "1 2 4"]
#        [--reps R] [--duration S] [--pcap] [--cases "tcp-p1 tcp-p1-R ..."] [--dry-run]
# Output: .tmp/perf/<run>/ (iperf JSON per case, snap-*.txt counters, stats.jsonl, results.csv).
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

TARGET=""; SERVER=""; UES=1; MULTI=""; REPS=3; DUR=20; PCAP=0; DRY=0; ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="$2"; shift ;; --server) SERVER="$2"; shift ;; --ues) UES="$2"; shift ;;
        --multi) MULTI="$2"; shift ;; --reps) REPS="$2"; shift ;; --duration) DUR="$2"; shift ;;
        --pcap) PCAP=1 ;; --cases) ONLY="$2"; shift ;; --dry-run) DRY=1 ;;
        *) echo "unknown arg $1" >&2; exit 2 ;;
    esac; shift
done
case "$TARGET" in public|dn|upf-local) ;; *) echo "--target public|dn|upf-local required" >&2; exit 2 ;; esac
require_cmds docker jq awk

# target -> server ip and base port (one port per concurrent UE: iperf3 serves one test at a time)
case "$TARGET" in
    dn)        SRV_IP=172.30.6.50;  BASE_PORT=5201 ;;
    upf-local) SRV_IP=10.60.0.254;  BASE_PORT=5301 ;;
    public)    [ -n "$SERVER" ] || { echo "--server host:port required for public" >&2; exit 2; }
               SRV_IP="${SERVER%:*}"; BASE_PORT="${SERVER#*:}" ;;
esac

CASES="tcp-p1|-P 1
tcp-p1-R|-P 1 -R
tcp-p4|-P 4
tcp-p4-R|-P 4 -R
tcp-p8|-P 8
tcp-p8-R|-P 8 -R
udp-100M|-u -b 100M -l 1200
udp-100M-R|-u -b 100M -l 1200 -R
udp-200M|-u -b 200M -l 1200
udp-200M-R|-u -b 200M -l 1200 -R
udp-400M|-u -b 400M -l 1200
udp-400M-R|-u -b 400M -l 1200 -R"
if [ -n "$ONLY" ]; then
    CASES="$(echo "$CASES" | awk -F'|' -v only=" $ONLY " 'index(only, " " $1 " ")')"
fi

ALL="$(perf_discover_sessions)"
[ -n "$ALL" ] || { echo "no UE with a uesimtun IPv4 address (make ueransim UE_COUNT=N)" >&2; exit 2; }
RUN="$(perf_new_run "ue-$TARGET")"; perf_env_manifest "$RUN"
echo "$ALL" > "$RUN/sessions.txt"
echo "case,mbps,retrans,loss_pct,jitter_ms,cpu_local,cpu_remote,ues,ue,rep" > "$RUN/results.csv"
COUNTS="${MULTI:-$UES}"

# one_client <ue> <ip> <port> <outfile> <iperf args...>
one_client() {
    local ue="$1" ip="$2" port="$3" out="$4"; shift 4
    # shellcheck disable=SC2086
    docker run --rm --network "container:$ue" "$PERF_IMAGE" iperf3 -c "$SRV_IP" -p "$port" -B "$ip" \
        -t "$DUR" --connect-timeout 5000 -J "$@" > "$out" 2>"$out.err" </dev/null
}

for n in $COUNTS; do
  SEL="$(echo "$ALL" | head -n "$n")"
  got="$(echo "$SEL" | wc -l | tr -d ' ')"
  [ "$got" -ge "$n" ] || { echo "only $got sessions, need $n (make ueransim UE_COUNT=$n)" >&2; continue; }
  echo "$CASES" | while IFS='|' read -r name args; do
    r=1
    while [ "$r" -le "$REPS" ]; do
      tag="n${n}_${name}_r${r}"
      if [ "$DRY" = 1 ]; then echo "plan: $TARGET ues=$n $name rep$r ($SRV_IP)"; r=$((r+1)); continue; fi
      perf_snap "$RUN" "$tag-before"; perf_stats_start "$RUN" upf ueransim-gnb $(echo "$SEL" | cut -d'|' -f1 | sort -u)
      i=0; pids=""
      for s in $(echo "$SEL"); do
          ue="${s%%|*}"; ip="${s##*|}"; port=$((BASE_PORT + i)); i=$((i+1))
          # shellcheck disable=SC2086
          one_client "$ue" "$ip" "$port" "$RUN/${tag}_u$i.json" $args & pids="$pids $!"
      done
      wait $pids
      perf_stats_stop; perf_snap "$RUN" "$tag-after"
      i=0
      for s in $(echo "$SEL"); do
          i=$((i+1)); f="$RUN/${tag}_u$i.json"
          if jq -e '.end and (.error==null)' "$f" >/dev/null 2>&1; then
              echo "$(iperf_json_to_csv "$f" "$name"),$n,$i,$r" | tr -d '"' >> "$RUN/results.csv"
          else
              plog "FAIL $tag u$i: $(jq -r '.error // empty' "$f" 2>/dev/null) $(head -c 160 "$f.err")"
              echo "$name,0,0,0,0,0,0,$n,$i,$r" >> "$RUN/results.csv"
          fi
      done
      sleep 3; r=$((r+1))
    done
  done
done
echo "$RUN"
[ "$DRY" = 1 ] || "$PERF_LIB_DIR/perf-report.sh" "$RUN" >&2
