#!/usr/bin/env bash
# scripts/perf/iperf-baseline.sh — host / Docker-NAT baseline (Objective 1b).
# Runs the TCP/UDP matrix from host, plain container and 5gc-n6 container toward validated servers.
# Usage: iperf-baseline.sh [--dry-run] [--validated FILE] [--top N] [--reps R] [--duration S]
#        [--vantages "host plain n6"] [--server host:port]...   (explicit servers skip --validated)
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

VALIDATED=""; ONLY=""; TOP=3; REPS=3; DUR=10; VANTAGES="host plain n6"; DRY=0; SERVERS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1 ;; --validated) VALIDATED="$2"; shift ;; --top) TOP="$2"; shift ;;
        --reps) REPS="$2"; shift ;; --duration) DUR="$2"; shift ;; --vantages) VANTAGES="$2"; shift ;;
        --server) SERVERS="$SERVERS $2"; shift ;; --cases) ONLY="$2"; shift ;;
        *) echo "unknown arg $1" >&2; exit 2 ;;
    esac; shift
done
require_cmds iperf3 jq docker

if [ -z "$SERVERS" ]; then
    [ -n "$VALIDATED" ] || VALIDATED="$(ls -d "$PERF_OUT_ROOT"/*-probe/validated.csv 2>/dev/null | tail -1)"
    [ -s "$VALIDATED" ] || { echo "no validated.csv — run make perf-probe first (or pass --server host:port)" >&2; exit 2; }
    # validated.csv: host,port,rtt,vantages_ok — lowest RTT first, and add the farthest one for RTT contrast
    SERVERS="$(sort -t, -k3 -n "$VALIDATED" | head -n "$TOP" | awk -F, '{print $1":"$2}' | tr '\n' ' ')"
fi

# case name | iperf3 args
CASES="tcp-p1|-P 1
tcp-p1-R|-P 1 -R
tcp-p4|-P 4
tcp-p4-R|-P 4 -R
tcp-p8|-P 8
tcp-p8-R|-P 8 -R
udp-100M|-u -b 100M -l 1200
udp-100M-R|-u -b 100M -l 1200 -R
udp-300M|-u -b 300M -l 1200
udp-300M-R|-u -b 300M -l 1200 -R"

if [ -n "$ONLY" ]; then CASES="$(echo "$CASES" | awk -F'|' -v only=" $ONLY " 'index(only, " " $1 " ")')"; fi
RUN="$(perf_new_run baseline)"; perf_env_manifest "$RUN"
echo "case,mbps,retrans,loss_pct,jitter_ms,cpu_local,cpu_remote,vantage,server,rep" > "$RUN/baseline.csv"
n=0
for srv in $SERVERS; do
  host="${srv%:*}"; port="${srv#*:}"
  for v in $VANTAGES; do
    echo "$CASES" | while IFS='|' read -r name args; do
      r=1
      while [ "$r" -le "$REPS" ]; do
        if [ "$DRY" = 1 ]; then echo "plan: $v $host:$port $name rep$r"; r=$((r+1)); continue; fi
        f="$RUN/${v}_${host}_${name}_r${r}.json"
        # shellcheck disable=SC2086
        perf_vantage_run "$v" -c "$host" -p "$port" -t "$DUR" -O 2 -J --connect-timeout 5000 $args > "$f" 2>/dev/null </dev/null
        if jq -e '.end and (.error==null)' "$f" >/dev/null 2>&1; then
            echo "$(iperf_json_to_csv "$f" "$name"),$v,$host,$r" | tr -d '"' >> "$RUN/baseline.csv"
        else
            echo "$name,0,0,0,0,0,0,$v,$host,$r  # FAIL: $(jq -r '.error // "no json"' "$f" 2>/dev/null)" >> "$RUN/baseline.csv"
            sleep 5
        fi
        sleep 3; r=$((r+1))
      done
    done
  done
done
echo "$RUN"
[ "$DRY" = 1 ] || awk -F, 'NR>1{k=$8" "$1; s[k]+=$2; c[k]++} END{for(k in s) printf "%-28s %9.1f Mb/s (n=%d)\n", k, s[k]/c[k], c[k]}' "$RUN/baseline.csv" | sort >&2
