#!/usr/bin/env bash
# scripts/perf/iperf-public-probe.sh — validate public iperf3 servers (Objective 1a).
# For each host:port: DNS -> TCP connect -> 3 s iperf3 sanity run, from three vantage points
# (host, plain container, 5gc-n6 container). Writes probe.csv + validated.txt (servers "ok" everywhere).
# Usage: iperf-public-probe.sh [--dry-run] [--servers FILE] [--ports-per-host N] [--vantages "host plain n6"]
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

SERVERS_FILE="$REPO_ROOT/config/perf/public-iperf3-servers.txt"
PORTS_PER_HOST=3; VANTAGES="host plain n6"; DRY=0; DUR=3
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1 ;; --servers) SERVERS_FILE="$2"; shift ;;
        --ports-per-host) PORTS_PER_HOST="$2"; shift ;; --vantages) VANTAGES="$2"; shift ;;
        *) echo "unknown arg $1" >&2; exit 2 ;;
    esac; shift
done
require_cmds iperf3 jq docker

# expand "5200-5209,9200" -> list of ports (first N)
expand_ports() {
    echo "$1" | tr ',' '\n' | while read -r r; do
        case "$r" in *-*) seq "${r%-*}" "${r#*-}" ;; *) echo "$r" ;; esac
    done | head -n "$PORTS_PER_HOST"
}

# probe_one <vantage> <host> <port> -> status (ok|busy|refused|timeout|dns|error) and mbps
probe_one() {
    local v="$1" h="$2" p="$3" out status mbps
    out="$(perf_vantage_run "$v" -c "$h" -p "$p" -t "$DUR" -J --connect-timeout 4000 2>&1 </dev/null)"
    if jq -e '.end.sum_received.bits_per_second' >/dev/null 2>&1 <<<"$out"; then
        mbps="$(jq -r '.end.sum_received.bits_per_second/1e6*100|round/100' <<<"$out")"
        if awk -v m="$mbps" 'BEGIN{exit !(m>1)}'; then status=ok; else status=zero; fi
    else
        mbps=0
        if   grep -qi 'busy' <<<"$out"; then status=busy
        elif grep -qi 'refused' <<<"$out"; then status=refused
        elif grep -qiE 'timed out|timeout' <<<"$out"; then status=timeout
        elif grep -qiE 'resolve|unknown host|Name or service' <<<"$out"; then status=dns
        else status=error; fi
    fi
    echo "$status,$mbps"
}

RUN="$(perf_new_run probe)"; perf_env_manifest "$RUN"
echo "ts,vantage,host,port,rtt_ms,status,mbps" > "$RUN/probe.csv"
grep -vE '^\s*(#|$)' "$SERVERS_FILE" | while read -r host ports _note; do
    rtt="$(ping -c 3 -W 2000 "$host" 2>/dev/null | awk -F'/' '/^round-trip|^rtt/{print $5}')"
    for v in $VANTAGES; do
        got=""
        for port in $(expand_ports "$ports"); do
            if [ "$DRY" = 1 ]; then echo "plan: $v $host:$port"; continue; fi
            r="$(probe_one "$v" "$host" "$port")"; st="${r%%,*}"
            echo "$(date +%s),$v,$host,$port,${rtt:--},$st,${r#*,}" | tee -a "$RUN/probe.csv" >&2
            if [ "$st" = ok ]; then got=1; break; fi
            sleep 2   # polite back-off before the next port
        done
        [ "$DRY" = 1 ] && break
    done
done
[ "$DRY" = 1 ] && exit 0
# validated = moved data (>1 Mb/s) from EVERY vantage point; ports may differ per vantage because
# public servers rotate "busy" ports. Output: host,port_used_from_n6,rtt_ms,vantages_ok,mbps_n6
nv=$(echo $VANTAGES | wc -w | tr -d ' ')
awk -F, -v n="$nv" 'NR>1 && $6=="ok"{ if(!(($2 SUBSEP $3) in seen)){seen[$2,$3]=1; c[$3]++}
      if($2=="n6"){p[$3]=$4; m[$3]=$7}; r[$3]=$5 }
    END{for(h in c) if(c[h]>=n) printf "%s,%s,%s,%d,%s\n", h, (h in p)?p[h]:"-", r[h], c[h], (h in m)?m[h]:0}' \
    "$RUN/probe.csv" | sort -t, -k3 -n > "$RUN/validated.csv"
echo "$RUN"
echo "validated (host,port_n6,rtt_ms,vantages_ok,mbps_n6): $(wc -l < "$RUN/validated.csv" | tr -d ' ')" >&2
cat "$RUN/validated.csv" >&2
