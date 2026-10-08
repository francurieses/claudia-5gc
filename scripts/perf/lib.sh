# shellcheck shell=bash
# scripts/perf/lib.sh — shared helpers for the user-plane throughput benchmarks
# (docs/performance/user-plane-throughput.md). Bash 3.2 / BSD-safe, same contract as
# scripts/lib/common.sh. Source it:  . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

PERF_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$PERF_LIB_DIR/../lib/common.sh"

PERF_IMAGE="${PERF_IMAGE:-nicolaka/netshoot}"
PERF_OUT_ROOT="${PERF_OUT_ROOT:-$REPO_ROOT/.tmp/perf}"

plog()  { printf '[perf] %s\n' "$*" >&2; }
pwarn() { printf '[perf] WARN: %s\n' "$*" >&2; }

# perf_new_run <label> -> prints a fresh run dir (.tmp/perf/<UTC ts>-<label>)
perf_new_run() {
    local d="$PERF_OUT_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-$1"
    mkdir -p "$d"
    echo "$d"
}

# perf_env_manifest <dir> — every number is only valid against this manifest.
perf_env_manifest() {
    {
        echo "date_utc=$(date -u +%FT%TZ)"
        echo "host=$(uname -srm)"
        echo "docker=$(docker info --format '{{.ServerVersion}} cpus={{.NCPU}} mem={{.MemTotal}} kernel={{.KernelVersion}} os={{.OperatingSystem}}' 2>/dev/null)"
        echo "iperf3_host=$(iperf3 --version 2>/dev/null | head -1)"
        echo "git_head=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null)"
        echo "upf_image=$(docker inspect -f '{{.Image}}' upf 2>/dev/null)"
        echo "upf_log_level=$(docker exec upf printenv LOG_LEVEL 2>/dev/null)"
        echo "upf_gomaxprocs=$(docker exec upf printenv GOMAXPROCS 2>/dev/null)"
        echo "default_route_if=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
    } > "$1/env.txt"
}

# perf_stats_start <dir> <containers...> / perf_stats_stop — 1 s docker stats sampler.
PERF_STATS_PID=""
perf_stats_start() {
    local dir="$1"; shift
    ( while :; do
        docker stats --no-stream --format '{{json .}}' "$@" 2>/dev/null | jq -c --arg t "$(date +%s)" '. + {ts:$t}' >> "$dir/stats.jsonl"
      done ) &
    PERF_STATS_PID=$!
}
perf_stats_stop() {
    [ -n "$PERF_STATS_PID" ] && { kill "$PERF_STATS_PID" 2>/dev/null; wait "$PERF_STATS_PID" 2>/dev/null; }
    PERF_STATS_PID=""
}

# perf_snap <dir> <label> — counters before/after a case (UPF netns: snmp, links, udp skmem, metrics).
perf_snap() {
    local out="$1/snap-$2.txt"
    {
        echo "## ts $(date +%s)"
        docker run --rm --network container:upf "$PERF_IMAGE" sh -c '
            echo "## snmp"; grep -E "^(Udp|Tcp|Ip):" /proc/net/snmp
            echo "## link"; ip -s link
            echo "## udp-skmem"; ss -uamn "sport = :2152"
            echo "## metrics"; curl -s --max-time 3 http://127.0.0.1:9107/metrics | grep -E "^fivegc_upf_" ' 2>/dev/null
    } > "$out"
}

# perf_log_rate <container> <secs> — log lines/s emitted in a window (hot-path logging detector).
perf_log_rate() {
    local a b
    a="$(docker logs "$1" 2>&1 | wc -l | tr -d ' ')"; sleep "$2"
    b="$(docker logs "$1" 2>&1 | wc -l | tr -d ' ')"
    awk -v a="$a" -v b="$b" -v s="$2" 'BEGIN{printf "%.1f\n", (b-a)/s}'
}

# iperf_json_to_csv <file> <case> -> "case,mbps,retrans,loss_pct,jitter_ms,cpu_local,cpu_remote"
# Handles iperf3 3.9 (UE image: UDP only in .end.sum) and >=3.11 (.sum_received).
iperf_json_to_csv() {
    jq -r --arg c "$2" '
      (.end.sum_received // .end.sum // {}) as $r
      | [$c, (($r.bits_per_second // 0) / 1e6 * 100 | round / 100),
         (.end.sum_sent.retransmits // 0), (.end.sum.lost_percent // 0),
         (.end.sum.jitter_ms // 0),
         (.end.cpu_utilization_percent.host_total // 0),
         (.end.cpu_utilization_percent.remote_total // 0)] | @csv' "$1" 2>/dev/null
}

# perf_vantage_run <vantage> <iperf3 args...> — run iperf3 from host | plain | n6.
# PERF_WATCHDOG seconds (default: 3x the -t value + 20) hard-kills a hung run (servers that accept
# the TCP connection but never answer the iperf3 control handshake would block forever).
perf_vantage_run() {
    local v="$1"; shift
    local wd="${PERF_WATCHDOG:-}" a prev="" t=10 cname="perf-$$-$RANDOM" pid kp
    if [ -z "$wd" ]; then
        for a in "$@"; do [ "$prev" = "-t" ] && t="$a"; prev="$a"; done
        wd=$((t * 3 + 20))
    fi
    case "$v" in
        host)  iperf3 "$@" & ;;
        plain) docker run --rm --name "$cname" "$PERF_IMAGE" iperf3 "$@" & ;;
        n6)    docker run --rm --name "$cname" --network 5gc-n6 "$PERF_IMAGE" iperf3 "$@" & ;;
    esac
    pid=$!
    ( sleep "$wd"; kill "$pid" 2>/dev/null; docker rm -f "$cname" >/dev/null 2>&1 ) >/dev/null 2>&1 &
    kp=$!
    wait "$pid"; local rc=$?
    kill "$kp" 2>/dev/null; wait "$kp" 2>/dev/null
    return $rc
}

# perf_discover_sessions -> lines "container|tun|ip" for every running ueransim-ue* uesimtun with IPv4.
perf_discover_sessions() {
    local ue
    for ue in $(docker ps --format '{{.Names}}' | grep -E '^ueransim-ue' | sort); do
        docker exec "$ue" ip -4 -o addr show 2>/dev/null \
            | awk -v ue="$ue" '$2 ~ /^uesimtun/ { split($4, a, "/"); print ue "|" $2 "|" a[1] }'
    done
}
