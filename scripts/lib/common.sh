# shellcheck shell=bash
# scripts/lib/common.sh — portable helpers shared by the UERANSIM validation scripts
# (test-slices.sh, validate-ursp.sh, validate-ueransim-mod.sh, ueransim-status.sh).
#
# Portability contract: bash 3.2 (macOS /bin/bash) + BSD userland as well as GNU/Linux.
#   - no associative arrays, no ${var,,}, no mapfile
#   - no grep -P, no GNU-only sed flags, no coreutils `timeout`
#   - text matching uses here-strings (`grep ... <<<"$var"`) instead of
#     `echo "$var" | grep -q ...`: with `set -o pipefail`, grep -q exits on the first
#     match, the producer gets SIGPIPE and the pipeline reports 141 (a false "no match")
#     once the input is large (e.g. `docker logs amf`).
#
# Source it with:  . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

# Repo root and PKI directory (read-only use: client cert for mTLS SBI calls).
COMMON_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$COMMON_LIB_DIR/../.." && pwd)}"
PKI_DIR="${PKI_DIR:-$REPO_ROOT/pki}"

# Client identity presented on SBI calls (every NF requires mTLS — TS 33.501 §13.1).
SBI_CLIENT_NF="${SBI_CLIENT_NF:-amf}"
# Image for the throw-away curl container used when an SBI port is not published
# to the host (or the host curl lacks HTTP/2).
SBI_CURL_IMAGE="${SBI_CURL_IMAGE:-curlimages/curl:latest}"
# SBI_MODE=auto (default: host when the port is published, else container) | container.
# Per-request ceiling for SBI / management calls (seconds).
SBI_MAX_TIME="${SBI_MAX_TIME:-10}"

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# require_cmds CMD... — exit 2 with a clear message when a host tool is missing.
require_cmds() {
    local c missing=""
    for c in "$@"; do
        have_cmd "$c" || missing="$missing $c"
    done
    if [ -n "$missing" ]; then
        echo "missing required host tool(s):$missing — install them and retry" >&2
        exit 2
    fi
}

# text_has PATTERN TEXT — extended-regex match on TEXT without a pipe (SIGPIPE-safe).
text_has() { grep -qE -- "$1" <<<"$2"; }
# text_has_i PATTERN TEXT — case-insensitive variant.
text_has_i() { grep -qiE -- "$1" <<<"$2"; }
# text_lines PATTERN TEXT — print the lines of TEXT matching PATTERN (never fails).
text_lines() { grep -E -- "$1" <<<"$2" || true; }
# text_count PATTERN TEXT — number of lines of TEXT matching PATTERN.
text_count() {
    local n
    n=$(grep -cE -- "$1" <<<"$2" || true)
    printf '%s' "${n:-0}"
}

# json_num_last KEY TEXT — last numeric value of "KEY":<n> found in TEXT (empty if none).
json_num_last() {
    sed -nE 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' <<<"$2" | tail -n 1
}
# json_str_last KEY TEXT — last string value of "KEY":"<s>" found in TEXT (empty if none).
json_str_last() {
    sed -nE 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' <<<"$2" | tail -n 1
}

# urlencode STRING — RFC 3986 percent-encoding (jq, else python3, else pure bash).
urlencode() {
    if have_cmd jq; then
        jq -rn --arg s "$1" '$s|@uri'
    elif have_cmd python3; then
        python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"
    else
        local LC_ALL=C str="$1" out="" ch i hex q="'"
        for ((i = 0; i < ${#str}; i++)); do
            ch="${str:i:1}"
            case "$ch" in
                [A-Za-z0-9.~_-]) out="$out$ch" ;;
                *) hex=$(printf '%02X' "$q$ch"); out="$out%$hex" ;;
            esac
        done
        printf '%s\n' "$out"
    fi
}

# run_timeout SECS CMD... — run CMD with a wall-clock limit (bash 3.2 replacement for
# coreutils `timeout`). Returns CMD's status, or 124 when the limit was hit (detected via
# a marker file: the docker CLI exits 0 on SIGTERM, so the exit code alone can't tell).
# The watchdog writes nowhere, so `$(run_timeout ...)` never waits on it.
run_timeout() {
    local secs="$1" pid wd rc=0 mark
    shift
    mark="$(mktemp "${TMPDIR:-/tmp}/run_timeout.XXXXXX")" || mark=""
    [ -n "$mark" ] && rm -f "$mark"
    "$@" &
    pid=$!
    (
        sleep "$secs" &
        spid=$!
        trap 'kill "$spid" 2>/dev/null; exit 0' TERM
        wait "$spid"
        [ -n "$mark" ] && : > "$mark"
        kill -TERM "$pid" 2>/dev/null || exit 0
        sleep 1
        kill -KILL "$pid" 2>/dev/null
    ) >/dev/null 2>&1 &
    wd=$!
    wait "$pid" 2>/dev/null || rc=$?
    kill -TERM "$wd" 2>/dev/null || true
    wait "$wd" 2>/dev/null || true
    if [ -n "$mark" ] && [ -e "$mark" ]; then
        rm -f "$mark"
        rc=124
    fi
    return "$rc"
}

# container_running NAME — true when the container exists and is running.
container_running() {
    [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]
}

# now_ts — current Unix time minus a 2 s margin (host/Docker VM clock skew), suitable
# for `docker logs --since` so a check only matches lines produced after its trigger.
now_ts() { echo $(( $(date +%s) - 2 )); }

# container_logs NAME [SINCE] — `docker logs` (stdout+stderr), optionally only since
# SINCE (Unix time / RFC 3339). Never fails, bounded in time.
container_logs() {
    if [ -n "${2:-}" ]; then
        run_timeout 20 docker logs --since "$2" "$1" 2>&1 || true
    else
        run_timeout 20 docker logs "$1" 2>&1 || true
    fi
}

# logs_have NAME PATTERN [SINCE] — container log contains the extended regex PATTERN.
logs_have() {
    local l
    l=$(container_logs "$1" "${3:-}")
    text_has "$2" "$l"
}

# wait_for_log NAME PATTERN [SECS] [SINCE] — poll the container log until PATTERN appears.
wait_for_log() {
    local c="$1" pat="$2" secs="${3:-30}" since="${4:-}" deadline
    deadline=$((SECONDS + secs))
    while :; do
        if logs_have "$c" "$pat" "$since"; then return 0; fi
        [ "$SECONDS" -ge "$deadline" ] && return 1
        sleep 1
    done
}

# published_port CONTAINER PORT — host port a container port is published on (empty if not).
published_port() {
    local out
    out=$(docker port "$1" "$2/tcp" 2>/dev/null || true)
    sed -nE '1s/.*:([0-9]+)$/\1/p' <<<"$out"
}

# docker_network_of CONTAINER SUBSTRING — name of the container's network containing SUBSTRING.
docker_network_of() {
    local nets n
    nets=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$1" 2>/dev/null || true)
    for n in $nets; do
        case "$n" in
            *"$2"*) printf '%s' "$n"; return 0 ;;
        esac
    done
    return 1
}

# host_curl_has_http2 — the host curl can speak HTTP/2 (needed for SBI, TS 29.500 §5.2).
host_curl_has_http2() {
    local v
    v=$(curl -V 2>/dev/null || true)
    text_has 'HTTP2' "$v"
}

# sbi_curl URL [CURL_ARGS...] — call an NF SBI endpoint over HTTP/2 + mTLS from the host.
#   URL uses the in-network name, e.g. https://nrf:8000/nnrf-disc/v1/nf-instances?...
#   The NF images are distroless (no curl inside), so:
#     1. if <nf>:<port> is published to the host and the host curl has HTTP/2, call
#        https://localhost:<published>/... with the $SBI_CLIENT_NF client cert from pki/;
#     2. otherwise run a throw-away $SBI_CURL_IMAGE container on the NF's SBI network
#        with pki/ mounted read-only.
#   Prints the response body (plus whatever -w adds). Never fails the caller.
sbi_curl() {
    local url="$1" rest host nf port path hport net
    shift
    rest="${url#https://}"
    host="${rest%%/*}"
    path="/${rest#*/}"
    nf="${host%%:*}"
    port="${host##*:}"
    [ "$port" = "$host" ] && port=443

    hport=""
    [ "${SBI_MODE:-auto}" != "container" ] && hport=$(published_port "$nf" "$port")
    if [ -n "$hport" ] && host_curl_has_http2; then
        curl -sk --http2 --max-time "$SBI_MAX_TIME" \
            --cert "$PKI_DIR/$SBI_CLIENT_NF.crt" --key "$PKI_DIR/$SBI_CLIENT_NF.key" \
            "$@" "https://localhost:${hport}${path}" 2>/dev/null || true
        return 0
    fi

    net=$(docker_network_of "$nf" sbi || true)
    if [ -z "$net" ]; then
        echo "sbi_curl: cannot reach $nf:$port (not published, no SBI network found)" >&2
        return 0
    fi
    run_timeout $((SBI_MAX_TIME + 60)) docker run --rm --network "$net" \
        -v "$PKI_DIR:/pki:ro" "$SBI_CURL_IMAGE" \
        -sk --http2 --max-time "$SBI_MAX_TIME" \
        --cert "/pki/$SBI_CLIENT_NF.crt" --key "/pki/$SBI_CLIENT_NF.key" \
        "$@" "$url" 2>/dev/null || true
}

# nr_cli_bounded SECS CONTAINER NR-CLI-ARGS... — run nr-cli inside a UERANSIM container
# with a time limit enforced on both sides: in-container `timeout` (so a wedged nr-cli
# does not linger inside the container after the host gives up) and run_timeout on the
# host-side docker exec. Returns 124 on timeout.
nr_cli_bounded() {
    local secs="$1" c="$2"
    shift 2
    run_timeout $((secs + 3)) docker exec "$c" sh -c \
        'secs=$1; shift; if command -v timeout >/dev/null 2>&1; then exec timeout -k 1 "$secs" nr-cli "$@"; else exec nr-cli "$@"; fi' \
        sh "$secs" "$@"
}

# nrcli CONTAINER NODE CMD [SECS] — `nr-cli NODE -e CMD` inside a UERANSIM container,
# bounded in time (nr-cli can block while a UE/gNB is (re)starting). Never fails.
nrcli() {
    nr_cli_bounded "${4:-10}" "$1" "$2" -e "$3" 2>&1 || true
}
