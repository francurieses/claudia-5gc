#!/usr/bin/env bash
# scripts/services-restart-check.sh
# PORTAL-001 — verify every service can be restarted from the management portal
# (Services page) and recovers.
#
# For each service, in a fixed order, the script:
#   a. restarts it through the portal API the Services page uses
#        POST http://localhost:$PORTAL_PORT/api/v1/services/<container>/restart
#      (mgmt-portal itself is restarted LAST with `docker restart`, since restarting it
#      from its own API kills the request);
#   b. waits for the container to be running again with a new .State.StartedAt;
#   c. NFs (except UPF and NRF): waits for the NF profile to be REGISTERED in the NRF
#      (NFListRetrieval, GET /nnrf-nfm/v1/nf-instances?detail=true — TS 29.510 §5.2.2.6)
#      and for the NF log to show "registered with NRF" since the restart; duplicate
#      profiles of the same nfType are flagged WARN. After an NRF restart every other
#      NF must re-appear REGISTERED (heartbeat 404 -> re-register, TS 29.510 §5.2.2.3.4);
#   d. NFs: /metrics on the published metrics port (fallback: Prometheus up{} == 1);
#      infra: a service-specific health probe;
#   e. after amf/smf/upf restarts and once at the end (E2E=1): N2 recovery (gNBs back to
#      NG_READY at the AMF), default UE (ueransim-ue) registered at UE and AMF, PDU session
#      active (ps-establish if missing), ping through uesimtun0 (WARN only), and for
#      smf/upf whether a new PFCP Association Setup is visible in the logs (info only);
#   f. if a PCAP sidecar <svc>-pcap exists (tcpdump, network_mode "service:<svc>"): it is
#      running and sees an eth* interface in /sys/class/net within PCAP_TIMEOUT. A sidecar
#      left on the restarted container's old netns only sees lo + tunnel stubs (capture
#      silently dead); the portal restarts it after the NF (response "sidecars":[...]).
#
# Prints progress, then a Markdown results table to stdout and to $RESULTS_FILE.
# Exit 0 iff no FAIL; 1 on any FAIL; 2 on a failed pre-flight.
#
# Verification only: it restarts containers but never changes configuration.
# It does NOT restart PCAP sidecars (*-pcap) itself (the portal does, step f) nor the
# RAN simulators (they are clients).
#
# Usage:  make services-restart-check [SERVICES="nssf grafana"] [E2E=0]
#         SERVICES="amf,smf" E2E=1 ./scripts/services-restart-check.sh
#
# Environment (defaults in brackets):
#   SERVICES          space/comma list restricting the set [all present services]
#   E2E               1 = run the N2/UE/data-plane checks, 0 = skip them [1]
#   PORTAL_PORT       management portal host port [8080]
#   RESULTS_FILE      Markdown results file [./services-restart-results.md]
#   RESTART_TIMEOUT   container back up with a new StartedAt (s) [60]
#   NRF_TIMEOUT       NF profile REGISTERED in NRF (s; NF heartbeat is 45 s) [120]
#   METRICS_TIMEOUT   /metrics answering (s) [45]
#   HEALTH_TIMEOUT    infra health probe passing (s; Loki needs ~15 s+) [90]
#   N2_TIMEOUT        gNBs NG_READY again after an AMF restart (s) [60]
#   UE_TIMEOUT        default UE registered at UE + AMF (s) [90]
#   PS_TIMEOUT        PDU session active after ps-establish (s) [30]
#   PCAP_TIMEOUT      <svc>-pcap sidecar running with an eth* interface (s) [20]
#   PFCP_TIMEOUT      smf/upf: new PFCP association logged by the UPF (s; SMF-004) [20]
#   PFCP_SETTLE       smf/upf: wait after re-association for the PDU session release (s) [3]
#   UE_CONTAINER      UERANSIM UE container for the E2E check [ueransim-ue]
#   PING_TARGET       address pinged through uesimtun0 (UPF N3 IP) [172.30.3.100]
#
# Portable to macOS bash 3.2 + BSD userland (see scripts/lib/common.sh).
# spec_ref: n/a (operability) — NRF behaviour per TS 29.510 §5.2.2.2.2 / §5.2.2.3.4.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

require_cmds docker curl jq

PORTAL_PORT="${PORTAL_PORT:-8080}"
PORTAL="http://localhost:${PORTAL_PORT}"
RESULTS_FILE="${RESULTS_FILE:-./services-restart-results.md}"
E2E="${E2E:-1}"
RESTART_TIMEOUT="${RESTART_TIMEOUT:-60}"
NRF_TIMEOUT="${NRF_TIMEOUT:-120}"
METRICS_TIMEOUT="${METRICS_TIMEOUT:-45}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-90}"
N2_TIMEOUT="${N2_TIMEOUT:-60}"
UE_TIMEOUT="${UE_TIMEOUT:-90}"
PS_TIMEOUT="${PS_TIMEOUT:-30}"
PCAP_TIMEOUT="${PCAP_TIMEOUT:-20}"
PFCP_TIMEOUT="${PFCP_TIMEOUT:-20}"
PFCP_SETTLE="${PFCP_SETTLE:-3}"
UE_CONTAINER="${UE_CONTAINER:-ueransim-ue}"
PING_TARGET="${PING_TARGET:-172.30.3.100}"
AMF_MGMT="http://localhost:9002"

# Canonical order: stateless SBA NFs, NRF, SMF, UPF, AMF, infra/obs, portal last.
ALL_SERVICES="ausf udm udr pcf nssf bsf nef lmf smsf nrf smf upf amf redis postgres prometheus loki promtail grafana jaeger mcp mgmt-portal"
# NFs that register with the NRF (UPF does not; NRF is the registry).
NRF_CLIENT_NFS="amf ausf udm udr smf pcf nssf bsf nef lmf smsf"

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
    BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

PASS=0; FAIL=0; WARN=0
ok()   { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS + 1)); }
bad()  { echo -e "  ${RED}FAIL${NC} $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}WARN${NC} $1"; WARN=$((WARN + 1)); }
info() { echo -e "  ${CYAN}....${NC} $1"; }
section() { echo -e "\n${BOLD}${CYAN}== $1 ==${NC}"; }

# ---- Results (parallel indexed arrays; bash 3.2 has no associative arrays) ------
R_N=0
R_SVC=(); R_RESTART=(); R_UP=(); R_NRF=(); R_HEALTH=(); R_E2E=(); R_PCAP=(); R_NOTES=()
# Current row fields, flushed by row_commit.
c_svc=""; c_restart=""; c_up=""; c_nrf=""; c_health=""; c_e2e=""; c_pcap=""; c_notes=""
row_begin() {
    c_svc="$1"; c_restart="n/a"; c_up="n/a"; c_nrf="n/a"; c_health="n/a"; c_e2e="n/a"; c_pcap="n/a"; c_notes=""
}
note() { if [ -z "$c_notes" ]; then c_notes="$1"; else c_notes="$c_notes; $1"; fi; }
row_commit() {
    R_SVC[R_N]="$c_svc"; R_RESTART[R_N]="$c_restart"; R_UP[R_N]="$c_up"; R_NRF[R_N]="$c_nrf"
    R_HEALTH[R_N]="$c_health"; R_E2E[R_N]="$c_e2e"; R_PCAP[R_N]="$c_pcap"; R_NOTES[R_N]="${c_notes:--}"
    R_N=$((R_N + 1))
}

# ---- Lookup tables (case statements) --------------------------------------------
nf_type_of() {
    case "$1" in
        nrf|amf|smf|upf|udm|udr|ausf|pcf|nssf|bsf|nef|lmf|smsf)
            tr '[:lower:]' '[:upper:]' <<<"$1" ;;
        *) echo "" ;;
    esac
}
# nf_id_of NF — deterministic nfInstanceId (nf/<nf>/config/dev.yaml nf_instance_id).
nf_id_of() {
    case "$1" in
        amf)  echo 00000000-0000-4001-8000-000000000001 ;;
        ausf) echo 00000000-0000-4002-8000-000000000001 ;;
        udm)  echo 00000000-0000-4003-8000-000000000001 ;;
        smf)  echo 00000000-0000-4004-8000-000000000001 ;;
        upf)  echo 00000000-0000-4005-8000-000000000001 ;;
        pcf)  echo 00000000-0000-4006-8000-000000000001 ;;
        nssf) echo 00000000-0000-4007-8000-000000000001 ;;
        udr)  echo 00000000-0000-4008-8000-000000000001 ;;
        smsf) echo 00000000-0000-4010-8000-000000000001 ;;
        bsf)  echo 00000000-0000-4010-8000-000000000002 ;;
        nef)  echo 00000000-0000-4011-8000-000000000001 ;;
        lmf)  echo 00000000-0000-4012-8000-000000000001 ;;
        *) echo "" ;;
    esac
}
# metrics_port_of NF — container metrics port (observability/prometheus/prometheus.yml).
metrics_port_of() {
    case "$1" in
        nrf) echo 9100 ;; amf) echo 9101 ;; ausf) echo 9102 ;; udm) echo 9103 ;;
        udr) echo 9104 ;; smf) echo 9105 ;; pcf) echo 9106 ;; upf) echo 9107 ;;
        nssf) echo 9109 ;; smsf) echo 9110 ;; bsf) echo 9111 ;; nef) echo 9112 ;;
        lmf) echo 9113 ;; *) echo "" ;;
    esac
}
PROM_JOB="5gc-nfs"

in_list() {
    local x
    for x in $2; do [ "$x" = "$1" ] && return 0; done
    return 1
}
container_exists() { docker inspect -f '{{.Id}}' "$1" >/dev/null 2>&1; }
started_at() { docker inspect -f '{{.State.StartedAt}}' "$1" 2>/dev/null || true; }

# ---- NRF helpers -----------------------------------------------------------------
# nrf_profiles — one line per NF profile in the NRF: "<nfInstanceId> <nfType> <nfStatus>".
nrf_profiles() {
    local body
    body=$(sbi_curl "https://nrf:8000/nnrf-nfm/v1/nf-instances?detail=true" 2>/dev/null)
    [ -n "$body" ] || return 0
    jq -r '.nfInstances[]? | select(type == "object") | "\(.nfInstanceId) \(.nfType) \(.nfStatus // "-")"' \
        <<<"$body" 2>/dev/null || true
}
# nf_registered_in PROFILES NF — the NF's deterministic id is REGISTERED in PROFILES.
nf_registered_in() {
    local id
    id=$(nf_id_of "$2")
    text_has "^${id} [A-Z]+ REGISTERED$" "$1"
}

# check_nrf_registration NF SINCE — sets c_nrf (and notes) for an NF client restart.
check_nrf_registration() {
    local nf="$1" since="$2" type deadline t0 profiles="" logs n dup_ids
    type=$(nf_type_of "$nf")
    t0=$SECONDS
    deadline=$((SECONDS + NRF_TIMEOUT))
    while :; do
        profiles=$(nrf_profiles)
        logs=$(container_logs "$nf" "$since")
        if nf_registered_in "$profiles" "$nf" && text_has '"registered with NRF"' "$logs"; then
            break
        fi
        if text_has 'NRF registration failed' "$logs" && ! text_has '"registered with NRF"' "$logs"; then
            break
        fi
        [ "$SECONDS" -ge "$deadline" ] && break
        sleep 3
    done
    local el=$((SECONDS - t0))
    if nf_registered_in "$profiles" "$nf" && text_has '"registered with NRF"' "$logs"; then
        c_nrf="PASS (${el}s)"; ok "$nf: profile $type REGISTERED in NRF and 'registered with NRF' logged (${el}s)"
    elif text_has 'NRF registration failed' "$logs"; then
        c_nrf="FAIL"; note "NF logged 'NRF registration failed' and does not retry"
        bad "$nf: NF logged 'NRF registration failed (continuing without NRF)' after restart"
    elif nf_registered_in "$profiles" "$nf"; then
        c_nrf="WARN"; note "profile REGISTERED but no 'registered with NRF' log since restart (stale profile?)"
        warn "$nf: profile REGISTERED in NRF but no 'registered with NRF' log since restart"
    else
        c_nrf="FAIL"; note "not REGISTERED in NRF within ${NRF_TIMEOUT}s"
        bad "$nf: profile $type not REGISTERED in NRF within ${NRF_TIMEOUT}s"
    fi
    # Duplicate (stale) profiles of the same nfType.
    n=$(text_count "^[^ ]+ ${type} " "$profiles")
    if [ "$n" -gt 1 ]; then
        dup_ids=$(text_lines "^[^ ]+ ${type} " "$profiles" | awk '{print $1}' | tr '\n' ' ')
        [ "$c_nrf" = "FAIL" ] || c_nrf="WARN"
        note "$n $type profiles in NRF: $dup_ids"
        warn "$nf: $n $type profiles in NRF (duplicate/stale): $dup_ids"
    fi
}

# check_all_nfs_reregistered — after an NRF restart, every present NF client must be
# REGISTERED again within NRF_TIMEOUT. Sets c_nrf.
check_all_nfs_reregistered() {
    local expected="" nf profiles="" missing deadline t0
    for nf in $NRF_CLIENT_NFS; do
        container_running "$nf" && expected="$expected $nf"
    done
    t0=$SECONDS
    deadline=$((SECONDS + NRF_TIMEOUT))
    info "waiting up to ${NRF_TIMEOUT}s for NFs to re-register:$expected"
    while :; do
        profiles=$(nrf_profiles)
        missing=""
        for nf in $expected; do
            nf_registered_in "$profiles" "$nf" || missing="$missing $nf"
        done
        [ -z "$missing" ] && break
        [ "$SECONDS" -ge "$deadline" ] && break
        sleep 5
    done
    local el=$((SECONDS - t0))
    if [ -z "$missing" ]; then
        c_nrf="PASS (${el}s)"; ok "nrf: all NFs re-registered (${el}s):$expected"
    else
        c_nrf="FAIL"; note "not re-registered after NRF restart:$missing"
        bad "nrf: NFs not re-registered within ${NRF_TIMEOUT}s:$missing"
    fi
}

# ---- Health helpers --------------------------------------------------------------
http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time "${2:-5}" "$1" 2>/dev/null || true; }

# metrics_ok NF — /metrics returns 200 with Go/5GC series (published port), else the
# Prometheus target is up. Echoes a short description of how it passed.
metrics_ok() {
    local nf="$1" port hp body q val
    port=$(metrics_port_of "$nf")
    hp=$(published_port "$nf" "$port")
    if [ -n "$hp" ]; then
        body=$(curl -s --max-time 5 -w '\n%{http_code}' "http://localhost:${hp}/metrics" 2>/dev/null || true)
        if [ "$(tail -n 1 <<<"$body")" = "200" ] && text_has '^(fivegc_|go_)' "$body"; then
            echo "/metrics :$hp"; return 0
        fi
        return 1
    fi
    q=$(urlencode "up{job=\"${PROM_JOB}\",instance=\"${nf}:${port}\"}")
    body=$(curl -s --max-time 5 "http://localhost:9090/api/v1/query?query=${q}" 2>/dev/null || true)
    val=$(jq -r '.data.result[0].value[1] // empty' <<<"$body" 2>/dev/null || true)
    if [ "$val" = "1" ]; then echo "prometheus up=1"; return 0; fi
    return 1
}

# infra_probe SVC — one health probe attempt (0 = healthy).
infra_probe() {
    local out hp
    case "$1" in
        postgres) run_timeout 10 docker exec postgres pg_isready -U 5gc >/dev/null 2>&1 ;;
        redis)
            out=$(run_timeout 10 docker exec redis redis-cli ping 2>/dev/null || true)
            text_has '^PONG' "$out" ;;
        prometheus) [ "$(http_code "http://localhost:9090/-/ready")" = "200" ] ;;
        grafana)    [ "$(http_code "http://localhost:3000/api/health")" = "200" ] ;;
        loki)       [ "$(http_code "http://localhost:3100/ready")" = "200" ] ;;
        jaeger)     [ "$(http_code "http://localhost:16686/")" = "200" ] ;;
        promtail)   container_running promtail ;;
        mcp)
            container_running mcp || return 1
            hp=$(published_port mcp 9300)
            [ -z "$hp" ] && return 0
            out=$(http_code "http://localhost:${hp}/" 3)
            [ -n "$out" ] && [ "$out" != "000" ] ;;
        mgmt-portal) [ "$(http_code "${PORTAL}/api/v1/health")" = "200" ] ;;
        *) return 1 ;;
    esac
}
infra_probe_desc() {
    case "$1" in
        postgres) echo "pg_isready" ;; redis) echo "redis-cli ping" ;;
        prometheus) echo "/-/ready" ;; grafana) echo "/api/health" ;; loki) echo "/ready" ;;
        jaeger) echo "UI 200" ;; promtail) echo "running only (no published port)" ;;
        mcp) if [ -n "$(published_port mcp 9300)" ]; then echo ":9300 answers"; else echo "running (9300 not published)"; fi ;;
        mgmt-portal) echo "/api/v1/health" ;;
    esac
}

check_health() {
    local svc="$1" t0 deadline how="" el
    t0=$SECONDS
    if [ -n "$(nf_type_of "$svc")" ]; then
        deadline=$((SECONDS + METRICS_TIMEOUT))
        while :; do
            if how=$(metrics_ok "$svc"); then break; fi
            how=""
            [ "$SECONDS" -ge "$deadline" ] && break
            sleep 3
        done
        el=$((SECONDS - t0))
        if [ -n "$how" ]; then
            c_health="PASS (${el}s)"; ok "$svc: metrics OK via $how (${el}s)"
        else
            c_health="FAIL"; note "/metrics not OK within ${METRICS_TIMEOUT}s"
            bad "$svc: /metrics not OK within ${METRICS_TIMEOUT}s"
        fi
        return 0
    fi
    deadline=$((SECONDS + HEALTH_TIMEOUT))
    while :; do
        if infra_probe "$svc"; then how=ok; break; fi
        [ "$SECONDS" -ge "$deadline" ] && break
        sleep 3
    done
    el=$((SECONDS - t0))
    if [ -n "$how" ]; then
        c_health="PASS (${el}s)"; ok "$svc: health OK — $(infra_probe_desc "$svc") (${el}s)"
    else
        c_health="FAIL"; note "health ($(infra_probe_desc "$svc")) not OK within ${HEALTH_TIMEOUT}s"
        bad "$svc: health ($(infra_probe_desc "$svc")) not OK within ${HEALTH_TIMEOUT}s"
    fi
}

# ---- E2E helpers -----------------------------------------------------------------
gnbs_ready_count() {
    local body
    body=$(curl -s --max-time 5 "${AMF_MGMT}/amf/v1/ran/gnbs" 2>/dev/null || true)
    jq -r '[.gnbs[]? | select(.state == "NG_READY")] | length' <<<"$body" 2>/dev/null || echo 0
}
GNB_EXPECTED=0

# e2e_check CONTEXT — N2 + UE + data-plane recovery. Sets c_e2e (and notes).
e2e_check() {
    local ctx="$1" e2e_res="PASS" t0 deadline n supi st amf_ctx gmm ps addr el
    if [ "$E2E" != "1" ]; then c_e2e="SKIP"; return 0; fi
    info "E2E recovery check ($ctx)"

    # N2: gNBs back to NG_READY.
    if [ "$GNB_EXPECTED" -gt 0 ]; then
        t0=$SECONDS; deadline=$((SECONDS + N2_TIMEOUT)); n=0
        while :; do
            n=$(gnbs_ready_count)
            [ "${n:-0}" -ge "$GNB_EXPECTED" ] && break
            [ "$SECONDS" -ge "$deadline" ] && break
            sleep 3
        done
        el=$((SECONDS - t0))
        if [ "${n:-0}" -ge "$GNB_EXPECTED" ]; then
            ok "$ctx: $n/$GNB_EXPECTED gNB(s) NG_READY at the AMF (${el}s)"
        else
            bad "$ctx: only ${n:-0}/$GNB_EXPECTED gNB(s) NG_READY within ${N2_TIMEOUT}s"
            note "gNBs NG_READY ${n:-0}/$GNB_EXPECTED"; e2e_res="FAIL"
        fi
    fi

    if ! container_running "$UE_CONTAINER"; then
        warn "$ctx: $UE_CONTAINER not running — UE checks skipped"
        note "UE checks skipped ($UE_CONTAINER absent)"
        [ "$e2e_res" = "PASS" ] && e2e_res="SKIP"
        c_e2e="$e2e_res"; return 0
    fi

    # UE registered at the UE side AND the AMF holds a 5GMM-REGISTERED context.
    t0=$SECONDS; deadline=$((SECONDS + UE_TIMEOUT)); supi=""; st=""; gmm=""
    while :; do
        [ -z "$supi" ] && supi=$(nr_cli_bounded 10 "$UE_CONTAINER" --dump 2>/dev/null | awk '/^imsi-/ {print $1; exit}' || true)
        if [ -n "$supi" ]; then
            st=$(nrcli "$UE_CONTAINER" "$supi" status 10)
            amf_ctx=$(curl -s --max-time 5 "${AMF_MGMT}/amf/v1/ue-contexts/${supi}" 2>/dev/null || true)
            gmm=$(json_str_last gmm_state "$amf_ctx")
            if text_has 'mm-state: MM-REGISTERED' "$st" && [ "$gmm" = "5GMM-REGISTERED" ]; then break; fi
        fi
        [ "$SECONDS" -ge "$deadline" ] && break
        sleep 3
    done
    el=$((SECONDS - t0))
    if [ -z "$supi" ]; then
        bad "$ctx: no UE found in $UE_CONTAINER (nr-cli --dump)"
        note "no UE in $UE_CONTAINER"; c_e2e="FAIL"; return 0
    fi
    if text_has 'mm-state: MM-REGISTERED' "$st" && [ "$gmm" = "5GMM-REGISTERED" ]; then
        ok "$ctx: $supi registered (UE MM-REGISTERED, AMF 5GMM-REGISTERED) (${el}s)"
    else
        local ue_mm
        ue_mm=$(sed -nE 's/^mm-state: ([^ ]+).*/\1/p' <<<"$st" | head -n 1)
        bad "$ctx: $supi not registered within ${UE_TIMEOUT}s (UE mm-state=${ue_mm:-?}, AMF gmm_state=${gmm:-no context})"
        note "$supi UE=${ue_mm:-?} AMF=${gmm:-no context}"; e2e_res="FAIL"
        c_e2e="$e2e_res"; return 0
    fi

    # PDU session with an address (establish one if missing).
    ps=$(nrcli "$UE_CONTAINER" "$supi" ps-list 10)
    addr=$(sed -nE 's/^[[:space:]]*address: ([0-9.]+).*/\1/p' <<<"$ps" | head -n 1)
    if [ -z "$addr" ] || ! text_has 'PS-ACTIVE' "$ps"; then
        info "$ctx: no active PDU session — ps-establish IPv4 --dnn internet"
        nrcli "$UE_CONTAINER" "$supi" "ps-establish IPv4 --dnn internet" 15 >/dev/null
        deadline=$((SECONDS + PS_TIMEOUT))
        while :; do
            ps=$(nrcli "$UE_CONTAINER" "$supi" ps-list 10)
            addr=$(sed -nE 's/^[[:space:]]*address: ([0-9.]+).*/\1/p' <<<"$ps" | head -n 1)
            [ -n "$addr" ] && text_has 'PS-ACTIVE' "$ps" && break
            [ "$SECONDS" -ge "$deadline" ] && break
            sleep 3
        done
    fi
    if [ -n "$addr" ] && text_has 'PS-ACTIVE' "$ps"; then
        ok "$ctx: PDU session PS-ACTIVE, UE address $addr"
    else
        bad "$ctx: no PS-ACTIVE PDU session for $supi within ${PS_TIMEOUT}s"
        note "no PDU session"; c_e2e="FAIL"; return 0
    fi

    # Data plane (WARN only).
    if run_timeout 15 docker exec "$UE_CONTAINER" ping -c 2 -W 2 -I uesimtun0 "$PING_TARGET" >/dev/null 2>&1; then
        ok "$ctx: ping $PING_TARGET via uesimtun0 OK"
    else
        warn "$ctx: ping $PING_TARGET via uesimtun0 failed (stale PDU session after restart?)"
        note "ping $PING_TARGET failed"; [ "$e2e_res" = "PASS" ] && e2e_res="WARN"
    fi
    if run_timeout 15 docker exec "$UE_CONTAINER" ping -c 2 -W 2 -I uesimtun0 8.8.8.8 >/dev/null 2>&1; then
        info "$ctx: ping 8.8.8.8 via uesimtun0 OK (external connectivity)"
    else
        info "$ctx: ping 8.8.8.8 via uesimtun0 failed (no external connectivity — informational)"
    fi
    c_e2e="$e2e_res"
}

# wait_pfcp_reassociation SINCE — SMF-004: after an smf/upf restart the SMF detects the
# UPF restart via the Heartbeat Recovery Time Stamp (TS 23.007 §19A, TS 23.527 §4.2),
# re-runs PFCP Association Setup and releases the stale PDU sessions towards AMF/UE.
# Wait (bounded by PFCP_TIMEOUT) for the UPF to log the new association, then PFCP_SETTLE
# seconds for the NW-initiated PDU Session Release to reach the UE, so e2e_check sees the
# post-recovery state instead of the stale session. Never fails (always returns 0).
wait_pfcp_reassociation() {
    local since="$1" deadline
    deadline=$((SECONDS + PFCP_TIMEOUT))
    while :; do
        if text_has 'PFCP AssociationSetup accepted' "$(container_logs upf "$since")"; then
            sleep "$PFCP_SETTLE"; return 0
        fi
        [ "$SECONDS" -ge "$deadline" ] && return 0
        sleep 1
    done
}

# pfcp_note SINCE — informational: PFCP Association Setup seen since the restart.
pfcp_note() {
    local since="$1" upf_l smf_l
    upf_l=$(container_logs upf "$since")
    smf_l=$(container_logs smf "$since")
    if text_has 'PFCP AssociationSetup accepted' "$upf_l"; then
        info "UPF logged 'PFCP AssociationSetup accepted' since restart"
        note "PFCP Association Setup seen"
    elif text_has_i 'association' "$smf_l"; then
        info "SMF logged an association message since restart (no UPF AssociationSetup accepted)"
        note "SMF association log seen, no UPF AssociationSetup accepted"
    else
        warn "no PFCP Association Setup in SMF/UPF logs since restart"
        note "no PFCP Association Setup in logs"
    fi
    if text_has 'PFCP Session established' "$upf_l"; then note "UPF re-established a PFCP session"; fi
}

# ---- PCAP sidecar ----------------------------------------------------------------
# check_pcap_sidecar SVC — if <svc>-pcap exists, it must be running and joined to SVC's
# current netns (an eth* entry in /sys/class/net) within PCAP_TIMEOUT. Sets c_pcap.
check_pcap_sidecar() {
    local svc="$1" sc="$1-pcap" t0 deadline ifs="" el
    case "$svc" in *-pcap) return 0 ;; esac
    container_exists "$sc" || return 0
    if text_has "\"${sc}\"" "$LAST_RESTART_BODY"; then
        info "$svc: portal reported sidecar $sc restarted"
    fi
    t0=$SECONDS
    deadline=$((SECONDS + PCAP_TIMEOUT))
    while :; do
        ifs=""
        if container_running "$sc"; then
            ifs=$(run_timeout 10 docker exec "$sc" sh -c 'ls /sys/class/net' 2>/dev/null | tr '\n' ' ' || true)
            text_has '(^| )eth[0-9]' "$ifs" && break
        fi
        [ "$SECONDS" -ge "$deadline" ] && break
        sleep 2
    done
    el=$((SECONDS - t0))
    if ! container_running "$sc"; then
        c_pcap="FAIL"; note "$sc not running"
        bad "$svc: PCAP sidecar $sc not running within ${PCAP_TIMEOUT}s"
    elif text_has '(^| )eth[0-9]' "$ifs"; then
        c_pcap="PASS (${el}s)"; ok "$svc: PCAP sidecar $sc joined to the current netns (${ifs% }) (${el}s)"
    else
        c_pcap="FAIL"; note "$sc has no eth* interface (stale netns): ${ifs:-none}"
        bad "$svc: PCAP sidecar $sc has no eth* interface after ${PCAP_TIMEOUT}s (${ifs:-none}) — stale netns, capture dead"
    fi
}

# ---- Restart ---------------------------------------------------------------------
# do_restart SVC — restart via portal (docker for mgmt-portal) and wait until it is up
# with a new StartedAt. Sets c_restart / c_up. Returns 1 if the service did not come back.
do_restart() {
    local svc="$1" before after resp code body t0 deadline
    LAST_RESTART_BODY=""
    before=$(started_at "$svc")
    t0=$SECONDS
    if [ "$svc" = "mgmt-portal" ]; then
        if run_timeout 60 docker restart "$svc" >/dev/null 2>&1; then
            c_restart="PASS"; ok "$svc: docker restart issued (portal cannot restart itself via its API)"
            note "restarted with docker restart"
        else
            c_restart="FAIL"; bad "$svc: docker restart failed"
        fi
    else
        resp=$(curl -s -X POST --max-time $((RESTART_TIMEOUT + 15)) -w '\n%{http_code}' \
            "${PORTAL}/api/v1/services/${svc}/restart" 2>/dev/null || true)
        code=$(tail -n 1 <<<"$resp")
        body=$(sed '$d' <<<"$resp")
        LAST_RESTART_BODY="$body"
        if [ "$code" = "200" ] && text_has '"restarting"' "$body"; then
            c_restart="PASS"; ok "$svc: portal restart -> 200 {\"status\":\"restarting\"}"
        else
            c_restart="FAIL"; note "portal restart HTTP ${code:-none}: $(tr -d '\n' <<<"$body" | cut -c1-80)"
            bad "$svc: portal restart HTTP ${code:-none} $(tr -d '\n' <<<"$body" | cut -c1-120)"
        fi
    fi
    deadline=$((t0 + RESTART_TIMEOUT))
    while :; do
        after=$(started_at "$svc")
        if container_running "$svc" && [ -n "$after" ] && [ "$after" != "$before" ]; then break; fi
        [ "$SECONDS" -ge "$deadline" ] && break
        sleep 1
    done
    local el=$((SECONDS - t0))
    if container_running "$svc" && [ "$after" != "$before" ]; then
        c_up="$el"; ok "$svc: running again, StartedAt $before -> $after (${el}s)"
        return 0
    fi
    c_up="FAIL"
    if container_running "$svc"; then
        note "StartedAt unchanged (not restarted)"; bad "$svc: running but StartedAt unchanged after ${RESTART_TIMEOUT}s"
    else
        note "not running after ${RESTART_TIMEOUT}s"; bad "$svc: not running after ${RESTART_TIMEOUT}s"
    fi
    return 1
}

LAST_RESTART_BODY=""

# ---- Pre-flight ------------------------------------------------------------------
if [ "$(http_code "${PORTAL}/api/v1/health")" != "200" ]; then
    echo "management portal not answering at ${PORTAL}/api/v1/health — start it with: make portal (or make 5gcsa)" >&2
    exit 2
fi
svc_json=$(curl -s --max-time 10 "${PORTAL}/api/v1/services" 2>/dev/null || true)
if ! jq -e 'type == "array"' <<<"$svc_json" >/dev/null 2>&1; then
    echo "GET ${PORTAL}/api/v1/services did not return a JSON array (docker unavailable in the portal?)" >&2
    exit 2
fi

# Resolve the service set.
REQ="$(tr ',' ' ' <<<"${SERVICES:-}")"
if [ -n "$(tr -d ' ' <<<"$REQ")" ]; then
    for s in $REQ; do
        in_list "$s" "$ALL_SERVICES" || { echo "unknown service '$s' (known: $ALL_SERVICES)" >&2; exit 2; }
    done
    SET=""
    for s in $ALL_SERVICES; do in_list "$s" "$REQ" && SET="$SET $s"; done
else
    SET="$ALL_SERVICES"
fi

echo -e "${BOLD}PORTAL-001 services restart check${NC} — portal ${PORTAL}, E2E=${E2E}"
echo "Services:$SET"

if [ "$E2E" = "1" ]; then
    GNB_EXPECTED=$(gnbs_ready_count)
    GNB_EXPECTED=${GNB_EXPECTED:-0}
    info "baseline: $GNB_EXPECTED gNB(s) NG_READY at the AMF; UE container $UE_CONTAINER $(container_running "$UE_CONTAINER" && echo running || echo absent)"
fi

# ---- Main loop -------------------------------------------------------------------
for svc in $SET; do
    section "$svc"
    row_begin "$svc"
    if ! container_exists "$svc"; then
        c_restart="SKIP"; c_up="SKIP"; c_health="SKIP"; note "container not present"
        echo -e "  ${YELLOW}SKIP${NC} $svc: container not present"
        row_commit; continue
    fi
    if ! jq -e --arg n "$svc" 'any(.[]; .name == $n)' <<<"$svc_json" >/dev/null 2>&1; then
        note "not listed by GET /api/v1/services"
        warn "$svc: not listed by GET /api/v1/services"
    fi
    since=$(now_ts)
    if ! do_restart "$svc"; then
        row_commit; continue
    fi
    if [ "$svc" = "nrf" ]; then
        check_all_nfs_reregistered
    elif in_list "$svc" "$NRF_CLIENT_NFS"; then
        check_nrf_registration "$svc" "$since"
    fi
    check_health "$svc"
    check_pcap_sidecar "$svc"
    case "$svc" in
        amf) e2e_check "after AMF restart" ;;
        smf|upf)
            [ "$E2E" = "1" ] && wait_pfcp_reassociation "$since" && pfcp_note "$since"
            e2e_check "after $(nf_type_of "$svc") restart" ;;
    esac
    row_commit
done

if [ "$E2E" = "1" ]; then
    section "final E2E"
    row_begin "(final E2E)"
    e2e_check "final"
    row_commit
fi

# ---- Results table ---------------------------------------------------------------
cell_fail() { case "$1" in FAIL*) return 0 ;; esac; return 1; }
ROWFAIL=0; PCAP_PASS=0; PCAP_FAIL=0
for ((i = 0; i < R_N; i++)); do
    for v in "${R_RESTART[i]}" "${R_UP[i]}" "${R_NRF[i]}" "${R_HEALTH[i]}" "${R_E2E[i]}" "${R_PCAP[i]}"; do
        cell_fail "$v" && ROWFAIL=$((ROWFAIL + 1))
    done
    case "${R_PCAP[i]}" in
        PASS*) PCAP_PASS=$((PCAP_PASS + 1)) ;;
        FAIL*) PCAP_FAIL=$((PCAP_FAIL + 1)) ;;
    esac
done

TABLE="$(
    echo "# Services restart check (PORTAL-001)"
    echo
    echo "Run: $(date -u '+%Y-%m-%dT%H:%M:%SZ') — portal ${PORTAL}, E2E=${E2E}, timeouts restart=${RESTART_TIMEOUT}s nrf=${NRF_TIMEOUT}s metrics=${METRICS_TIMEOUT}s health=${HEALTH_TIMEOUT}s"
    echo
    echo "| Service | Restart | Up (s) | NRF registered | /metrics or health | E2E | PCAP sidecar | Notes |"
    echo "|---|---|---|---|---|---|---|---|"
    for ((i = 0; i < R_N; i++)); do
        printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' "${R_SVC[i]}" "${R_RESTART[i]}" "${R_UP[i]}" \
            "${R_NRF[i]}" "${R_HEALTH[i]}" "${R_E2E[i]}" "${R_PCAP[i]}" "$(sed 's/|/\\|/g' <<<"${R_NOTES[i]}")"
    done
    echo
    echo "Checks: PASS=${PASS} FAIL=${FAIL} WARN=${WARN}"
    echo "PCAP sidecars: PASS=${PCAP_PASS} FAIL=${PCAP_FAIL} (timeout ${PCAP_TIMEOUT}s)"
)"

section "Results"
echo "$TABLE"
if printf '%s\n' "$TABLE" > "$RESULTS_FILE" 2>/dev/null; then
    echo -e "\nResults written to $RESULTS_FILE"
else
    echo -e "\n${YELLOW}could not write $RESULTS_FILE${NC}" >&2
fi

if [ "$FAIL" -gt 0 ] || [ "$ROWFAIL" -gt 0 ]; then
    echo -e "${RED}${BOLD}FAILED${NC} — $FAIL failing check(s)"
    exit 1
fi
echo -e "${GREEN}${BOLD}ALL PASSED${NC} ($WARN warning(s))"
exit 0
