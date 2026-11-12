#!/usr/bin/env bash
# scripts/rolling-upgrade-check.sh
# REL19-7.3 - rolling upgrade + downgrade check for AMF and SMF (state compatibility).
#
#   1. Build AMF+SMF images from a `git worktree` of PREV (default: latest tag) as
#      5gc/{amf,smf}:rolling-prev; back up the current 5gc/{amf,smf}:dev as :rolling-cur.
#   2. prev-start: retag :dev -> PREV image, recreate amf+smf, re-attach the gNB, restart the
#      UE, wait for registration + PDU session (UE 1) and ping through the session.
#   3. UPGRADE: retag :dev -> current build, recreate amf+smf, assert (stage "upgrade").
#   4. DOWNGRADE: back to PREV images, assert again (stage "downgrade").
#   5. Restore the current build (EXIT trap, also removes the worktree).
#
# After every swap (prev-start, upgrade, downgrade) the script asserts, in this order:
#   - State gate. Within SWAP_TIMEOUT s the NEW amf/smf containers (docker logs since the swap)
#     must log
#       AMF: "AMF PostgreSQL store connected", "AMF Redis cache connected" and
#            "amf: purged stale UE contexts from previous run";
#       SMF: "SMF PostgreSQL store connected" and ("SMF: no stale sessions in store" or
#            "SMF: purged stale sessions from previous run");
#     and none of "PostgreSQL unavailable", "Redis unavailable", "LoadFromStore failed",
#     "could not list stale UE contexts", "failed to load sessions from store",
#     "failed to purge stale session from store", "panic" (re-checked at the end of the stage).
#     Both NFs only WARN and continue in memory when a store step fails, so without this gate a
#     state-compatibility regression would pass silently. The strings are identical in
#     v2.6.0-rel17-final and HEAD (nf/amf/cmd/amf/main.go, nf/amf/internal/context/context.go,
#     nf/smf/cmd/smf/main.go, nf/smf/internal/server/server.go); the SMF has no Redis.
#   - gNB re-attach. The AMF mgmt API must answer (/amf/v1/ran/gnbs); the gNB gets GNB_GRACE s to
#     show up with "state":"NG_READY", otherwise it is restarted once (SWAP_TIMEOUT s to appear).
#   - UE. MM-REGISTERED at the UE and 5GMM-REGISTERED at the AMF within UE_TIMEOUT s; while the
#     AMF has no context one uplink ping per 10 s triggers the Service Request (see (b)). Then a
#     PDU session whose address pings within SESSION_TIMEOUT s (newest session probed first).
#   - AMF canonical log present; a Service Request line in it is expected (WARN when absent).
#
# docker-compose.yml pins `image: 5gc/amf:dev` / `5gc/smf:dev`, so the swap is done by
# retagging those local images; the compose file is never edited. `make down` is never run.
# The core stack and ueransim-gnb/ueransim-ue must already be up (make ueransim UE_COUNT=1).
# After a FAIL the amf/smf containers are back on the current build (EXIT trap) but the gNB/UE
# may be detached: `make ueransim-only` restarts them.
#
# Known baselines (true of both versions, not regressions; the script works around them):
#   (a) UERANSIM v3.2.8 gNB never re-establishes SCTP after the AMF container is recreated, so
#       every swap needs a gNB restart (done once GNB_GRACE s have passed without NG_READY).
#   (b) The new AMF purges all UE contexts at start by design (nf/amf/CLAUDE.md §8), so the UE is
#       CM-IDLE and still believes it is MM-REGISTERED. Without uplink traffic it only recovers
#       after T3512 (60 s, nf/amf/config/dev.yaml) -> Registration Reject #10 -> T3511 (10 s) ->
#       re-registration. One uplink ping makes it start a Service Request (TS 24.501 §5.6.1.1,
#       user data pending; UERANSIM logs "Sending Service Request due to
#       [IDLE-UPLINK-DATA-PENDING]"); the AMF answers Service Reject #9 (TS 24.501 §5.6.1.5) and
#       the UE re-registers.
#   (c) After a re-registration UERANSIM drops the first PDU Session Establishment Request ("No
#       response from RRC from UAC checks, considering access attempt is barred"; it never
#       appears on N2); only the T3580 retransmission (16 s, TS 24.501 §10.3) gets through.
#       UERANSIM also keeps stale PS-ACTIVE sessions after Reject #9/#10 and a new session can
#       reuse a stale IP; the `from <ip>` rule points at the newest uesimtunN.
#   (d) The PREV AMF (v2.6.0-rel17-final) adds ~8 s per PDU session (NRF discovery URL bug,
#       fixed in HEAD).
#   (e) An SMF swap drops the N4 sessions (TS 29.244 §6.2.6): both versions release all sessions
#       on graceful shutdown, so the pre-swap tunnel is dead and a fresh session is needed.
#
# Final line: `PASS upgrade+downgrade` (exit 0) or `FAIL <stage>` (exit 1).
# Stages: prereq, build, prev-start, upgrade, downgrade, restore.
#
# Env: PREV (git tag), UE_CONTAINER, GNB_CONTAINER, AMF_MGMT, PING_TARGET,
#      UE_TIMEOUT (registration, default 90), SESSION_TIMEOUT (PDU session, default 90),
#      SWAP_TIMEOUT (default 60), GNB_GRACE (default 10),
#      BUILD_CURRENT=1 (rebuild current build from the tree instead of using the existing
#      :dev images), GO_VERSION.
# Ref: TS 24.501 §5.6.1 (Service Request), TS 23.502 §4.2.3.2.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

UE_CONTAINER="${UE_CONTAINER:-ueransim-ue}"
GNB_CONTAINER="${GNB_CONTAINER:-ueransim-gnb}"
AMF_MGMT="${AMF_MGMT:-http://localhost:9002}"
PING_TARGET="${PING_TARGET:-172.30.3.100}"
# UE_TIMEOUT covers the registration phase only (UE MM-REGISTERED + AMF 5GMM-REGISTERED).
UE_TIMEOUT="${UE_TIMEOUT:-90}"
# SESSION_TIMEOUT is the PDU-session phase's own deadline, started once registration is
# confirmed (it must not share UE_TIMEOUT: a slow re-registration would eat the session budget).
# It is generous on purpose: after a re-registration UERANSIM drops the first PDU Session
# Establishment Request (UAC barring), so only the T3580 retransmission (16 s, TS 24.501 §10.3)
# reaches the AMF - baseline (c) in the header - and the PREV AMF (v2.6.0-rel17-final) adds ~8 s
# per PDU session (NRF discovery URL bug fixed in HEAD) - baseline (d).
SESSION_TIMEOUT="${SESSION_TIMEOUT:-90}"
SWAP_TIMEOUT="${SWAP_TIMEOUT:-60}"
# GNB_GRACE: seconds the gNB gets to show up as NG_READY by itself before it is restarted.
GNB_GRACE="${GNB_GRACE:-10}"
GO_VERSION="${GO_VERSION:-1.26.2}"
BUILD_CURRENT="${BUILD_CURRENT:-0}"
IMAGES=(amf smf)
DRY_RUN=0
PREV="${PREV:-}"

usage() {
    cat <<USAGE
Usage: $0 [--dry-run] [--help]   (env PREV=<git tag>, default: latest tag)
Rolling upgrade/downgrade check of AMF+SMF against a previous release.
Prints 'PASS upgrade+downgrade' (exit 0) or 'FAIL <stage>' (exit 1).
Needs the core + ueransim-gnb/ueransim-ue running (make ueransim UE_COUNT=1); never edits
docker-compose.yml and never runs 'make down'.
Env (effective values): UE_TIMEOUT=$UE_TIMEOUT (registration)  SESSION_TIMEOUT=$SESSION_TIMEOUT (PDU session)
  SWAP_TIMEOUT=$SWAP_TIMEOUT  GNB_GRACE=$GNB_GRACE  BUILD_CURRENT=$BUILD_CURRENT  GO_VERSION=$GO_VERSION
  UE_CONTAINER=$UE_CONTAINER  GNB_CONTAINER=$GNB_CONTAINER  AMF_MGMT=$AMF_MGMT  PING_TARGET=$PING_TARGET
USAGE
}

for a in "$@"; do
    case "$a" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $a" >&2; usage >&2; exit 2 ;;
    esac
done

[ -n "$PREV" ] || PREV="$(git -C "$ROOT" describe --tags --abbrev=0 2>/dev/null || true)"

log() { printf '[rolling-upgrade] %s\n' "$*"; }

if [ "$DRY_RUN" = 1 ]; then
    log "PREV=${PREV:-<none>}"
    log "worktree: git worktree add <tmp> $PREV; docker build -f nf/{amf,smf}/Dockerfile --build-arg GO_VERSION=$GO_VERSION"
    log "tags: 5gc/{amf,smf}:rolling-prev (PREV), 5gc/{amf,smf}:rolling-cur (backup of :dev)"
    log "stages: prereq -> build -> prev-start -> upgrade -> downgrade -> restore"
    log "per swap: state gate (SWAP_TIMEOUT=${SWAP_TIMEOUT}s) -> gNB re-attach (GNB_GRACE=${GNB_GRACE}s, else one restart) -> UE registration (UE_TIMEOUT=${UE_TIMEOUT}s, uplink-ping Service Request trigger) -> PDU session (SESSION_TIMEOUT=${SESSION_TIMEOUT}s)"
    exit 0
fi

STAGE="prereq"
STAGE_T0=""
SWAP_SINCE=""
GATE_MISSING=""
WORKTREE=""
SWAPPED=0

fail() {
    log "FAIL at stage $STAGE: $*"
    FAIL_STAGE="$STAGE"
    if container_running amf; then
        log "--- amf/smf WARN|ERROR lines since stage start (evidence) ---"
        docker logs --since "${STAGE_T0:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" amf 2>&1 | grep -E '"level":"(WARN|ERROR)"' | cut -c1-400 | tail -15 || true
        docker logs --since "${STAGE_T0:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" smf 2>&1 | grep -E '"level":"(WARN|ERROR)"' | cut -c1-400 | tail -15 || true
    fi
    exit 1
}
FAIL_STAGE=""

cleanup() {
    local rc=$?
    set +e
    if [ "$SWAPPED" = 1 ]; then
        log "restoring current build"
        for n in "${IMAGES[@]}"; do docker tag "5gc/$n:rolling-cur" "5gc/$n:dev"; done
        (cd "$ROOT" && docker compose --profile core up -d --no-deps --pull never amf smf >/dev/null 2>&1) \
            || log "WARN: restore of amf/smf failed"
    fi
    if [ -n "$WORKTREE" ]; then
        git -C "$ROOT" worktree remove --force "$WORKTREE" >/dev/null 2>&1
        rm -rf "$WORKTREE"
    fi
    for n in "${IMAGES[@]}"; do docker rmi "5gc/$n:rolling-cur" >/dev/null 2>&1; done
    if [ "$rc" -ne 0 ]; then
        echo "FAIL ${FAIL_STAGE:-$STAGE}"
        exit 1
    fi
    exit 0
}
trap cleanup EXIT

# swap TAG - retag 5gc/{amf,smf}:dev to :TAG and recreate the containers. SWAP_SINCE (the
# `docker logs --since` anchor of the state gate) is read from the daemon's own clock, the one
# that stamps the container logs, so host/VM clock skew cannot hide the first lines of the new
# containers; fail() reuses it as the evidence window.
swap() {
    local tag="$1" n
    for n in "${IMAGES[@]}"; do docker tag "5gc/$n:$tag" "5gc/$n:dev"; done
    SWAPPED=1
    SWAP_SINCE="$(docker info -f '{{.SystemTime}}' 2>/dev/null || true)"
    [ -n "$SWAP_SINCE" ] || SWAP_SINCE="$(now_ts)"
    STAGE_T0="$SWAP_SINCE"
    (cd "$ROOT" && docker compose --profile core up -d --no-deps --pull never amf smf) >/dev/null 2>&1 \
        || fail "docker compose up amf smf ($tag)"
}

# running_image NAME - image ID of running container (to prove the swap happened).
image_of() { docker inspect -f '{{.Image}}' "$1" 2>/dev/null | cut -c8-19; }

# ---- gNB re-attach ------------------------------------------------------------
# gnb_list - one raw GET of the AMF gNB list (empty on any error). Shape (checked live):
# {"amf":{...},"generated_at":"...","gnbs":[{"id":"...","state":"NG_READY",...}]}; the other
# states are DISCONNECTED and SCTP_UP (nf/amf/internal/ngap/gnb_registry.go).
gnb_list() { curl -s --max-time 5 "$AMF_MGMT/amf/v1/ran/gnbs" 2>/dev/null || true; }

# wait_amf_api SECS - poll until the AMF management API answers with a gNB list ("gnbs" key).
wait_amf_api() {
    local deadline=$((SECONDS + $1)) body
    while :; do
        body="$(gnb_list)"
        if text_has '"gnbs"[[:space:]]*:' "$body"; then return 0; fi
        [ "$SECONDS" -ge "$deadline" ] && return 1
        sleep 2
    done
}

# wait_gnb_ready SECS - poll until a gNB is NG_READY at the AMF. The state value is matched
# exactly: "DISCONNECTED" and "SCTP_UP" entries must not count as attached.
wait_gnb_ready() {
    local deadline=$((SECONDS + $1)) body
    while :; do
        body="$(gnb_list)"
        if text_has '"state"[[:space:]]*:[[:space:]]*"NG_READY"' "$body"; then return 0; fi
        [ "$SECONDS" -ge "$deadline" ] && return 1
        sleep 2
    done
}

# reattach_gnb CTX - bring the gNB back to NG_READY at the freshly started AMF. UERANSIM v3.2.8
# never re-establishes SCTP after the AMF container is recreated (baseline (a) in the header),
# so: wait for the AMF mgmt API, give the gNB GNB_GRACE s to attach by itself, otherwise restart
# it once and wait SWAP_TIMEOUT s for NG_READY.
reattach_gnb() {
    local ctx="$1"
    wait_amf_api "$SWAP_TIMEOUT" || { log "$ctx: AMF management API $AMF_MGMT not answering within ${SWAP_TIMEOUT}s"; return 1; }
    if wait_gnb_ready "$GNB_GRACE"; then
        log "$ctx: gNB NG_READY at AMF (no restart needed)"
        return 0
    fi
    log "$ctx: gNB not NG_READY after ${GNB_GRACE}s; restarting $GNB_CONTAINER (once)"
    docker restart "$GNB_CONTAINER" >/dev/null 2>&1 || { log "$ctx: docker restart $GNB_CONTAINER failed"; return 1; }
    wait_gnb_ready "$SWAP_TIMEOUT" || { log "$ctx: gNB never NG_READY at AMF within ${SWAP_TIMEOUT}s after the restart"; return 1; }
    log "$ctx: gNB NG_READY at AMF after the restart"
    return 0
}

# ---- state-compatibility gate -------------------------------------------------
# Lines that must NOT appear in the new containers' logs: store failures (the NFs only WARN and
# carry on in memory) and panics. Alternatives are extended regexes (text_lines is grep -E).
GATE_FORBIDDEN='PostgreSQL unavailable|Redis unavailable|LoadFromStore failed|could not list stale UE contexts|failed to load sessions from store|failed to purge stale session from store|panic'

# gate_required NF - the success lines NF logs at start, one extended regex per line.
gate_required() {
    case "$1" in
        amf) printf '%s\n' \
                 'AMF PostgreSQL store connected' \
                 'AMF Redis cache connected' \
                 'amf: purged stale UE contexts from previous run' ;;
        smf) printf '%s\n' \
                 'SMF PostgreSQL store connected' \
                 'SMF: (no stale sessions in store|purged stale sessions from previous run)' ;;
    esac
}

# gate_poll CTX WHEN - evaluate the gate once on the logs of the new containers since the swap.
# Returns 0 (all success lines seen, nothing forbidden), 1 (forbidden line: printed) or
# 2 (success lines still missing: one indented line each in GATE_MISSING).
gate_poll() {
    local ctx="$1" when="$2" n logs bad pat
    GATE_MISSING=""
    for n in amf smf; do
        logs="$(container_logs "$n" "$SWAP_SINCE")"
        bad="$(text_lines "$GATE_FORBIDDEN" "$logs")"
        if [ -n "$bad" ]; then
            log "$ctx: STATE GATE FAILED ($when) - $n logged a store failure/panic since the swap:"
            { printf '%s\n' "$bad" | cut -c1-400 | sed -n '1,10p' | sed 's/^/    /'; } || true
            return 1
        fi
        while IFS= read -r pat; do
            text_has "$pat" "$logs" || GATE_MISSING="$GATE_MISSING
    $n: /$pat/"
        done <<<"$(gate_required "$n")"
    done
    [ -z "$GATE_MISSING" ] || return 2
    return 0
}

# state_gate CTX WHEN - wait up to SWAP_TIMEOUT s for the success lines (WHEN is only a label
# for the log); a forbidden line fails at once. Called right after the swap and again at the
# end of the stage (so a late panic or store failure is caught too).
state_gate() {
    local ctx="$1" when="$2" deadline rc
    deadline=$((SECONDS + SWAP_TIMEOUT))
    while :; do
        rc=0
        gate_poll "$ctx" "$when" || rc=$?
        case "$rc" in
            0) log "$ctx: state gate OK ($when): amf+smf store connected, stale state purged, no store-failure lines"; return 0 ;;
            1) return 1 ;;
        esac
        if [ "$SECONDS" -ge "$deadline" ]; then
            log "$ctx: STATE GATE FAILED ($when) - log lines not seen within ${SWAP_TIMEOUT}s of the swap:$GATE_MISSING"
            return 1
        fi
        sleep 2
    done
}

# ---- UE assertions ----------------------------------------------------------------
# ps_addrs_newest_first PS_LIST - IPv4 addresses from `nr-cli ... ps-list`, newest session
# first, each address once. ps-list numbers the sessions in creation order; UERANSIM keeps
# stale PS-ACTIVE sessions after Reject #9/#10 and a new session can reuse a stale IP, and the
# `from <ip>` rule points at the newest uesimtunN, so the newest entry decides whether an
# address works (baseline (c) in the header).
ps_addrs_newest_first() {
    sed -nE 's/^[[:space:]]*address: ([0-9.]+).*/\1/p' <<<"$1" |
        awk '{ a[NR] = $0 } END { for (i = NR; i >= 1; i--) if (!(a[i] in seen)) { seen[a[i]] = 1; print a[i] } }'
}

# send_uplink_trigger CTX SUPI GMM - the UE is MM-REGISTERED but the AMF holds no 5GMM-REGISTERED
# context for it (the new AMF purged them, baseline (b)): send one uplink packet through an
# existing PS-ACTIVE session. The CM-IDLE UE then starts a Service Request (TS 24.501 §5.6.1.1,
# user data pending), the AMF answers Service Reject #9 (§5.6.1.5) and the UE re-registers.
send_uplink_trigger() {
    local ctx="$1" supi="$2" gmm="$3" ps list a
    ps=$(nrcli "$UE_CONTAINER" "$supi" ps-list 10)
    list=$(ps_addrs_newest_first "$ps")
    a="${list%%$'\n'*}"
    if [ -z "$a" ]; then
        log "$ctx: UE MM-REGISTERED, AMF context '${gmm:-none}', but the UE lists no PDU session address to send an uplink packet from"
        return 0
    fi
    log "$ctx: UE MM-REGISTERED, AMF context '${gmm:-none}': 1 uplink ping from $a to trigger a Service Request (expect Service Reject #9, then re-registration)"
    run_timeout 5 docker exec "$UE_CONTAINER" ping -c 1 -W 1 -I "$a" "$PING_TARGET" >/dev/null 2>&1 || true
}

# assert_ue CTX - UE registered at UE + AMF, PS-ACTIVE session that pings.
assert_ue() {
    local ctx="$1" deadline sdeadline supi="" st="" gmm="" ps="" addr="" ctxj
    local last_sr=-100 tries=0 a ok=0 reest=0
    # Phase 1 - registration, deadline UE_TIMEOUT.
    deadline=$((SECONDS + UE_TIMEOUT))
    while :; do
        [ -z "$supi" ] && supi=$(nr_cli_bounded 10 "$UE_CONTAINER" --dump 2>/dev/null | awk '/^imsi-/ {print $1; exit}' || true)
        if [ -n "$supi" ]; then
            st=$(nrcli "$UE_CONTAINER" "$supi" status 10)
            ctxj=$(curl -s --max-time 5 "$AMF_MGMT/amf/v1/ue-contexts/$supi" 2>/dev/null || true)
            gmm=$(json_str_last gmm_state "$ctxj")
            if text_has 'mm-state: MM-REGISTERED' "$st"; then
                [ "$gmm" = "5GMM-REGISTERED" ] && break
                # UE believes it is registered, the AMF has no (or no registered) context:
                # trigger the Service Request, at most every 10 s.
                if [ $((SECONDS - last_sr)) -ge 10 ]; then
                    last_sr=$SECONDS
                    send_uplink_trigger "$ctx" "$supi" "$gmm"
                fi
            fi
        fi
        [ "$SECONDS" -ge "$deadline" ] && { log "$ctx: not registered within ${UE_TIMEOUT}s (supi=${supi:-none} gmm=${gmm:-none})"; return 1; }
        sleep 3
    done
    log "$ctx: $supi MM-REGISTERED, AMF 5GMM-REGISTERED"
    # Phase 2 - PDU session, own deadline SESSION_TIMEOUT (see its definition for why).
    # An SMF swap drops the N4 sessions on the UPF (TS 29.244 §6.2.6, SMF-004: sessions are
    # not restored), so the pre-swap tunnel may be dead. Accept any PS-ACTIVE session whose
    # own address pings (newest first); otherwise establish a fresh one on the new SMF and
    # require that.
    sdeadline=$((SECONDS + SESSION_TIMEOUT))
    while [ "$ok" = 0 ]; do
        ps=$(nrcli "$UE_CONTAINER" "$supi" ps-list 10)
        for a in $(ps_addrs_newest_first "$ps"); do
            if run_timeout 15 docker exec "$UE_CONTAINER" ping -c 2 -W 2 -I "$a" "$PING_TARGET" >/dev/null 2>&1; then
                addr="$a"; ok=1; break
            fi
        done
        [ "$ok" = 1 ] && break
        [ "$SECONDS" -ge "$sdeadline" ] && { log "$ctx: no PDU session reaches $PING_TARGET within ${SESSION_TIMEOUT}s (sessions: $(tr '\n' ' ' <<<"$ps" | tr -s ' '))"; return 1; }
        if [ "$reest" = 0 ] || [ "$tries" -ge 5 ]; then
            log "$ctx: no working PDU session; ps-establish IPv4 --dnn internet"
            nrcli "$UE_CONTAINER" "$supi" "ps-establish IPv4 --dnn internet" 15 >/dev/null
            reest=1; tries=0
        fi
        tries=$((tries + 1)); sleep 3
    done
    [ "$reest" = 1 ] && log "$ctx: NOTE PDU session had to be re-established (N4 sessions dropped on SMF swap)"
    log "$ctx: PDU session PS-ACTIVE, ping $PING_TARGET from $addr OK"
    return 0
}

# post_swap CTX - after the AMF/SMF swap: state gate, gNB re-attach (the gNB SCTP association
# is gone), then require the UE to be usable again and the new AMF to log a Service Request
# (or Registration) for it, and re-run the gate for late failures.
post_swap() {
    local ctx="$1" logs
    state_gate "$ctx" "after swap" || return 1
    reattach_gnb "$ctx" || return 1
    assert_ue "$ctx" || return 1
    logs="$(container_logs amf "$SWAP_SINCE")"
    if grep -qiE 'ServiceRequest|service.request' <<<"$logs"; then
        log "$ctx: AMF canonical log shows Service Request"
    else
        log "$ctx: WARN no Service Request line in AMF logs (UE re-registered instead?)"
    fi
    grep -qE '"nf":"AMF"' <<<"$logs" || { log "$ctx: no canonical AMF logs"; return 1; }
    state_gate "$ctx" "end of stage" || return 1
    return 0
}

# ---- prereq -----------------------------------------------------------------
require_cmds docker git curl
[ -n "$PREV" ] || fail "no PREV tag (set PREV=<git tag>)"
git -C "$ROOT" rev-parse -q --verify "refs/tags/$PREV" >/dev/null || fail "tag $PREV not found"
for c in amf smf "$UE_CONTAINER" "$GNB_CONTAINER"; do
    container_running "$c" || fail "container $c is not running (make ueransim UE_COUNT=1)"
done
for n in "${IMAGES[@]}"; do
    docker image inspect "5gc/$n:dev" >/dev/null 2>&1 || fail "image 5gc/$n:dev missing"
done

# ---- build -------------------------------------------------------------------
STAGE="build"
if [ "$BUILD_CURRENT" = 1 ]; then
    log "building current build as 5gc/{amf,smf}:dev"
    for n in "${IMAGES[@]}"; do
        docker build -q --build-arg "GO_VERSION=$GO_VERSION" -f "$ROOT/nf/$n/Dockerfile" -t "5gc/$n:dev" "$ROOT" >/dev/null \
            || fail "current build $n"
    done
fi
for n in "${IMAGES[@]}"; do docker tag "5gc/$n:dev" "5gc/$n:rolling-cur"; done
WORKTREE="$(mktemp -d "${TMPDIR:-/tmp}/rolling-prev.XXXXXX")"
git -C "$ROOT" worktree add --detach -f "$WORKTREE" "$PREV" >/dev/null 2>&1 || fail "git worktree add $PREV"
for n in "${IMAGES[@]}"; do
    log "building PREV ($PREV) $n image"
    docker build -q --build-arg "GO_VERSION=$GO_VERSION" -f "$WORKTREE/nf/$n/Dockerfile" -t "5gc/$n:rolling-prev" "$WORKTREE" >/dev/null \
        || fail "PREV build $n"
done

# ---- PREV start --------------------------------------------------------------
STAGE="prev-start"
log "starting from PREV $PREV"
swap rolling-prev
log "amf image $(image_of amf), smf image $(image_of smf)"
state_gate "prev" "after swap" || fail "state gate on PREV start"
# UE 1 registers from scratch against PREV: re-attach the gNB, then bounce the UE.
reattach_gnb "prev" || fail "gNB NG Setup with PREV AMF"
docker restart "$UE_CONTAINER" >/dev/null 2>&1 || fail "restart UE"
sleep 5
assert_ue "prev" || fail "UE 1 registration/PDU session on PREV"
state_gate "prev" "end of stage" || fail "state gate on PREV (late store failure or panic)"

# ---- upgrade -----------------------------------------------------------------
STAGE="upgrade"
log "UPGRADE $PREV -> current"
swap rolling-cur
log "amf image $(image_of amf), smf image $(image_of smf)"
post_swap "upgrade" || fail "assertions after upgrade"

# ---- downgrade ---------------------------------------------------------------
STAGE="downgrade"
log "DOWNGRADE current -> $PREV"
swap rolling-prev
log "amf image $(image_of amf), smf image $(image_of smf)"
post_swap "downgrade" || fail "assertions after downgrade"

# ---- restore -----------------------------------------------------------------
STAGE="restore"
for n in "${IMAGES[@]}"; do docker tag "5gc/$n:rolling-cur" "5gc/$n:dev"; done
(cd "$ROOT" && docker compose --profile core up -d --no-deps --pull never amf smf) >/dev/null 2>&1 || fail "restore compose up"
SWAPPED=0
# Best effort: leave the gNB attached to the restored AMF; never changes the verdict.
reattach_gnb "restore" || log "WARN: gNB not NG_READY at the restored AMF; run 'make ueransim-only'"
echo "PASS upgrade+downgrade"
