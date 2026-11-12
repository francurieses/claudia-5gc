#!/usr/bin/env bash
# scripts/mixed-release-e2e.sh
# REL19-10.2 - mixed-release interworking: Rel-19 AMF against a Rel-17-behaving SMF/PCF, then the
# reverse (Rel-17 AMF, Rel-19 SMF/PCF).
#
#   make mixed-release-e2e
#
# For each direction (A = AMF rel19 / SMF+PCF rel17, B = AMF rel17 / SMF+PCF rel19) the script:
#   1. starts a tcpdump on core-pcap (pcaps/core/mixed-release-<dir>.pcap, SBI TCP ports 8000-8099 only: inter-NF SBI runs on
#      both the 5gc-sbi and 5gc-obs bridges, so a subnet filter would miss it) and
#      recreates amf+smf+pcf with docker-compose.mixed-release.yml (NF_RELEASE_PROFILE per NF,
#      SSLKEYLOGFILE -> pcaps/mixed-keys/<nf>-<dir>.keys); the new containers' logs must show the
#      requested release_profile;
#   2. re-attaches the UERANSIM gNB (restart once if it does not reach NG_READY), restarts the
#      UE and waits for registration + a PDU session that pings (T3580 retransmit: generous
#      timeouts, see scripts/rolling-upgrade-check.sh baselines (a)-(c));
#   3. asserts the FeatureNegotiation log lines (TS 29.500 §6.6.2) of SMF (IN from AMF, Nsmf),
#      PCF (IN from AMF and from SMF, Npcf) and AMF (OUT to SMF, Nsmf): for every line
#      features_negotiated == features_local AND features_peer (bitwise on the hex values, an
#      absent peer gives 0), and at least one line per leg exists;
#   4. asserts the NRF discovery answer (mTLS GET /nnrf-disc/v1/nf-instances) carries the
#      apiFullVersion of the NF's release profile (table: shared/sbi/apiversion) for
#      nsmf-pdusession (SMF), npcf-smpolicycontrol (PCF), namf-comm (AMF);
#   5. stops the capture and decrypts it with the key logs (tshark): the Nsmf CreateSMContext
#      body carries supportedFeatures "80" in direction A (Rel-19 AMF offers ES3XX) and the
#      distinct supportedFeatures values on the wire are printed per direction.
# After both directions the apiFullVersion of PCF and AMF must differ between A and B (SMF: WARN
# only if SMF_STRICT_NRF_VERSION=0, see below).
#
# The EXIT trap recreates amf/smf/pcf from docker-compose.yml alone (default rel17, no override,
# no SSLKEYLOGFILE), re-attaches the gNB, restarts the UE and waits for registration + PDU
# session, so the stack is left healthy. `make down` is never run; other containers
# (roaming hnrf/hsepp/vsepp, ...) are untouched. Needs `make ueransim UE_COUNT=1` and `make pki`.
#
# Final line: `PASS mixed-release (A: amf19/core17, B: amf17/core19)` (exit 0) or `FAIL <stage>`.
# Env: UE_CONTAINER, GNB_CONTAINER, AMF_MGMT, PING_TARGET, NRF_URL, WAIT (container/NRF waits,
#      default 90), UE_TIMEOUT (registration, default 90), SESSION_TIMEOUT (default 120),
#      GNB_GRACE (default 10), STRICT_NRF_VERSION (default 1, see check_nrf).
# Ref: TS 29.500 §6.6.2 (supportedFeatures negotiation), TS 29.510 §6.1.6.2.19 (NFServiceVersion).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"
cd "$ROOT"

UE_CONTAINER="${UE_CONTAINER:-ueransim-ue}"
GNB_CONTAINER="${GNB_CONTAINER:-ueransim-gnb}"
AMF_MGMT="${AMF_MGMT:-http://localhost:9002}"
NRF_URL="${NRF_URL:-https://localhost:8000}"
PING_TARGET="${PING_TARGET:-172.30.3.100}"
WAIT="${WAIT:-90}"
UE_TIMEOUT="${UE_TIMEOUT:-90}"
SESSION_TIMEOUT="${SESSION_TIMEOUT:-120}"
GNB_GRACE="${GNB_GRACE:-10}"
# STRICT_NRF_VERSION=1: a NRF apiFullVersion that does not follow the release profile is a FAIL
# (default). AMF, PCF and SMF all register per profile (NRF-VER-001); SMF_STRICT_NRF_VERSION
# (default 1) is kept as a separate knob so the SMF check can be relaxed to WARN with 0.
STRICT_NRF_VERSION="${STRICT_NRF_VERSION:-1}"
SMF_STRICT_NRF_VERSION="${SMF_STRICT_NRF_VERSION:-1}"
KEYS_DIR="pcaps/mixed-keys"
PCAP_DIR="pcaps/core"
APIVER_GO="shared/sbi/apiversion/apiversion.go"
COMPOSE_BASE=(docker compose --profile core)
COMPOSE_MIXED=(docker compose --profile core -f docker-compose.yml -f docker-compose.mixed-release.yml)

log() { printf '[mixed-release] %s\n' "$*"; }
STAGE="prereq"
FAIL_STAGE=""
ENV_DIRTY=0
VERDICT_PASS=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/mixed-release.XXXXXX")"
PASS=0; FAILS=0; WARNS=0
ok()  { log "  PASS $*"; PASS=$((PASS + 1)); }
warn() { log "  WARN $*"; WARNS=$((WARNS + 1)); }
bad() { log "  FAIL $*"; FAILS=$((FAILS + 1)); }
fail() { log "FAIL at stage $STAGE: $*"; FAIL_STAGE="$STAGE"; exit 1; }

# ---- gNB / UE helpers (same approach as scripts/rolling-upgrade-check.sh) --------------------
gnb_list() { curl -s --max-time 5 "$AMF_MGMT/amf/v1/ran/gnbs" 2>/dev/null || true; }

wait_amf_api() {
    local deadline=$((SECONDS + $1)) body
    while :; do
        body="$(gnb_list)"
        if text_has '"gnbs"[[:space:]]*:' "$body"; then return 0; fi
        [ "$SECONDS" -ge "$deadline" ] && return 1
        sleep 2
    done
}

wait_gnb_ready() {
    local deadline=$((SECONDS + $1)) body
    while :; do
        body="$(gnb_list)"
        if text_has '"state"[[:space:]]*:[[:space:]]*"NG_READY"' "$body"; then return 0; fi
        [ "$SECONDS" -ge "$deadline" ] && return 1
        sleep 2
    done
}

# reattach_gnb CTX - UERANSIM v3.2.8 never re-establishes SCTP after the AMF is recreated:
# give the gNB GNB_GRACE s, then restart it once.
reattach_gnb() {
    local ctx="$1"
    wait_amf_api "$WAIT" || { log "$ctx: AMF management API $AMF_MGMT not answering within ${WAIT}s"; return 1; }
    if wait_gnb_ready "$GNB_GRACE"; then log "$ctx: gNB NG_READY (no restart needed)"; return 0; fi
    log "$ctx: gNB not NG_READY after ${GNB_GRACE}s; restarting $GNB_CONTAINER"
    docker restart "$GNB_CONTAINER" >/dev/null 2>&1 || return 1
    wait_gnb_ready "$WAIT" || { log "$ctx: gNB never NG_READY within ${WAIT}s"; return 1; }
    log "$ctx: gNB NG_READY after the restart"
}

# ps_addrs_newest_first PS_LIST - IPv4 addresses of `ps-list`, newest session first.
ps_addrs_newest_first() {
    sed -nE 's/^[[:space:]]*address: ([0-9.]+).*/\1/p' <<<"$1" |
        awk '{ a[NR] = $0 } END { for (i = NR; i >= 1; i--) if (!(a[i] in seen)) { seen[a[i]] = 1; print a[i] } }'
}

# assert_ue CTX - UE MM-REGISTERED (UE and AMF) and a PS-ACTIVE session whose address pings.
assert_ue() {
    local ctx="$1" deadline sdeadline supi="" st="" gmm="" ps="" addr="" ctxj tries=0 a ok=0 reest=0
    deadline=$((SECONDS + UE_TIMEOUT))
    while :; do
        [ -z "$supi" ] && supi=$(nr_cli_bounded 10 "$UE_CONTAINER" --dump 2>/dev/null | awk '/^imsi-/ {print $1; exit}' || true)
        if [ -n "$supi" ]; then
            st=$(nrcli "$UE_CONTAINER" "$supi" status 10)
            ctxj=$(curl -s --max-time 5 "$AMF_MGMT/amf/v1/ue-contexts/$supi" 2>/dev/null || true)
            gmm=$(json_str_last gmm_state "$ctxj")
            if text_has 'mm-state: MM-REGISTERED' "$st" && [ "$gmm" = "5GMM-REGISTERED" ]; then break; fi
        fi
        [ "$SECONDS" -ge "$deadline" ] && { log "$ctx: not registered within ${UE_TIMEOUT}s (supi=${supi:-none} gmm=${gmm:-none})"; return 1; }
        sleep 3
    done
    log "$ctx: $supi MM-REGISTERED, AMF 5GMM-REGISTERED"
    sdeadline=$((SECONDS + SESSION_TIMEOUT))
    while [ "$ok" = 0 ]; do
        ps=$(nrcli "$UE_CONTAINER" "$supi" ps-list 10)
        for a in $(ps_addrs_newest_first "$ps"); do
            if run_timeout 15 docker exec "$UE_CONTAINER" ping -c 2 -W 2 -I "$a" "$PING_TARGET" >/dev/null 2>&1; then
                addr="$a"; ok=1; break
            fi
        done
        [ "$ok" = 1 ] && break
        [ "$SECONDS" -ge "$sdeadline" ] && { log "$ctx: no PDU session reaches $PING_TARGET within ${SESSION_TIMEOUT}s"; return 1; }
        # first PDU Session Establishment can be lost to the UAC race (T3580 retransmit, 16 s)
        if [ "$reest" = 0 ] || [ "$tries" -ge 8 ]; then
            if [ "$reest" = 1 ]; then
                log "$ctx: still no working PDU session; ps-establish IPv4 --dnn internet"
                nrcli "$UE_CONTAINER" "$supi" "ps-establish IPv4 --dnn internet" 15 >/dev/null
                tries=0
            fi
            reest=1
        fi
        tries=$((tries + 1)); sleep 3
    done
    log "$ctx: PDU session PS-ACTIVE, ping $PING_TARGET from $addr OK"
}

# bring_ue_up CTX - gNB re-attach, UE restart, registration + PDU session.
bring_ue_up() {
    local ctx="$1"
    reattach_gnb "$ctx" || return 1
    docker restart "$UE_CONTAINER" >/dev/null 2>&1 || return 1
    sleep 5
    assert_ue "$ctx"
}

# ---- restore (EXIT trap) --------------------------------------------------------------------
cleanup() {
    local rc=$?
    set +e
    docker exec core-pcap pkill -INT tcpdump >/dev/null 2>&1
    if [ "$ENV_DIRTY" = 1 ]; then
        log "restoring defaults: amf/smf/pcf from docker-compose.yml alone"
        env -u NF_RELEASE_PROFILE -u MIXED_AMF_PROFILE -u MIXED_CORE_PROFILE -u MIXED_TAG \
            "${COMPOSE_BASE[@]}" up -d --no-deps --pull never --force-recreate amf smf pcf >/dev/null 2>&1 \
            || { log "WARN: restore of amf/smf/pcf failed"; rc=1; FAIL_STAGE="${FAIL_STAGE:-restore}"; }
        if ! bring_ue_up "restore"; then
            log "WARN: UE not re-registered after restore; run 'make ueransim-only'"
            rc=1; FAIL_STAGE="${FAIL_STAGE:-restore}"
        fi
    fi
    rm -rf "$TMP"
    if [ "$rc" -ne 0 ]; then echo "FAIL ${FAIL_STAGE:-$STAGE}"; exit 1; fi
    [ "$VERDICT_PASS" = 1 ] && echo "PASS mixed-release (A: amf19/core17, B: amf17/core19)"
    exit 0
}
trap cleanup EXIT

# ---- feature negotiation assertions ----------------------------------------------------------
# jfield KEY - first string value of "KEY":"..." on stdin line.
jfield() { sed -nE "s/.*\"$1\":\"([^\"]*)\".*/\1/p"; }

# check_negotiation LABEL CONTAINER NF INTERFACE DIRECTION PEER_NF
# Every matching FeatureNegotiation line must satisfy negotiated == local & peer (peer "absent"
# counts as 0); at least one line must exist. Prints the distinct (local, peer, negotiated).
check_negotiation() {
    local label="$1" c="$2" nf="$3" iface="$4" dir="$5" peer_nf="$6" logs lines n=0 badn=0 line l p g pv samples=""
    logs="$(container_logs "$c")"
    lines="$(grep -E '"procedure":"FeatureNegotiation"' <<<"$logs" | grep -F "\"nf\":\"$nf\"" | grep -F "\"interface\":\"$iface\"" \
        | grep -F "\"direction\":\"$dir\"" | grep -F "\"peer_nf_type\":\"$peer_nf\"" || true)"
    if [ -z "$lines" ]; then bad "$label: no FeatureNegotiation line ($nf $iface $dir peer=$peer_nf)"; return; fi
    while IFS= read -r line; do
        n=$((n + 1))
        l="$(jfield features_local <<<"$line")"; p="$(jfield features_peer <<<"$line")"; g="$(jfield features_negotiated <<<"$line")"
        pv="$p"; [ "$p" = "absent" ] && pv="0"
        if ! [[ "$l" =~ ^[0-9a-fA-F]{1,12}$ && "$pv" =~ ^[0-9a-fA-F]{1,12}$ && "$g" =~ ^[0-9a-fA-F]{1,12}$ ]]; then
            badn=$((badn + 1)); log "    unparsable local=$l peer=$p negotiated=$g"; continue
        fi
        if [ $(( 16#$g )) -ne $(( 16#$l & 16#$pv )) ]; then
            badn=$((badn + 1)); log "    MISMATCH local=$l peer=$p negotiated=$g"
        fi
        case " $samples " in *" local=$l,peer=$p,negotiated=$g "*) ;; *) samples="$samples local=$l,peer=$p,negotiated=$g" ;; esac
    done <<<"$lines"
    if [ "$badn" = 0 ]; then ok "$label: $n line(s), negotiated = local & peer;$samples"; else bad "$label: $badn of $n line(s) violate negotiated = local & peer"; fi
}

# ---- NRF discovery -----------------------------------------------------------------------------
# expected_version SERVICE_CONST PROFILE - apiFullVersion from the apiversion table (Rel17|Rel19).
expected_version() {
    local row
    row="$(grep -E "^[[:space:]]*\{$1," "$APIVER_GO" | head -1)"
    [ -n "$row" ] || return 1
    if [ "$2" = rel19 ]; then grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' <<<"$row" | tail -1 | tr -d '"'
    else grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' <<<"$row" | tail -2 | head -1 | tr -d '"'; fi
}

# nrf_version NFTYPE SERVICE - apiFullVersion(s) of SERVICE in the NRF discovery answer for NFTYPE.
nrf_version() {
    curl -s --max-time 8 --cacert pki/ca.crt --cert pki/amf.crt --key pki/amf.key \
        "$NRF_URL/nnrf-disc/v1/nf-instances?target-nf-type=$1&requester-nf-type=AMF" 2>/dev/null |
        jq -r --arg s "$2" '[.nfInstances[]?.nfServices[]? | select(.serviceName == $s) | .versions[]?.apiFullVersion] | unique | join(",")' 2>/dev/null || true
}

# check_nrf LABEL NFTYPE SERVICE SERVICE_CONST PROFILE VARNAME - waits for the NRF to return the
# profile's version (the NF re-registers after the recreate); stores the value in VARNAME.
check_nrf() {
    local label="$1" t="$2" svc="$3" const="$4" prof="$5" var="$6" strict="${7:-$STRICT_NRF_VERSION}" want got deadline
    want="$(expected_version "$const" "$prof")" || { bad "$label: no apiversion row for $const"; return; }
    deadline=$((SECONDS + WAIT))
    while :; do
        got="$(nrf_version "$t" "$svc")"
        [ "$got" = "$want" ] && break
        [ "$SECONDS" -ge "$deadline" ] && break
        sleep 2
    done
    printf -v "$var" '%s' "$got"
    if [ "$got" = "$want" ]; then ok "NRF discovery $label: $svc apiFullVersion $got ($prof)"
    elif [ "$strict" != 1 ] && [ "$got" = "$(expected_version "$const" rel17)" ]; then
        # KNOWN GAP: every NF registers with nrf.ServiceVersion(nil, ...) (rel17 column) whatever
        # its release profile; STRICT_NRF_VERSION=1 turns this into a failure.
        warn "NRF discovery $label: $svc apiFullVersion $got is the rel17 value under $prof (expected $want; NF registers ServiceVersion(nil,...))"
    else bad "NRF discovery $label: $svc apiFullVersion '$got', expected $want ($prof)"; fi
}

# ---- pcap ---------------------------------------------------------------------------------------
# decrypt_pcap TAG - tshark decrypt with the key logs; fills TMP/json-TAG.txt; prints evidence.
decrypt_pcap() {
    local tag="$1" pcap="$PCAP_DIR/mixed-release-$1.pcap" keys="$KEYS_DIR/all-$1.keys" P K cnt vals
    local ts=(tshark)
    if [ ! -s "$pcap" ]; then bad "pcap $pcap missing or empty"; return; fi
    ok "pcap $pcap ($(wc -c <"$pcap" | tr -d ' ') bytes)"
    cat "$KEYS_DIR"/*-"$tag".keys >"$keys" 2>/dev/null || true
    if [ ! -s "$keys" ]; then bad "no TLS key log for $tag (SSLKEYLOGFILE not honoured?)"; return; fi
    ok "TLS key log $keys ($(grep -c . "$keys") secrets)"
    P="$pcap"; K="$keys"
    if ! command -v tshark >/dev/null 2>&1; then
        ts=(docker run --rm -v "$ROOT/pcaps:/p" nicolaka/netshoot tshark)
        P="/p/core/mixed-release-$tag.pcap"; K="/p/mixed-keys/all-$tag.keys"
    fi
    # SBI ports are not in Wireshark's default TLS port list: enable the TLS-over-TCP heuristic.
    # The Nsmf bodies are multipart/related, which tshark does not parse as JSON, so the HTTP/2
    # DATA payloads are decoded from hex and scanned for the supportedFeatures attribute.
    "${ts[@]}" -r "$P" -o "tls.keylog_file:$K" --enable-heuristic tls_tcp -Y 'http2.type == 0' \
        -T fields -e http2.data.data 2>/dev/null | tr -d ':,' |
        while IFS= read -r h; do [ -n "$h" ] && { printf '%s' "$h" | xxd -r -p | tr -c '[:print:]' '.'; echo; }; done >"$TMP/data-$tag.txt" || true
    grep -oE '"supportedFeatures":"[0-9a-fA-F]*"' "$TMP/data-$tag.txt" | sed -E 's/"supportedFeatures":"([^"]*)"/supportedFeatures:\1/' |
        sort | uniq -c >"$TMP/sf-$tag.txt" || true
    vals="$(awk '{printf "%s(x%s) ", $2, $1}' "$TMP/sf-$tag.txt")"
    log "  info decrypted supportedFeatures on the wire ($tag): ${vals:-none}"
    log "  info decrypted HTTP/2 DATA frames: $(grep -c . "$TMP/data-$tag.txt" || true)"
    cp "$TMP/sf-$tag.txt" "$PCAP_DIR/mixed-release-$tag.wire.txt" 2>/dev/null || true
    cnt="$("${ts[@]}" -r "$P" -o "tls.keylog_file:$K" --enable-heuristic tls_tcp -Y '_ws.malformed' 2>/dev/null | wc -l | tr -d ' ')"
    [ "${cnt:-0}" = 0 ] && ok "no malformed frames in $tag pcap" || bad "$cnt malformed frame(s) in $tag pcap"
    WIRE_VALUES="$(awk '{print $2}' "$TMP/sf-$tag.txt" | tr '\n' ' ')"
}

# ---- one direction ---------------------------------------------------------------------------------
# run_direction TAG AMF_PROFILE CORE_PROFILE PREFIX
V_SMF=""; V_PCF=""; V_AMF=""
run_direction() {
    local tag="$1" ap="$2" cp="$3" pre="$4" nf pcap="mixed-release-$1.pcap"
    log "=== direction $tag: AMF=$ap SMF=$cp PCF=$cp"
    STAGE="$tag-recreate"
    rm -f "$KEYS_DIR"/*-"$tag".keys "$KEYS_DIR/all-$tag.keys" "$PCAP_DIR/$pcap"
    docker exec -d core-pcap tcpdump -i any -U -s 0 -w "/pcaps/$pcap" 'tcp and portrange 8000-8099' \
        || fail "tcpdump start on core-pcap"
    sleep 2
    ENV_DIRTY=1
    MIXED_AMF_PROFILE="$ap" MIXED_CORE_PROFILE="$cp" MIXED_TAG="$tag" \
        "${COMPOSE_MIXED[@]}" up -d --no-deps --pull never --force-recreate amf smf pcf >/dev/null 2>&1 \
        || fail "compose up amf smf pcf ($tag)"
    for nf in amf smf pcf; do
        local want="$ap"; [ "$nf" != amf ] && want="$cp"
        wait_for_log "$nf" "\"release_profile\":\"$want\"" "$WAIT" \
            && ok "$nf runs release profile $want" || bad "$nf release profile is not $want"
    done
    STAGE="$tag-ue"
    bring_ue_up "$tag" || fail "gNB/UE/PDU session in direction $tag"
    ok "registration + PDU session (ping $PING_TARGET) with AMF=$ap SMF/PCF=$cp"

    STAGE="$tag-negotiation"
    log "--- FeatureNegotiation logs ($tag)"
    check_negotiation "SMF IN from AMF (Nsmf)" smf SMF Nsmf IN AMF
    check_negotiation "PCF IN from AMF (Npcf)" pcf PCF Npcf IN AMF
    check_negotiation "PCF IN from SMF (Npcf)" pcf PCF Npcf IN SMF
    check_negotiation "AMF OUT to SMF (Nsmf)" amf AMF Nsmf OUT SMF

    STAGE="$tag-nrf"
    log "--- NRF discovery apiFullVersion ($tag)"
    check_nrf "SMF" SMF nsmf-pdusession NsmfPDUSession "$cp" "${pre}SMF" "$SMF_STRICT_NRF_VERSION"
    check_nrf "PCF" PCF npcf-smpolicycontrol NpcfSMPolicyControl "$cp" "${pre}PCF"
    check_nrf "AMF" AMF namf-comm NamfComm "$ap" "${pre}AMF"

    STAGE="$tag-pcap"
    log "--- pcap + keylog ($tag)"
    sleep 2
    docker exec core-pcap pkill -INT tcpdump >/dev/null 2>&1 || true
    sleep 2
    WIRE_VALUES=""
    decrypt_pcap "$tag"
    if [ "$ap" = rel19 ]; then
        case " $WIRE_VALUES " in *" supportedFeatures:80 "*) ok "$tag: Rel-19 AMF offers supportedFeatures 80 (Nsmf ES3XX) on the wire" ;;
            *) bad "$tag: supportedFeatures 80 not seen on the wire" ;; esac
    else
        case " $WIRE_VALUES " in *" supportedFeatures:80 "*) bad "$tag: Rel-17 AMF must not offer supportedFeatures 80" ;;
            *) ok "$tag: no supportedFeatures 80 on the wire (Rel-17 AMF sends none)" ;; esac
    fi
}

# ---- prereq ---------------------------------------------------------------------------------------------
require_cmds docker curl jq
for f in pki/ca.crt pki/amf.crt pki/amf.key docker-compose.mixed-release.yml "$APIVER_GO"; do
    [ -f "$f" ] || fail "missing $f (make pki?)"
done
for c in nrf amf smf pcf core-pcap "$UE_CONTAINER" "$GNB_CONTAINER"; do
    container_running "$c" || fail "container $c is not running (make ueransim UE_COUNT=1)"
done
mkdir -p "$KEYS_DIR" "$PCAP_DIR"; chmod 777 "$KEYS_DIR"

T0=$SECONDS
run_direction "amf19-core17" rel19 rel17 A_
SMF_A="$A_SMF"; PCF_A="$A_PCF"; AMF_A="$A_AMF"
run_direction "amf17-core19" rel17 rel19 B_
STAGE="compare"
log "=== cross-direction: apiFullVersion must differ"
differ() { # differ LABEL A B [STRICT]
    if [ "$2" != "$3" ]; then ok "$1 $2 (A) vs $3 (B)"
    elif [ "${4:-$STRICT_NRF_VERSION}" = 1 ]; then bad "$1 identical in both directions ($2)"
    else warn "$1 identical in both directions ($2): known gap, the NF registers the rel17 apiFullVersion under every profile"; fi
}
differ "SMF nsmf-pdusession" "$SMF_A" "$B_SMF" "$SMF_STRICT_NRF_VERSION"
differ "PCF npcf-smpolicycontrol" "$PCF_A" "$B_PCF"
differ "AMF namf-comm" "$AMF_A" "$B_AMF"

log "assertions: PASS=$PASS FAIL=$FAILS WARN=$WARNS in $((SECONDS - T0))s"
log "pcaps: $PCAP_DIR/mixed-release-amf19-core17.pcap  $PCAP_DIR/mixed-release-amf17-core19.pcap"
log "keylogs: $KEYS_DIR/all-amf19-core17.keys  $KEYS_DIR/all-amf17-core19.keys"
[ "$FAILS" = 0 ] || { FAIL_STAGE="assertions"; exit 1; }
VERDICT_PASS=1   # printed by the EXIT trap once the defaults are restored and the UE is back
