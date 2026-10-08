#!/usr/bin/env bash
#
# validate-ueransim-mod.sh — end-to-end validation of the modified UERANSIM
# features (tools/ueransim/patches) against the running 5GC.
#
# Prerequisite: the stack is up with the modified image, e.g. `make ueransim`.
#
# Sub-commands:
#   ursp        URSP delivery round-trip: AMF sends MANAGE UE POLICY COMMAND,
#               modded UE replies MANAGE UE POLICY COMPLETE (AMF logs the ACK).
#   ursp-cli    nr-cli introspection: ursp-show + ursp-match on the UE.
#   ursp-steer  URSP-steered additional PDU session via nr-cli ursp-establish.
#   qos-mod     NW-initiated QoS modification: SMF 0xCB -> UE 0xCC round-trip.
#   location    Cell-ID positioning: LMF DetermineLocation -> AMF -> NGAP LocationReportingControl
#               -> modded gNB LocationReport; checks NRCGI + that the LMF mobility model moves.
#   nrppa       E-CID positioning: LMF DetermineLocation (hAccuracy=100) -> AMF NRPPa relay
#               -> modded gNB NRPPa-Transport (ProcCode 8 DL / 50 UL); checks positioningDataList
#               =["eCID"] + uncertainty <=150 m + gNB/AMF NRPPa log lines.
#   gnss        A-GNSS positioning: LMF DetermineLocation (hAccuracy=30) -> AMF LPP relay (DL/UL
#               NAS Transport, payload container type 3) -> modded UE LPP responder (patch 0042);
#               checks positioningDataList=["gnss"] + uncertainty <=50 m + UE/AMF/LMF LPP log lines.
#   all         run every check in sequence; exits 1 if any check failed (✗).
#
# Portable to macOS bash 3.2 + BSD userland (helpers in scripts/lib/common.sh). Log checks
# only look at lines emitted after the check's trigger (`docker logs --since`), and every
# docker exec / nr-cli call is time-bounded.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

require_cmds docker curl python3

# Precondition: these checks drive UERANSIM, which is optional (RAN=ueransim).
DOCKER_NAMES=$(docker ps --format '{{.Names}}' 2>/dev/null || true)
if ! text_has '^ueransim-' "$DOCKER_NAMES"; then
    echo "UERANSIM not deployed — run: make ueransim (or make up-obs RAN=ueransim)" >&2
    exit 2
fi

# Pick the first actually-running candidate container. The `make ueransim*`
# scenarios (standard / multi-slice / suci-profile-a) name the UE/gNB containers
# differently, and `make ueransim-all` runs all of them at once, so candidates are
# listed in preference order: the default-scenario UE (ueransim-ue on ueransim-gnb)
# wins whenever it is up. Override with UE_CONTAINER / GNB_CONTAINER / SUPI.
detect_container() {
    local c
    for c in "$@"; do
        if container_running "$c"; then
            printf '%s' "$c"; return 0
        fi
    done
    printf '%s' "$1"
}

UE_CONTAINER="${UE_CONTAINER:-$(detect_container ueransim-ue ueransim-ue-profile-a ueransim-ue-internet)}"
# The gNB follows the UE: multi-slice UEs attach to ueransim-gnb-ms, the rest to ueransim-gnb.
case "$UE_CONTAINER" in
    ueransim-ue-internet|ueransim-ue-gold|ueransim-ue-silver|ueransim-ue-bronze)
        GNB_CONTAINER="${GNB_CONTAINER:-ueransim-gnb-ms}" ;;
    *)  GNB_CONTAINER="${GNB_CONTAINER:-$(detect_container ueransim-gnb ueransim-gnb-ms)}" ;;
esac
# Default SUPI follows the selected UE container (SUPI plan: ueransim-ue
# 001..UE_COUNT, multi-slice 201..204, SUCI Profile A 301).
default_supi_for() {
    case "$1" in
        ueransim-ue-internet)  printf 'imsi-001010000000201' ;;
        ueransim-ue-gold)      printf 'imsi-001010000000202' ;;
        ueransim-ue-silver)    printf 'imsi-001010000000203' ;;
        ueransim-ue-bronze)    printf 'imsi-001010000000204' ;;
        ueransim-ue-profile-a) printf 'imsi-001010000000301' ;;
        *)                     printf 'imsi-001010000000001' ;;
    esac
}
SUPI="${SUPI:-$(default_supi_for "$UE_CONTAINER")}"
AMF_MGMT="${AMF_MGMT:-http://localhost:9002}"
SMF_MGMT="${SMF_MGMT:-https://localhost:8004}"

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red() { printf '\033[31m%s\033[0m\n' "$*"; }
hr() { printf -- '----------------------------------------------------------------\n'; }

# wait_for_log / logs_have / nrcli / run_timeout / now_ts: scripts/lib/common.sh.

# internet_psi — PSI of the UE's PS-ACTIVE internet PDU session (empty if none).
internet_psi() {
    local out
    out=$(nrcli "$UE_CONTAINER" "$SUPI" ps-list 10)
    awk '
        function emit() { if (st == "PS-ACTIVE" && apn == "internet" && psi != "") print psi }
        /^PDU Session/ { emit(); psi = $2; sub(/^Session/, "", psi); sub(/:$/, "", psi); st = apn = "" }
        /state:/ { st = $2 }
        /apn:/   { apn = $2 }
        END      { emit() }
    ' <<<"$out" | head -n 1
}

# ensure_internet_session — make sure the UE has a PS-ACTIVE internet session (keeps it
# CM-CONNECTED for the network-triggered procedures) without stacking duplicates.
# Prints the PSI (empty if none could be established).
ensure_internet_session() {
    local psi
    psi=$(internet_psi)
    if [ -z "$psi" ]; then
        nrcli "$UE_CONTAINER" "$SUPI" "ps-establish IPv4 --dnn internet" 15 >/dev/null
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            sleep 1
            psi=$(internet_psi)
            [ -n "$psi" ] && break
        done
    fi
    printf '%s' "$psi"
}

check_ursp() {
    hr; green "[ursp] URSP delivery round-trip (TS 24.501 Annex D)"
    # The policy is pushed at registration; force a fresh push to be deterministic and
    # only accept log lines emitted after it.
    local since code
    since=$(now_ts)
    code=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' \
        -X POST "$AMF_MGMT/amf/v1/ue-contexts/$SUPI/push-policies" 2>/dev/null || true)
    echo "    push-policies $SUPI → HTTP ${code:-000}"

    if wait_for_log amf "UE policy container sent|ursp_version" 20 "$since"; then
        green "  ✓ AMF sent the UE policy container (MANAGE UE POLICY COMMAND)"
    else
        red "  ✗ AMF did not send a UE policy container (push-policies HTTP ${code:-000})"; return 1
    fi

    if wait_for_log amf "MANAGE UE POLICY COMPLETE received" 20 "$since"; then
        green "  ✓ AMF received MANAGE UE POLICY COMPLETE — modded UE acknowledged URSP"
    else
        red "  ✗ no MANAGE UE POLICY COMPLETE (is the modified UERANSIM image running?)"; return 1
    fi

    if wait_for_log "$UE_CONTAINER" "URSP policy received" 10 "$since"; then
        green "  ✓ UE applied the URSP rules (no 'Unhandled payload container type [5]')"
    else
        red "  ! UE log did not show 'URSP policy received' (check $UE_CONTAINER)"
    fi
}

check_ursp_cli() {
    hr; green "[ursp-cli] nr-cli URSP introspection"
    local out rc=0 cmd
    for cmd in "ursp-show" "ursp-match ims"; do
        echo "  $cmd:"
        out=$(nrcli "$UE_CONTAINER" "$SUPI" "$cmd" 10)
        sed 's/^/    /' <<<"$out"
        if [ -z "$out" ] || text_has_i '^ERROR|unknown command|Command not found' "$out"; then
            red "  ✗ nr-cli $cmd failed (is the URSP-patched UERANSIM image running?)"; rc=1
        else
            green "  ✓ nr-cli $cmd answered"
        fi
    done
    return "$rc"
}

check_ursp_steer() {
    hr; green "[ursp-steer] URSP-steered additional PDU session (TS 23.503 §6.6.2)"
    local target="${1:-ims}" since out
    since=$(now_ts)
    out=$(nrcli "$UE_CONTAINER" "$SUPI" "ursp-establish $target" 15)
    sed 's/^/    /' <<<"$out"
    if wait_for_log "$UE_CONTAINER" "PDU Session establishment is successful" 30 "$since"; then
        green "  ✓ UE established the URSP-steered session for '$target'"
    else
        red "  ✗ no successful establishment for '$target'"; return 1
    fi
}

check_qos_mod() {
    hr; green "[qos-mod] NW-initiated QoS modification round-trip (TS 23.502 §4.3.3.2)"
    # Target the UE's real internet session: several UEs share PSI 1 under
    # `make ueransim-all`, so the SMF needs the SUPI to disambiguate (else 409).
    local psi since resp code body
    psi=$(ensure_internet_session)
    if [ -z "$psi" ]; then
        red "  ✗ $UE_CONTAINER ($SUPI) has no PS-ACTIVE internet PDU session"; return 1
    fi
    since=$(now_ts)
    resp=$(curl -sSk --max-time 10 -X POST "$SMF_MGMT/nsmf-management/v1/sessions/$psi/qos" \
        -H 'Content-Type: application/json' \
        -d "{\"5qi\":7,\"reason\":\"validate-ueransim-mod\",\"supi\":\"$SUPI\"}" \
        -w '\n%{http_code}' 2>/dev/null || true)
    code=$(tail -n 1 <<<"$resp")
    body=$(sed '$d' <<<"$resp")
    echo "    POST sessions/$psi/qos (supi=$SUPI, 5qi=7) → HTTP ${code:-000} ${body:0:200}"
    case "$code" in
        2??) ;;
        *) red "  ✗ SMF rejected the QoS modification request (HTTP ${code:-000})"; return 1 ;;
    esac

    if wait_for_log "$UE_CONTAINER" "QoS modified by the network|Modification Complete" 25 "$since"; then
        green "  ✓ UE handled PDU SESSION MODIFICATION COMMAND (0xCB) and replied COMPLETE (0xCC)"
    else
        red "  ✗ UE did not handle the modification command"; return 1
    fi
    if wait_for_log amf "Modification Complete received" 15 "$since"; then
        green "  ✓ AMF received the modification complete — loop closed"
    else
        red "  ! AMF did not log the modification complete"
    fi
}

check_location() {
    hr; green "[location] Cell-ID positioning round-trip (TS 29.572 §5.2.2.2 / TS 38.413 §8.17)"
    local ROOT lmf_url r1 r2 cell lat1 lat2 since
    ROOT="$REPO_ROOT"
    lmf_url="https://localhost:8012/nlmf-loc/v1/ue-contexts/$SUPI/provide-loc-info"

    # The UE must be CM-CONNECTED for the AMF to trigger NGAP Location Reporting; ensure a session.
    ensure_internet_session >/dev/null
    since=$(now_ts)

    locate() {
        curl -sk --http2 --max-time 30 \
            --cert "$ROOT/pki/smf.crt" --key "$ROOT/pki/smf.key" --cacert "$ROOT/pki/ca.crt" \
            -X POST "$lmf_url" -H 'Content-Type: application/json' -d "{\"supi\":\"$SUPI\"}"
    }
    lat_of() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("locationEstimate",{}).get("point",{}).get("lat",""))' 2>/dev/null || true; }

    r1=$(locate); echo "    $r1"
    cell=$(printf '%s' "$r1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("nrCellId",""))' 2>/dev/null || true)
    if [ -n "$cell" ] && [ "$cell" != "000000000" ]; then
        green "  ✓ LMF returned serving NRCGI $cell"
    else
        red "  ✗ LMF returned no valid NRCGI (is the location-patched UERANSIM running and the UE connected?)"; return 1
    fi

    if wait_for_log "$GNB_CONTAINER" "Location Report sent" 20 "$since"; then
        green "  ✓ gNB answered LocationReportingControl with a LocationReport"
    else
        red "  ! gNB log did not show 'Location Report sent'"
    fi

    # Poll again — the LMF mobility model should yield a different coordinate.
    sleep 5
    r2=$(locate)
    lat1=$(printf '%s' "$r1" | lat_of); lat2=$(printf '%s' "$r2" | lat_of)
    if [ -n "$lat1" ] && [ -n "$lat2" ] && [ "$lat1" != "$lat2" ]; then
        green "  ✓ coordinates moved between polls ($lat1 → $lat2) — mobility model active"
    else
        red "  ! coordinates did not change ($lat1 → $lat2)"
    fi
}

check_nrppa() {
    hr; green "[nrppa] E-CID positioning round-trip (TS 38.455 §8 / TS 38.413 §8.17.3)"
    local ROOT lmf_url r uncert pdl since
    ROOT="$REPO_ROOT"
    lmf_url="https://localhost:8012/nlmf-loc/v1/ue-contexts/$SUPI/provide-loc-info"

    # The UE must be CM-CONNECTED for the AMF to relay NRPPa to the gNB; ensure a session.
    ensure_internet_session >/dev/null
    since=$(now_ts)

    # hAccuracy=100 m selects E-CID (50 < hAccuracy <= 200 -> E-CID; TS 23.273 §6.2.9).
    r=$(curl -sk --http2 --max-time 30 \
        --cert "$ROOT/pki/smf.crt" --key "$ROOT/pki/smf.key" --cacert "$ROOT/pki/ca.crt" \
        -X POST "$lmf_url" -H 'Content-Type: application/json' \
        -d "{\"supi\":\"$SUPI\",\"locationQoS\":{\"hAccuracy\":100}}")
    echo "    $r"

    pdl=$(printf '%s' "$r" | python3 -c 'import sys,json; print(",".join(json.load(sys.stdin).get("positioningDataList",[])))' 2>/dev/null || true)
    if text_has "eCID" "$pdl"; then
        green "  ✓ LMF returned an E-CID fix (positioningDataList=[$pdl])"
    else
        red "  ✗ LMF did not return an E-CID fix (positioningDataList=[$pdl]) — fell back to Cell-ID?"; return 1
    fi

    uncert=$(printf '%s' "$r" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("locationEstimate",{}).get("uncertainty",""))' 2>/dev/null || true)
    if [ -n "$uncert" ] && python3 -c "import sys; sys.exit(0 if float('$uncert') <= 150 else 1)" 2>/dev/null; then
        green "  ✓ E-CID uncertainty ${uncert} m <= 150 m"
    else
        red "  ! E-CID uncertainty '${uncert}' m not within the <=150 m band"
    fi

    if wait_for_log "$GNB_CONTAINER" "Uplink UE-associated NRPPa Transport sent|E-CIDMeasurementReport" 20 "$since"; then
        green "  ✓ gNB answered the NRPPa exchange (E-CIDMeasurementReport over ProcCode=50)"
    else
        red "  ! gNB log did not show the NRPPa reply"
    fi

    if wait_for_log amf "NRPPa|UplinkNRPPa|dl-nrppa" 20 "$since"; then
        green "  ✓ AMF relayed the NRPPa transport (DL ProcCode=8 / UL ProcCode=50)"
    else
        red "  ! AMF log did not show the NRPPa relay"
    fi

    check_nrppa_no_malformed_packets
}

check_gnss() {
    hr; green "[gnss] A-GNSS positioning round-trip (TS 37.355 §6 / TS 24.501 §8.7.4 / TS 23.273 §6.2.10)"
    local ROOT lmf_url r uncert pdl since
    ROOT="$REPO_ROOT"
    lmf_url="https://localhost:8012/nlmf-loc/v1/ue-contexts/$SUPI/provide-loc-info"

    # The UE must be CM-CONNECTED for the AMF to relay LPP over N1; ensure a session.
    ensure_internet_session >/dev/null
    since=$(now_ts)

    # hAccuracy=30 m selects GNSS/LPP (hAccuracy < 50 -> GNSS; TS 23.273 §6.2.10).
    r=$(curl -sk --http2 --max-time 30 \
        --cert "$ROOT/pki/smf.crt" --key "$ROOT/pki/smf.key" --cacert "$ROOT/pki/ca.crt" \
        -X POST "$lmf_url" -H 'Content-Type: application/json' \
        -d "{\"supi\":\"$SUPI\",\"locationQoS\":{\"hAccuracy\":30}}")
    echo "    $r"

    pdl=$(printf '%s' "$r" | python3 -c 'import sys,json; print(",".join(json.load(sys.stdin).get("positioningDataList",[])))' 2>/dev/null || true)
    if text_has "gnss" "$pdl"; then
        green "  ✓ LMF returned a GNSS fix (positioningDataList=[$pdl])"
    else
        red "  ✗ LMF did not return a GNSS fix (positioningDataList=[$pdl]) — fell back to E-CID/Cell-ID?"; return 1
    fi

    uncert=$(printf '%s' "$r" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("locationEstimate",{}).get("uncertainty",""))' 2>/dev/null || true)
    if [ -n "$uncert" ] && python3 -c "import sys; sys.exit(0 if float('$uncert') <= 50 else 1)" 2>/dev/null; then
        green "  ✓ GNSS uncertainty ${uncert} m <= 50 m (CEP50)"
    else
        red "  ! GNSS uncertainty '${uncert}' m not within the <=50 m band"
    fi

    # 20s budget: UERANSIM's logger sets flush_on(warn) (src/utils/logger.cpp), so
    # these info-level lines can sit buffered for a few seconds before `docker logs`
    # sees them even though the LPP round trip itself already completed synchronously.
    if wait_for_log "$UE_CONTAINER" "LPP RequestCapabilities received|ProvideLocationInformation" 20 "$since"; then
        green "  ✓ UE ran the LPP capability + measurement exchange (patch 0042)"
    else
        red "  ! UE log did not show the LPP exchange (is the LPP-patched UERANSIM running?)"
    fi

    if wait_for_log amf "LPP|dl-lpp|UplinkLPP" 20 "$since"; then
        green "  ✓ AMF relayed the LPP transport (DL/UL NAS Transport, payload container type 3)"
    else
        red "  ! AMF log did not show the LPP relay"
    fi

    if wait_for_log lmf "GNSS position calculated|GNSS fix" 20 "$since"; then
        green "  ✓ LMF computed the GNSS fix from the UE measurements (WLS solve)"
    else
        red "  ! LMF log did not show the GNSS fix"
    fi

    check_gnss_no_malformed_packets
}

# check_gnss_no_malformed_packets rotates the AMF PCAP sidecar and greps the fresh capture
# for malformed NGAP/NAS frames — the regression guard for the LPP relay leg. Note the inner
# LPP octets ride inside NEA2-ciphered NAS on the live N2 link and are NOT dissectable there;
# this check proves the NGAP + outer-NAS framing is well-formed (the LPP octets themselves are
# proven well-formed by the shared/lpp tshark oracle unit test). Skips if tshark is unavailable.
check_gnss_no_malformed_packets() {
    if ! command -v tshark >/dev/null 2>&1; then
        red "  ! tshark not installed — skipping malformed-packet check"
        return 0
    fi
    local ROOT pcap_dir latest malformed
    ROOT="$REPO_ROOT"
    pcap_dir="$ROOT/pcaps/amf"

    run_timeout 30 "$ROOT/scripts/pcap-control.sh" rotate amf >/dev/null 2>&1 || true
    sleep 2
    latest=$(ls -1t "$pcap_dir"/*.pcap 2>/dev/null | head -1 || true)
    if [ -z "$latest" ]; then
        red "  ! no AMF PCAP file found under $pcap_dir — skipping malformed-packet check"
        return 0
    fi
    malformed=$(tshark -r "$latest" -Y 'ngap || nas-5gs' 2>/dev/null | grep -c "Malformed Packet" || true)
    if [ "${malformed:-0}" -eq 0 ]; then
        green "  ✓ tshark: zero malformed NGAP/NAS frames in $(basename "$latest")"
    else
        red "  ✗ tshark: $malformed malformed NGAP/NAS frame(s) in $(basename "$latest")"
        tshark -r "$latest" -Y 'ngap || nas-5gs' 2>/dev/null | grep "Malformed Packet" || true
        return 1
    fi
}

# check_nrppa_no_malformed_packets rotates the AMF PCAP sidecar so the just-captured
# NGAP/NRPPa exchange flushes to disk, then greps the fresh capture with tshark for
# "Malformed Packet" — the regression guard for LMF-004's real-APER rewrite (a hand-rolled
# TLV format masquerading as APER, or a wrong ProcedureCode, dissects as malformed once real
# IE content is present; see docs/procedures/NRPPaRelay.md "NRPPa fix — real APER + correct
# procCodes"). Requires tshark; skips (warns) rather than failing if unavailable.
check_nrppa_no_malformed_packets() {
    if ! command -v tshark >/dev/null 2>&1; then
        red "  ! tshark not installed — skipping malformed-packet check"
        return 0
    fi
    local ROOT pcap_dir latest
    ROOT="$REPO_ROOT"
    pcap_dir="$ROOT/pcaps/amf"

    run_timeout 30 "$ROOT/scripts/pcap-control.sh" rotate amf >/dev/null 2>&1 || true
    sleep 2

    latest=$(ls -1t "$pcap_dir"/*.pcap 2>/dev/null | head -1 || true)
    if [ -z "$latest" ]; then
        red "  ! no AMF PCAP file found under $pcap_dir — skipping malformed-packet check"
        return 0
    fi

    local malformed
    malformed=$(tshark -r "$latest" -Y 'ngap || nrppa' 2>/dev/null | grep -c "Malformed Packet" || true)
    if [ "${malformed:-0}" -eq 0 ]; then
        green "  ✓ tshark: zero malformed NGAP/NRPPa frames in $(basename "$latest")"
    else
        red "  ✗ tshark: $malformed malformed NGAP/NRPPa frame(s) in $(basename "$latest")"
        tshark -r "$latest" -Y 'ngap || nrppa' 2>/dev/null | grep "Malformed Packet" || true
        return 1
    fi
}

case "${1:-all}" in
    ursp) check_ursp ;;
    ursp-cli) check_ursp_cli ;;
    ursp-steer) check_ursp_steer "${2:-ims}" ;;
    qos-mod) check_qos_mod ;;
    location) check_location ;;
    nrppa) check_nrppa ;;
    gnss) check_gnss ;;
    all)
        echo "UE: $UE_CONTAINER ($SUPI) · gNB: $GNB_CONTAINER"
        FAILED=""
        check_ursp || FAILED="$FAILED ursp"
        check_ursp_cli || FAILED="$FAILED ursp-cli"
        check_ursp_steer ims || FAILED="$FAILED ursp-steer"
        check_qos_mod || FAILED="$FAILED qos-mod"
        check_location || FAILED="$FAILED location"
        check_nrppa || FAILED="$FAILED nrppa"
        check_gnss || FAILED="$FAILED gnss"
        if [ -n "$FAILED" ]; then
            hr; red "validate-ueransim-mod: FAILED checks:$FAILED"
            exit 1
        fi
        ;;
    *) echo "usage: $0 {ursp|ursp-cli|ursp-steer [target]|qos-mod|location|nrppa|gnss|all}" >&2; exit 2 ;;
esac
hr; green "validate-ueransim-mod: done"
