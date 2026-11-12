#!/usr/bin/env bash
# scripts/sepp-e2e.sh — vSEPP <-> hSEPP roaming end-to-end (REL19-9.8).
#
#   make sepp-e2e [PROFILE=rel17|rel19]
#
# Brings up vsepp/hsepp/hnrf (compose profile `roaming`, core already running) under the
# chosen release profile, with a pcap on vsepp and opt-in TLS key logs, then checks:
#   1. N32-c exchange-capability completes both ways (TS 29.573 §5.2.2)
#   2. NFDiscover from the vPLMN through vSEPP -> hSEPP -> hNRF, 3gpp-Sbi-Target-apiRoot model
#      (TS 29.500 §6.1.4.3.4)
#   3. same through a telescopic FQDN: the home NF FQDN in the answer is rewritten under the
#      vSEPP domain (topology hiding, TS 23.003 §28.5.2, TS 33.501 §13.1.1.1)
#   4. a target FQDN without a PLMN is refused with 400 (TS 23.003 §28.5.1)
#   5. pcap + keylog: N32-c and N32-f HTTP/2 are visible (needs tshark, else WARN)
# Needs the core stack up (make up) and the dev PKI (make pki). The stack is left running.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROFILE="${PROFILE:-rel17}"
case "$PROFILE" in rel17|rel19) ;; *) echo "PROFILE must be rel17 or rel19 (got '$PROFILE')" >&2; exit 2 ;; esac

VFQDN="sepp.5gc.mnc001.mcc001.3gppnetwork.org"
HNRF_FQDN="nrf.5gc.mnc002.mcc001.3gppnetwork.org"
HSEPP_ID="00000000-0000-4014-8000-000000000002"
NRF_PROFILE_ID="00000000-0000-4000-8000-0000000000a2"
SBI_PORT=8014
HNRF_PORT=8100
WAIT="${WAIT:-90}"
PCAP_NAME="sepp-e2e-${PROFILE}.pcap"
PCAP_HOST="pcaps/vsepp/${PCAP_NAME}"
KEYS_DIR="pcaps/sepp-keys"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CURL=(curl -s --max-time 10 --cacert pki/ca.crt --cert pki/amf.crt --key pki/amf.key)

# vcurl: the client of vSEPP's SBI listener runs in a netshoot container (OpenSSL curl honours
# SSLKEYLOGFILE; macOS curl does not), on the 5gc-sbi network, so the leg can be decrypted.
VIP=""
vcurl() {
  docker run --rm --network 5gc-sbi -e SSLKEYLOGFILE="/keys/curl-${PROFILE}.keys" \
    -v "$ROOT/pki:/pki:ro" -v "$ROOT/$KEYS_DIR:/keys" nicolaka/netshoot \
    curl -s --max-time 10 --cacert /pki/ca.crt --cert /pki/amf.crt --key /pki/amf.key "$@"
}

PASS=0; FAIL=0; WARN=0
ok()   { echo "  PASS $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL + 1)); }
warn() { echo "  WARN $1"; WARN=$((WARN + 1)); }
step() { echo; echo "== $1"; }

wait_for() { # wait_for SECONDS DESCRIPTION CMD...
  local t=$1 d=$2; shift 2
  local end=$((SECONDS + t))
  while ! "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -ge "$end" ] && { bad "timeout (${t}s): $d"; return 1; }
    sleep 2
  done
  return 0
}
healthy() { [ "$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)" = "healthy" ]; }
dlogs() { docker logs "$1" 2>&1; }   # captured before grep: grep -q + pipefail would SIGPIPE docker logs
logs_have() { local o; o="$(dlogs "$1")"; grep -q -- "$2" <<<"$o"; }

# ---- pre-flight -------------------------------------------------------------------
step "pre-flight (profile=$PROFILE)"
for f in pki/ca.crt pki/vsepp.crt pki/hsepp.crt pki/hnrf.crt pki/amf.crt pki/amf.key; do
  [ -f "$f" ] || { echo "missing $f — run: make pki" >&2; exit 2; }
done
docker inspect -f '{{.State.Running}}' nrf 2>/dev/null | grep -q true \
  || { echo "core stack not running — run: make up" >&2; exit 2; }
mkdir -p pcaps/vsepp pcaps/hsepp "$KEYS_DIR"; chmod 777 "$KEYS_DIR"
rm -f "$KEYS_DIR"/*-"$PROFILE".keys "$KEYS_DIR/all-$PROFILE.keys" "$PCAP_HOST"

# ---- bring up under the profile -----------------------------------------------------
step "bring up hnrf + vsepp ($PROFILE)"
export NF_RELEASE_PROFILE="$PROFILE" SEPP_KEYLOG_DIR=1
DC=(docker compose --profile core --profile roaming)
"${DC[@]}" up -d --build --no-deps --force-recreate hnrf vsepp vsepp-pcap >/dev/null 2>&1 \
  && ok "hnrf, vsepp, vsepp-pcap recreated" || { bad "compose up hnrf/vsepp"; exit 1; }
wait_for "$WAIT" "vsepp healthy" healthy vsepp || exit 1
wait_for "$WAIT" "hnrf healthy" healthy hnrf || exit 1
ok "vsepp and hnrf healthy"
VIP="$(docker inspect -f '{{(index .NetworkSettings.Networks "5gc-sbi").IPAddress}}' vsepp)"
[ -n "$VIP" ] && ok "vsepp SBI address $VIP" || { bad "vsepp has no 5gc-sbi address"; exit 1; }
logs_have vsepp "\"release_profile\":\"$PROFILE\"" \
  && ok "vsepp runs release profile $PROFILE" || bad "vsepp release profile is not $PROFILE"

# capture N32-c too: start tcpdump before hsepp (the initiator) comes up
docker exec -d vsepp-pcap sh -c "tcpdump -i any -U -s 0 -w /pcaps/${PCAP_NAME} 'tcp port 8443 or tcp port ${SBI_PORT}'" \
  && ok "tcpdump started on vsepp-pcap" || warn "tcpdump did not start"
sleep 2

step "bring up hsepp ($PROFILE) — N32-c initiator"
"${DC[@]}" up -d --no-deps --force-recreate hsepp hsepp-pcap >/dev/null 2>&1 \
  && ok "hsepp recreated" || { bad "compose up hsepp"; exit 1; }
wait_for "$WAIT" "hsepp healthy" healthy hsepp || exit 1
logs_have hsepp "\"release_profile\":\"$PROFILE\"" \
  && ok "hsepp runs release profile $PROFILE" || bad "hsepp release profile is not $PROFILE"

# ---- 1. N32-c -----------------------------------------------------------------------
step "1. N32-c exchange-capability (TS 29.573 §5.2.2)"
wait_for "$WAIT" "hsepp initiator exchange completed" logs_have hsepp "n32 initiator exchange completed" \
  && ok "hsepp: initiator exchange completed"
wait_for 30 "vsepp accepted exchange-capability" logs_have vsepp "exchange-capability accepted" \
  && ok "vsepp: exchange-capability accepted"
{ o="$(dlogs hsepp)"; grep "exchange-capability completed" <<<"$o" | grep -q '"selected":"TLS"'; } \
  && ok "selected security capability TLS" || bad "selected capability is not TLS"
o="$(dlogs vsepp)"; echo "  info exchange log (vsepp): $(grep 'exchange-capability accepted' <<<"$o" | head -1 | cut -c1-400)"

# ---- 2. NFDiscover, header model ------------------------------------------------------
step "2. NFDiscover vPLMN -> vSEPP -> hSEPP -> hNRF (3gpp-Sbi-Target-apiRoot)"
code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' --resolve "hnrf.5gc.local:${HNRF_PORT}:127.0.0.1" -X PUT \
  -H 'content-type: application/json' \
  -d "{\"nfInstanceId\":\"${NRF_PROFILE_ID}\",\"nfType\":\"NRF\",\"nfStatus\":\"REGISTERED\",\"fqdn\":\"${HNRF_FQDN}\",\"plmnList\":[{\"mcc\":\"001\",\"mnc\":\"02\"}],\"nfServices\":[{\"serviceInstanceId\":\"nnrf-disc-1\",\"serviceName\":\"nnrf-disc\",\"versions\":[{\"apiVersionInUri\":\"v1\",\"apiFullVersion\":\"1.0.0\"}],\"scheme\":\"https\",\"nfServiceStatus\":\"REGISTERED\",\"ipEndPoints\":[{\"port\":8000}]}]}" \
  "https://hnrf.5gc.local:${HNRF_PORT}/nnrf-nfm/v1/nf-instances/${NRF_PROFILE_ID}")
case "$code" in 200|201) ok "home NRF profile registered in hNRF (HTTP $code)" ;; *) bad "hNRF registration HTTP $code" ;; esac

vcurl -w '\n%{http_code}' --resolve "${VFQDN}:${SBI_PORT}:${VIP}" \
  -H "3gpp-Sbi-Target-apiRoot: https://${HNRF_FQDN}:8000" \
  "https://${VFQDN}:${SBI_PORT}/nnrf-disc/v1/nf-instances?target-nf-type=SEPP&requester-nf-type=AMF" >"$TMP/r1.txt" 2>/dev/null
code="$(tail -n1 "$TMP/r1.txt")"; sed '$d' "$TMP/r1.txt" >"$TMP/disc1.json"
[ "$code" = "200" ] && ok "discovery answered 200" || bad "discovery HTTP $code: $(head -c 200 "$TMP/disc1.json")"
grep -q "$HSEPP_ID" "$TMP/disc1.json" \
  && ok "answer comes from hNRF (hSEPP profile $HSEPP_ID)" || bad "hSEPP profile not in the hNRF answer"

# ---- 3. telescopic FQDN, topology hiding ------------------------------------------------
step "3. telescopic FQDN + topology hiding (TS 23.003 §28.5.2)"
TH="nrf-5gc-mnc002-mcc001-3gppnetwork-org.${VFQDN}"
vcurl -w '\n%{http_code}' --resolve "${TH}:${SBI_PORT}:${VIP}" \
  "https://${TH}:${SBI_PORT}/nnrf-disc/v1/nf-instances?target-nf-type=NRF&requester-nf-type=AMF" >"$TMP/r2.txt" 2>/dev/null
code="$(tail -n1 "$TMP/r2.txt")"; sed '$d' "$TMP/r2.txt" >"$TMP/disc2.json"
[ "$code" = "200" ] && ok "telescopic discovery answered 200" || bad "telescopic discovery HTTP $code: $(head -c 200 "$TMP/disc2.json")"
vcurl -s -D - -o /dev/null --resolve "${TH}:${SBI_PORT}:${VIP}" -H 'X-Correlation-Id: 01E2ECORRELATION000000000' \
  "https://${TH}:${SBI_PORT}/nnrf-disc/v1/nf-instances?target-nf-type=NRF&requester-nf-type=AMF" 2>/dev/null >"$TMP/hdr.txt" || true
[ "$(grep -ic '^x-correlation-id:' "$TMP/hdr.txt")" = "1" ] \
  && ok "single X-Correlation-Id on the forwarded answer" || bad "X-Correlation-Id appears $(grep -ic '^x-correlation-id:' "$TMP/hdr.txt") times"
grep -qF "\"fqdn\":\"${TH}\"" "$TMP/disc2.json" \
  && ok "home NF FQDN rewritten under the vSEPP domain" || bad "fqdn not rewritten to ${TH}"
grep -qF "$HNRF_FQDN" "$TMP/disc2.json" \
  && bad "home FQDN ${HNRF_FQDN} leaked to the vPLMN" || ok "no home FQDN leaked in the body"

# ---- 4. negative ---------------------------------------------------------------------------
step "4. target FQDN without a PLMN is refused (TS 23.003 §28.5.1)"
code=$(vcurl -o /dev/null -w '%{http_code}' --resolve "${VFQDN}:${SBI_PORT}:${VIP}" \
  -H "3gpp-Sbi-Target-apiRoot: https://hnrf:8000" \
  "https://${VFQDN}:${SBI_PORT}/nnrf-disc/v1/nf-instances?target-nf-type=SEPP&requester-nf-type=AMF" 2>/dev/null)
[ "$code" = "400" ] && ok "400 INVALID_MSG_FORMAT for a PLMN-less target" || bad "expected 400, got $code"

# ---- 5. pcap -----------------------------------------------------------------------------------
step "5. pcap + TLS keylog (vsepp ${PCAP_HOST})"
sleep 2
docker exec vsepp-pcap sh -c 'pkill -INT tcpdump' >/dev/null 2>&1 || true
sleep 2
if [ -s "$PCAP_HOST" ]; then ok "pcap written ($(wc -c <"$PCAP_HOST" | tr -d ' ') bytes)"; else bad "pcap missing or empty: $PCAP_HOST"; fi
cat "$KEYS_DIR/vsepp.keys" "$KEYS_DIR/hsepp.keys" "$KEYS_DIR/curl-${PROFILE}.keys" > "$KEYS_DIR/all-${PROFILE}.keys" 2>/dev/null || true
if [ -s "$KEYS_DIR/all-${PROFILE}.keys" ]; then ok "TLS key log written ($(grep -c . "$KEYS_DIR/all-${PROFILE}.keys") secrets)"; else warn "no TLS key log (SSLKEYLOGFILE not honoured?)"; fi
TSHARK=(tshark)
command -v tshark >/dev/null 2>&1 || TSHARK=(docker run --rm -v "$ROOT/pcaps:/p" nicolaka/netshoot tshark)
if [ -s "$PCAP_HOST" ] && [ -s "$KEYS_DIR/all-${PROFILE}.keys" ]; then
  if [ "${TSHARK[0]}" = tshark ]; then P="$PCAP_HOST"; K="$KEYS_DIR/all-${PROFILE}.keys"; else P="/p/vsepp/${PCAP_NAME}"; K="/p/sepp-keys/all-${PROFILE}.keys"; fi
  "${TSHARK[@]}" -r "$P" -o "tls.keylog_file:$K" -Y 'http2.header.value' -T fields -e http2.header.value >"$TMP/h2.txt" 2>/dev/null || true
  grep -q 'n32c-handshake/v1/exchange-capability' "$TMP/h2.txt" \
    && ok "N32-c exchange-capability visible (HTTP/2, decrypted)" || bad "N32-c exchange-capability not visible in the pcap"
  grep -q 'nnrf-disc/v1/nf-instances' "$TMP/h2.txt" \
    && ok "N32-f forwarded nnrf-disc visible (HTTP/2, decrypted)" || bad "N32-f nnrf-disc not visible in the pcap"
  "${TSHARK[@]}" -r "$P" -o "tls.keylog_file:$K" -Y 'json' -T fields -e json.member_with_value 2>/dev/null >"$TMP/json.txt" || true
  tr ',' '\n' <"$TMP/json.txt" | grep -E 'supportedFeatures|apiFullVersion:1\.[24]\.1' | sort -u >"$TMP/sf.txt" || true
  want="1.2.1"; [ "$PROFILE" = rel19 ] && want="1.4.1"
  grep -q "n32c-handshake.*apiFullVersion:${want}\|apiFullVersion:${want}" "$TMP/json.txt" \
    && ok "N32 apiFullVersion on the wire is ${want} ($PROFILE)" || bad "apiFullVersion ${want} not seen on the wire"
  if [ -s "$TMP/sf.txt" ]; then echo "  info supportedFeatures on the wire ($PROFILE): $(tr '\n' ' ' <"$TMP/sf.txt")"; else echo "  info supportedFeatures: none on the wire ($PROFILE)"; fi
  cp "$TMP/sf.txt" "pcaps/vsepp/sepp-e2e-${PROFILE}.wire.txt" 2>/dev/null || true
else
  warn "pcap decryption skipped (pcap or key log missing)"
fi

echo
echo "== Results ($PROFILE): PASS=$PASS FAIL=$FAIL WARN=$WARN"
echo "   pcap: $PCAP_HOST   keylog: $KEYS_DIR/all-${PROFILE}.keys"
[ "$FAIL" -eq 0 ] && echo "PASS" && exit 0
echo "FAILED"; exit 1
