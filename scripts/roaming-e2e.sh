#!/usr/bin/env bash
# scripts/roaming-e2e.sh - roaming registration over N32 end-to-end (ROAM-001).
#
#   make roaming-e2e
#
# Assumes the core (make up RAN=ueransim, so ueransim-gnb + ueransim-ue run) and the compose
# `roaming` profile are already up, including hausf/hudm/hudr (home PLMN 001/02) next to
# hnrf/hsepp/sepp. Checks:
#   1. hNRF holds AUSF/UDM/UDR profiles carrying the home FQDNs (TS 23.003 §28.5.1)
#   2. a roaming UE (HPLMN 001/02, config/ueransim/ue-roaming.yaml) registers on the 001/01 core
#      (second nr-ue inside the running UE container)
#   3. fivegc_sepp_n32f_messages_total on local SEPP (:9115) increased (AUSF/UDM traffic crossed N32-f)
#   4. home-routed PDU session (ROAM-002): hNRF has the H-SMF (fqdn), PSI 1 is established with a UE IP from the
#      H-SMF pool (HR_UE_POOL), and a ping from that address reaches the home N6 gateway (HR_N6_TARGET), which only
#      the H-UPF can route to (user plane exits at the H-UPF N6, TS 23.502 §4.3.2.2.2).
#   5. UE switch-off deregistration: V-UPF UL FAR DROP + N16 ReleasePduSession, every roaming session gone
#      (serving-network release, TS 23.502 §4.3.4.3 step 1b).
#   6. UE-initiated release (session-less UE, ps-establish then ps-release): AMF -> V-SMF UpdateSMContext,
#      V-SMF -> H-SMF Nsmf_PDUSession_Update UE_REQ_PDU_SES_REL via SEPP (TS 23.502 §4.3.4.3 step 1a;
#      TS 29.502 §5.2.2.8.2.3); H-SMF/H-UPF end at 0 and V-SMF/V-UPF at baseline (stable 5 s), no N16 Release.
#   7. the home-routed session is re-established and pings the home N6 again.
# Exits non-zero on any failure. Procedure: docs/procedures/RoamingRegistration.md.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2

UE_CONTAINER="${UE_CONTAINER:-ueransim-ue}"
HNRF_PORT="${HNRF_PORT:-8100}"
SEPP_METRICS="${SEPP_METRICS:-http://localhost:9115/metrics}"
WAIT="${WAIT:-60}"
UE_CFG_HOST="config/ueransim/ue-roaming.yaml"
UE_CFG_CTR="/ueransim/config/ue-roaming.yaml"
UE_LOG="/tmp/ue-roaming.log"
SUPI="imsi-001020000000001"
DOM="5gc.mnc002.mcc001.3gppnetwork.org"
HR_UE_POOL="${HR_UE_POOL:-10.70.0.}"        # H-SMF internet pool prefix (nf/smf/config/hsmf.yaml)
HR_N6_TARGET="${HR_N6_TARGET:-172.30.22.1}"  # hn6-net gateway, reachable only via the H-UPF N6

CURL=(curl -s --max-time 10 --cacert pki/ca.crt --cert pki/amf.crt --key pki/amf.key
  --resolve "hnrf.5gc.local:${HNRF_PORT}:127.0.0.1")

PASS=0; FAIL=0
ok()   { echo "  PASS $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL + 1)); }
step() { echo; echo "== $1"; }

# n32f_total: sum of every fivegc_sepp_n32f_messages_total sample on local SEPP.
n32f_total() {
  curl -s --max-time 10 "$SEPP_METRICS" \
    | awk '/^fivegc_sepp_n32f_messages_total[{ ]/ { s += $NF } END { printf "%d\n", s }'
}

healthy() { [ "$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)" = "healthy" ]; }
wait_for() { # secs label cmd...
  local t="$1" label="$2"; shift 2
  local i=0
  while [ "$i" -lt "$t" ]; do "$@" && { ok "$label"; return 0; }; sleep 1; i=$((i + 1)); done
  bad "$label (timeout ${t}s)"; return 1
}

step "pre-flight"
for f in pki/ca.crt pki/amf.crt pki/amf.key "$UE_CFG_HOST" \
  pki/n32/local/sepp.crt pki/n32/local/sepp.key pki/n32/peers/001-02/ca.crt config/roaming/partners-testpeer.yaml; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 2; }
done
for c in hnrf hsepp sepp hausf hudm hudr hsmf hupf "$UE_CONTAINER"; do
  [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = "true" ] \
    || { echo "container $c not running (make up RAN=ueransim; compose --profile roaming)" >&2; exit 2; }
done
ok "core, roaming profile and UE container are running"

# The default core is partner-free: load the test-peer partner (PLMN 001/02) into sepp and amf
# for this run (partners are read at startup, so both are recreated). The SMF is recreated too so it
# runs with the current config (peers.sepp, upf_n9_addr) for home-routed sessions.
# RECREATE=0 skips the recreate (containers already run with the test-peer partners file, e.g. so
# that pcap sidecars started beforehand keep capturing); the partners file in use is still checked.
export ROAMING_PARTNERS_FILE=/etc/5gc/roaming/partners-testpeer.yaml
if [ "${RECREATE:-1}" = 1 ]; then
  # amf-pcap/sepp-pcap/smf-pcap share the NF netns: recreate them with the NF or they capture a dead netns.
  if compose_out="$(docker compose --profile core --profile roaming up -d --no-deps --force-recreate \
      sepp sepp-pcap smf smf-pcap amf amf-pcap 2>&1)"; then
    ok "sepp, smf and amf recreated with ROAMING_PARTNERS_FILE=$ROAMING_PARTNERS_FILE"
  else
    bad "compose up sepp smf amf"; echo "$compose_out" | tail -n 20 >&2; exit 1
  fi
else
  for c in sepp amf; do
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" 2>/dev/null \
      | grep -x "ROAMING_PARTNERS_FILE=$ROAMING_PARTNERS_FILE" >/dev/null \
      || { bad "RECREATE=0 but $c does not run with ROAMING_PARTNERS_FILE=$ROAMING_PARTNERS_FILE"; exit 1; }
  done
  ok "RECREATE=0: sepp and amf already run with ROAMING_PARTNERS_FILE=$ROAMING_PARTNERS_FILE"
fi
wait_for "$WAIT" "sepp healthy" healthy sepp || exit 1
AMF_LOG_SINCE="--since 90s"; [ "${RECREATE:-1}" = 1 ] || AMF_LOG_SINCE=""  # RECREATE=0: any NG Setup since start
# The AMF image has no healthcheck: ready = running and the gNB has (re)run NG Setup since the recreate.
amf_ready() { [ "$(docker inspect -f '{{.State.Running}}' amf 2>/dev/null)" = "true" ] \
  && docker logs ${AMF_LOG_SINCE} amf 2>&1 | grep '"NGSetupResponse"' >/dev/null; }
# (no grep -q after a pipe: with pipefail an early grep exit SIGPIPEs the writer and fails the test)
wait_for "$WAIT" "amf up and gNB NG-set-up" amf_ready || exit 1

step "1. hNRF profiles carry the home FQDNs"
for pair in AUSF:ausf UDM:udm UDR:udr SMF:smf; do
  type="${pair%%:*}"; short="${pair##*:}"
  body="$("${CURL[@]}" "https://hnrf.5gc.local:${HNRF_PORT}/nnrf-disc/v1/nf-instances?target-nf-type=${type}&requester-nf-type=AMF")"
  if grep -q "\"fqdn\":\"${short}.${DOM}\"" <<<"$body"; then
    ok "hNRF has ${type} with fqdn ${short}.${DOM}"
  else
    bad "hNRF has no ${type} profile with fqdn ${short}.${DOM}: $(head -c 200 <<<"$body")"
  fi
done

step "2. roaming UE ${SUPI} registers on the 001/01 core"
before="$(n32f_total)"
echo "  n32f messages on local SEPP before: ${before:-?}"
docker exec "$UE_CONTAINER" sh -c "pkill -f ue-roaming.yaml; rm -f ${UE_LOG}" >/dev/null 2>&1 || true
docker cp "$UE_CFG_HOST" "${UE_CONTAINER}:${UE_CFG_CTR}" >/dev/null \
  && ok "ue-roaming.yaml copied into ${UE_CONTAINER}" || { bad "docker cp ue-roaming.yaml"; exit 1; }
docker exec -d "$UE_CONTAINER" sh -c "nr-ue -c ${UE_CFG_CTR} > ${UE_LOG} 2>&1" \
  && ok "second nr-ue started" || { bad "docker exec nr-ue"; exit 1; }

registered=0; out=""
end=$((SECONDS + WAIT))
while [ "$SECONDS" -lt "$end" ]; do
  out="$(docker exec "$UE_CONTAINER" cat "$UE_LOG" 2>/dev/null)"
  if grep -qE "Registration accept|Initial Registration is successful|MM-REGISTERED/NORMAL-SERVICE" <<<"$out"; then
    registered=1; break
  fi
  amf="$(docker logs --since 2m amf 2>&1)"
  if grep -F "$SUPI" <<<"$amf" | grep -iE "registration accept|5GMM-REGISTERED" >/dev/null; then
    registered=1; break
  fi
  sleep 2
done
if [ "$registered" = 1 ]; then
  ok "roaming UE registered"
else
  bad "roaming UE not registered within ${WAIT}s"
  echo "  --- UE log tail ---"; docker exec "$UE_CONTAINER" tail -n 15 "$UE_LOG" 2>/dev/null
  if grep -q "No PLMN could be selected" <<<"$out"; then
    echo "  hint: UERANSIM does not select a non-HPLMN cell without the VPLMN-selection patch"
  fi
fi

step "3. N32-f traffic crossed local SEPP"
after="$(n32f_total)"
echo "  n32f messages on local SEPP after: ${after:-?}"
if [ -n "$before" ] && [ -n "$after" ] && [ "$after" -gt "$before" ]; then
  ok "fivegc_sepp_n32f_messages_total increased (${before} -> ${after})"
else
  bad "fivegc_sepp_n32f_messages_total did not increase (${before:-?} -> ${after:-?})"
fi

step "4. home-routed PDU session (PSI 1, DNN internet) exits at the H-UPF N6"
ue_ip=""
end=$((SECONDS + WAIT))
while [ "$SECONDS" -lt "$end" ]; do
  out="$(docker exec "$UE_CONTAINER" cat "$UE_LOG" 2>/dev/null)"
  ue_ip="$(grep -oE "TUN interface\[[a-z0-9]+, ${HR_UE_POOL//./\\.}[0-9]+\]" <<<"$out" | head -n 1 | grep -oE "${HR_UE_POOL//./\\.}[0-9]+")"
  [ -n "$ue_ip" ] && break
  sleep 2
done
if [ -n "$ue_ip" ]; then
  ok "PSI 1 established with UE IP ${ue_ip} from the H-SMF pool ${HR_UE_POOL}0/24"
  if docker exec "$UE_CONTAINER" ping -c 3 -W 2 -I "$ue_ip" "$HR_N6_TARGET" >/dev/null 2>&1; then
    ok "ping ${ue_ip} -> ${HR_N6_TARGET} (home N6) succeeded"
  else
    bad "ping ${ue_ip} -> ${HR_N6_TARGET} (home N6) failed"
  fi
else
  bad "no home-routed PDU session (no TUN with an address in ${HR_UE_POOL}0/24 within ${WAIT}s)"
  echo "  --- UE log tail ---"; docker exec "$UE_CONTAINER" tail -n 15 "$UE_LOG" 2>/dev/null
fi
if docker logs --since 5m smf 2>&1 | grep '"procedure":"HomeRoutedPduSession"' >/dev/null; then
  ok "visited SMF logged HomeRoutedPduSession (V-SMF role)"
else
  bad "visited SMF has no HomeRoutedPduSession log line"
fi
if docker logs --since 5m hsmf 2>&1 | grep '"procedure":"HomeRoutedPduSession"' >/dev/null; then
  ok "hsmf logged HomeRoutedPduSession (H-SMF role)"
else
  bad "hsmf has no HomeRoutedPduSession log line"
fi

# Session gauges. hsmf/hupf publish no ports: read their metrics from inside hupf (busybox wget; hsmf on hn4-net).
# V-SMF/V-UPF also carry the non-roaming UE's sessions, so they are compared against a baseline.
HSMF_IP="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{if eq $k "5gc-hn4"}}{{$v.IPAddress}}{{end}}{{end}}' hsmf 2>/dev/null)"
gauge_sum() { awk -v m="$1" '$1 ~ "^"m"([{ ]|$)" { s += $NF } END { printf "%d\n", s }'; }
vsmf_sessions() { curl -s --max-time 5 http://localhost:9105/metrics | gauge_sum fivegc_pdu_sessions_active; }
vupf_sessions() { curl -s --max-time 5 http://localhost:9107/metrics | gauge_sum fivegc_upf_pfcp_sessions_active; }
hsmf_sessions() { docker exec hupf wget -qO- "http://${HSMF_IP}:9105/metrics" | gauge_sum fivegc_pdu_sessions_active; }
hupf_sessions() { docker exec hupf wget -qO- http://127.0.0.1:9107/metrics | gauge_sum fivegc_upf_pfcp_sessions_active; }
counts() { echo "V-SMF $(vsmf_sessions) V-UPF $(vupf_sessions) H-SMF $(hsmf_sessions) H-UPF $(hupf_sessions)"; }
# at_counts VSMF VUPF HSMF HUPF: true when all four gauges have exactly these values.
at_counts() { [ "$(vsmf_sessions)" -eq "$1" ] && [ "$(vupf_sessions)" -eq "$2" ] \
  && [ "$(hsmf_sessions)" -eq "$3" ] && [ "$(hupf_sessions)" -eq "$4" ]; }

step "5. UE switch-off deregistration releases the home-routed session (serving-network release, N16 Release)"
if [ -z "$HSMF_IP" ]; then
  bad "hsmf has no address on 5gc-hn4"; echo; echo "roaming-e2e: ${PASS} passed, ${FAIL} failed"; exit 1
fi
h0="$(hsmf_sessions)"; v0="$(vsmf_sessions)"; u0="$(vupf_sessions)"
echo "  sessions before: $(counts)"
t_dereg="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker exec "$UE_CONTAINER" nr-cli "$SUPI" -e "deregister switch-off" >/dev/null 2>&1 \
  && ok "nr-cli deregister switch-off accepted" || bad "nr-cli deregister switch-off failed"
wait_for 20 "all roaming sessions released (H-SMF/H-UPF 0, V-SMF/V-UPF -${h0})" \
  at_counts $((v0 - h0)) $((u0 - h0)) 0 0
echo "  sessions after: $(counts)"
smf_l="$(docker logs --since "$t_dereg" smf 2>&1)"
grep -F "PFCP Session Modification Request sent (V-UPF UL FAR DROP)" <<<"$smf_l" >/dev/null \
  && ok "V-SMF stopped V-UPF uplink forwarding before the N16 release" || bad "no V-UPF UL FAR DROP on deregistration"
grep -F "Nsmf_PDUSession_Release (ReleasePduSession) sent via SEPP" <<<"$smf_l" >/dev/null \
  && ok "V-SMF released the H-SMF session with Nsmf_PDUSession_Release (serving-network release)" \
  || bad "no N16 ReleasePduSession on deregistration"
docker exec "$UE_CONTAINER" sh -c "pkill -f ue-roaming" >/dev/null 2>&1 || true

step "6. UE-initiated release of the home-routed session (Nsmf_PDUSession_Update UE_REQ_PDU_SES_REL)"
# A UE without configured sessions: UERANSIM re-requests every configured session that is not active about once
# a second, which would re-create PSI 1 right after the release and hide the end state.
UE_NS_CTR="/ueransim/config/ue-roaming-nosessions.yaml"; UE_NS_LOG="/tmp/ue-roaming-nosessions.log"
ns_cfg="$(awk '/^sessions:/ { skip = 1; next } skip && /^[^ \t-]/ { skip = 0 } !skip' "$UE_CFG_HOST")"
if grep -q '^sessions:' <<<"$ns_cfg"; then bad "could not strip sessions from ${UE_CFG_HOST}"; fi
docker exec -i "$UE_CONTAINER" sh -c "cat > ${UE_NS_CTR}" <<<"$ns_cfg" \
  && ok "session-less roaming UE config written" || bad "write ${UE_NS_CTR}"
docker exec -d "$UE_CONTAINER" sh -c "rm -f ${UE_NS_LOG}; nr-ue -c ${UE_NS_CTR} > ${UE_NS_LOG} 2>&1" \
  && ok "session-less roaming nr-ue started" || bad "docker exec nr-ue (session-less)"
ns_registered() { docker exec "$UE_CONTAINER" cat "$UE_NS_LOG" 2>/dev/null \
  | grep -E "Initial Registration is successful|MM-REGISTERED/NORMAL-SERVICE" >/dev/null; }
wait_for "$WAIT" "roaming UE registered again (no sessions configured)" ns_registered
vB="$(vsmf_sessions)"; uB="$(vupf_sessions)"
echo "  baseline: $(counts)"
hr_ip() { docker exec "$UE_CONTAINER" ip -4 -o addr 2>/dev/null | grep -oE "inet ${HR_UE_POOL//./\\.}[0-9]+" | head -n 1 | cut -d' ' -f2; }
establish_and_ping() { # label
  local ip="" end
  docker exec "$UE_CONTAINER" nr-cli "$SUPI" -e "ps-establish IPv4 --sst 1 --sd 1 --dnn internet" >/dev/null 2>&1 \
    && ok "$1: nr-cli ps-establish accepted" || bad "$1: nr-cli ps-establish failed"
  end=$((SECONDS + 30))
  while [ "$SECONDS" -lt "$end" ]; do ip="$(hr_ip)"; [ -n "$ip" ] && break; sleep 1; done
  if [ -z "$ip" ]; then bad "$1: no home-routed session within 30s"; return 1; fi
  ok "$1: home-routed session with UE IP ${ip}"
  docker exec "$UE_CONTAINER" ping -c 3 -W 2 -I "$ip" "$HR_N6_TARGET" >/dev/null 2>&1 \
    && ok "$1: ping ${ip} -> ${HR_N6_TARGET} (home N6) succeeded" || bad "$1: ping ${ip} -> ${HR_N6_TARGET} failed"
  HR_IP="$ip"
}
HR_IP=""
establish_and_ping "establish"
wait_for 20 "one home-routed session on V-SMF/V-UPF/H-SMF/H-UPF" at_counts $((vB + 1)) $((uB + 1)) 1 1
if [ -n "$HR_IP" ]; then
  t0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  psi="$(docker exec "$UE_CONTAINER" nr-cli "$SUPI" -e "ps-list" 2>/dev/null | grep -oE 'PDU Session[0-9]+' | head -n 1 | grep -oE '[0-9]+$')"
  psi="${psi:-1}"
  docker exec "$UE_CONTAINER" nr-cli "$SUPI" -e "ps-release ${psi}" >/dev/null 2>&1 \
    && ok "nr-cli ps-release ${psi} accepted" || bad "nr-cli ps-release ${psi} failed"
  ue_ip_gone() { ! docker exec "$UE_CONTAINER" ip -4 addr 2>/dev/null | grep -F "inet ${HR_IP}/" >/dev/null; }
  wait_for 20 "UE address ${HR_IP} removed (session released at the UE)" ue_ip_gone
  wait_for 20 "V-SMF/V-UPF back to baseline and H-SMF/H-UPF at 0" at_counts "$vB" "$uB" 0 0
  sleep 5
  if at_counts "$vB" "$uB" 0 0; then ok "end state stable 5s later: $(counts)"; else bad "end state changed: $(counts)"; fi
  amf_l="$(docker logs --since "$t0" amf 2>&1)"; smf_l="$(docker logs --since "$t0" smf 2>&1)"
  hsmf_l="$(docker logs --since "$t0" hsmf 2>&1)"
  grep -F "Nsmf_PDUSession_UpdateSMContext (UE release request) sent to V-SMF" <<<"$amf_l" >/dev/null \
    && ok "AMF forwarded the UE release request to the V-SMF (UpdateSMContext)" \
    || bad "AMF did not forward the release request to the V-SMF"
  grep -F "PDU Session Release Command (from V-SMF) sent" <<<"$amf_l" >/dev/null \
    && ok "AMF sent the V-SMF-built PDU SESSION RELEASE COMMAND" || bad "AMF did not send the V-SMF release command"
  grep -F "PFCP Session Modification Request sent (V-UPF UL FAR DROP)" <<<"$smf_l" >/dev/null \
    && ok "V-SMF stopped V-UPF uplink forwarding first" || bad "no V-UPF UL FAR DROP on UE release"
  grep -F "Nsmf_PDUSession_Update (UE_REQ_PDU_SES_REL) answered" <<<"$smf_l" >/dev/null \
    && ok "V-SMF sent Nsmf_PDUSession_Update UE_REQ_PDU_SES_REL via SEPP and the H-SMF answered" \
    || bad "V-SMF has no answered N16 Update UE_REQ_PDU_SES_REL"
  grep -F "Nsmf_PDUSession_Update UE_REQ_PDU_SES_REL" <<<"$hsmf_l" >/dev/null \
    && ok "H-SMF received Nsmf_PDUSession_Update UE_REQ_PDU_SES_REL" || bad "H-SMF has no Update UE_REQ_PDU_SES_REL line"
  if grep -F "ReleasePduSession) received" <<<"$hsmf_l" >/dev/null; then
    bad "H-SMF also received a ReleasePduSession (UE release must use Update only)"
  else
    ok "no Nsmf_PDUSession_Release on N16 for the UE-initiated release"
  fi

  step "7. re-establish the home-routed session after the release"
  establish_and_ping "re-establish"
fi

echo
echo "roaming-e2e: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
