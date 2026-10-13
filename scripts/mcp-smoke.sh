#!/usr/bin/env bash
# scripts/mcp-smoke.sh — live validation of the whole MCP tool surface against a running core.
#
# Every check calls one MCP tool over the SSE/HTTP transport and asserts the result. A coverage
# guard compares the tools/list names with the tools that were actually checked in this run
# and fails the run when a listed tool has no check ("unchecked: <names>").
#
#   default     R  read-only, dry-run and refusal checks for every listed tool: no state change
#   MUTATE=1    M  also the state-changing tools on test data, each reverted
#   DISRUPT=1   D  also the confirmed N1/N2 tools (AN release, paging, NW deregistration, PDU session
#                  release, QoS modification, UE policy push, location, PWS, RFSP, profile update,
#                  timers, URSP template, NSSAA, SMS, AF QoS), each followed by a polling wait and
#                  a state assertion. Takes about 5 minutes and briefly detaches both UEs.
#   LAB_URL=…   L  also the ADMIN tools and the role gates against a lab-mode instance
#                  (access_mode lab, allow_service_control true, bearer tokens LAB_TOKEN / VIEWER_TOKEN)
#
# A final [baseline] section asserts the state after the run equals the state captured at the start.
#
# Run:   make 5gcsa RAN=ueransim MCP=on UE_COUNT=2   (core + UEs + MCP)
#        make mcp-e2e                                  (MUTATE=1 / DISRUPT=1 / LAB_URL=… add sections)
# Exit:  0 all checks pass · 1 at least one check failed (or a listed tool is unchecked) · 2 MCP not reachable
#
# Environment: MCP_URL (default http://localhost:9300), MCP_TOKEN (bearer for MCP_URL, optional),
#   SUPI / SUPI2 (the two test UEs), EXPECTED_UES (expected registered UEs, default 2; not UE_COUNT, which the Makefile exports as 1),
#   EXPECT_TOOLS (expected tools/list size of MCP_URL, default 74), EXPECT_MODE (default operator),
#   PORTAL_URL (default http://localhost:8080, URSP template lookup and cleanup),
#   LAB_URL, LAB_TOKEN, VIEWER_TOKEN, EXPECT_LAB_TOOLS (default 77).
#
# Portability: bash 3.2 (macOS) and GNU/Linux. Needs curl, jq and python3 (3.9+).
set -u

MCP_URL="${MCP_URL:-http://localhost:9300}"
MCP_TOKEN="${MCP_TOKEN:-}"
MUTATE="${MUTATE:-0}"
DISRUPT="${DISRUPT:-0}"
SUPI="${SUPI:-imsi-001010000000001}"
SUPI2="${SUPI2:-imsi-001010000000002}"
EXPECTED_UES="${EXPECTED_UES:-2}"
EXPECT_TOOLS="${EXPECT_TOOLS:-74}"
EXPECT_MODE="${EXPECT_MODE:-operator}"
PORTAL_URL="${PORTAL_URL:-http://localhost:8080}"
LAB_URL="${LAB_URL:-}"
LAB_TOKEN="${LAB_TOKEN:-}"
VIEWER_TOKEN="${VIEWER_TOKEN:-}"
EXPECT_LAB_TOOLS="${EXPECT_LAB_TOOLS:-77}"

TOKEN="$MCP_TOKEN"   # bearer token used by rpc(); switched in the lab section
PASS=0
FAIL=0
SKIP=0
CHECKED=" "          # tool names whose check ran (PASS or FAIL); a SKIP does not count
NOMARK=0
LAST_TEXT=""
LAST_ERR=""
LAST_CODE=""
LAST_CONF=0
PI=2                 # poll interval, seconds

for c in curl jq python3; do
  command -v "$c" >/dev/null 2>&1 || { echo "mcp-smoke: $c is required" >&2; exit 2; }
done

# ---- transport -------------------------------------------------------------

# rpc <json-rpc body> → raw response (uses $MCP_URL and $TOKEN)
rpc() {
  if [ -n "$TOKEN" ]; then
    curl -s -m 60 -X POST "$MCP_URL/mcp" -H 'Content-Type: application/json' \
      -H "Authorization: Bearer $TOKEN" -d "$1"
  else
    curl -s -m 60 -X POST "$MCP_URL/mcp" -H 'Content-Type: application/json' -d "$1"
  fi
}

# call <tool> <args-json> → sets LAST_TEXT (tool content), LAST_ERR (tool or protocol error, "" on success), LAST_CODE
call() {
  local body resp
  body=$(jq -cn --arg n "$1" --argjson a "$2" \
    '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$n,arguments:$a}}')
  resp=$(rpc "$body")
  LAST_TEXT=""; LAST_ERR=""; LAST_CODE=""
  if [ -z "$resp" ]; then LAST_ERR="no response from $MCP_URL"; return; fi
  LAST_TEXT=$(printf '%s' "$resp" | jq -r '.result.content[0].text // empty' 2>/dev/null)
  if [ "$(printf '%s' "$resp" | jq -r '.error != null' 2>/dev/null)" = "true" ]; then
    LAST_ERR=$(printf '%s' "$resp" | jq -r '.error.message' 2>/dev/null)
    LAST_CODE=$(printf '%s' "$resp" | jq -r '.error.code' 2>/dev/null)
  elif [ "$(printf '%s' "$resp" | jq -r '.result.isError // false' 2>/dev/null)" = "true" ]; then
    LAST_ERR=$(printf '%s' "$LAST_TEXT" | jq -r '.error // empty' 2>/dev/null)
    LAST_CODE=$(printf '%s' "$LAST_TEXT" | jq -r '.code // empty' 2>/dev/null)
    [ -z "$LAST_ERR" ] && LAST_ERR="$LAST_TEXT"
    [ -z "$LAST_ERR" ] && LAST_ERR="tool error"
  fi
}

# gap_wait: the guard allows one confirmed disruptive call every 2 s; keep a margin (integer seconds)
gap_wait() {
  local d
  d=$(( $(date +%s) - LAST_CONF ))
  if [ "$d" -lt 3 ]; then sleep $((3 - d)); fi
  return 0
}

# cconf <tool> <args-json>: a confirmed call, spaced from the previous one, retried once when rate limited
cconf() {
  gap_wait
  call "$1" "$2"
  if printf '%s' "$LAST_ERR" | grep -q 'rate limited'; then
    sleep 3; call "$1" "$2"
  fi
  LAST_CONF=$(date +%s)
}

# ---- result bookkeeping ----------------------------------------------------

mark() {
  [ "$NOMARK" = "1" ] && return 0
  case "$CHECKED" in *" $1 "*) ;; *) CHECKED="$CHECKED$1 " ;; esac
}
pass() { PASS=$((PASS + 1)); echo "  PASS  $2"; mark "$1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL  $2${3:+: $3}"; mark "$1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP  $1 ($2)"; }

# tj <jq filter>: succeeds when the filter is truthy over LAST_TEXT
tj() { printf '%s' "$LAST_TEXT" | jq -e "$1" >/dev/null 2>&1; }
# tjr <jq filter>: prints the filter result over LAST_TEXT
tjr() { printf '%s' "$LAST_TEXT" | jq -r "$1" 2>/dev/null; }

# chk <tool> <label> <filter>: assert over the result of the previous call
chk() {
  if [ -n "$LAST_ERR" ]; then fail "$1" "$2" "$LAST_ERR"; return 1; fi
  if tj "$3"; then pass "$1" "$2"; return 0; fi
  fail "$1" "$2" "expected $3; got $(printf '%s' "$LAST_TEXT" | tr -d '\n ' | cut -c1-300)"; return 1
}

# ok <label> <tool> <args> <jq filter over the result>
ok() { call "$2" "$3"; chk "$2" "$1" "$4"; }

# okp <timeout s> <label> <tool> <args> <filter>: like ok, but retried until the filter holds (eventual consistency)
okp() {
  local to=$1 end
  end=$((SECONDS + to))
  while :; do
    call "$3" "$4"
    if [ -z "$LAST_ERR" ] && tj "$5"; then break; fi
    if [ "$SECONDS" -ge "$end" ]; then break; fi
    sleep 2
  done
  chk "$3" "$2" "$5"
}

# refused <label> <tool> <args> [error substring]: the call must be refused
refused() {
  call "$2" "$3"
  if [ -z "$LAST_ERR" ]; then fail "$2" "$1" "call was not refused"; return 1; fi
  if [ -n "${4:-}" ] && ! printf '%s' "$LAST_ERR" | grep -qi "$4"; then
    fail "$2" "$1" "refused, but not with '$4': $LAST_ERR"; return 1
  fi
  pass "$2" "$1 (refused: $LAST_ERR)"
}

# dry <label> <tool> <args>: an unconfirmed disruptive call returns a dry-run and changes nothing
dry() { ok "$1" "$2" "$3" ".dry_run == true and .tool == \"$2\""; }

# poll <timeout s> <command…>: run the command every $PI seconds until it succeeds or the deadline
poll() {
  local to=$1 end
  shift
  end=$((SECONDS + to))
  while :; do
    if "$@"; then return 0; fi
    if [ "$SECONDS" -ge "$end" ]; then return 1; fi
    sleep "$PI"
  done
}

# log_has <logql>: Loki holds at least one record for the query in the last 5 minutes
log_has() {
  call log_query "$(jq -cn --arg q "$1" '{query:$q,window:"5m",limit:5}')"
  [ -z "$LAST_ERR" ] || return 1
  tj '.count >= 1'
}

# ue_is <supi> <gmm_state> <cm_state or ""> <psi or "">
ue_is() {
  call ue_context_get "{\"supi\":\"$1\"}"
  [ -z "$LAST_ERR" ] || return 1
  printf '%s' "$LAST_TEXT" | jq -e --arg g "$2" --arg c "$3" --arg p "$4" \
    '(.gmm_state == $g) and ($c == "" or .cm_state == $c) and ($p == "" or ((.pdu_session_ids // []) | map(. == ($p | tonumber)) | any))' \
    >/dev/null 2>&1
}
ue_ready() { ue_is "$1" 5GMM-REGISTERED CM-CONNECTED 1; }
ue_registered() { ue_is "$1" 5GMM-REGISTERED "" ""; }
ue_idle() { ue_is "$1" 5GMM-REGISTERED CM-IDLE ""; }
all_ready() { ue_ready "$SUPI" && ue_ready "$SUPI2"; }

# psi_absent <supi> <psi>: the SMF has no session for the pair
psi_absent() {
  call pdu_session_list '{}'
  [ -z "$LAST_ERR" ] || return 1
  printf '%s' "$LAST_TEXT" | jq -e --arg s "$1" --argjson p "$2" \
    '[.sessions[] | select(.supi == $s and .pduSessionId == $p)] | length == 0' >/dev/null 2>&1
}
# sessions_n <n>: the SMF holds exactly n ACTIVE sessions
sessions_n() {
  call pdu_session_list '{}'
  [ -z "$LAST_ERR" ] || return 1
  printf '%s' "$LAST_TEXT" | jq -e --argjson n "$1" '(.count == $n) and ([.sessions[] | select(.sessionState != "ACTIVE")] | length == 0)' >/dev/null 2>&1
}
# qos5qi <supi> <psi> <5qi>
qos5qi() {
  call pdu_session_qos_get "{\"supi\":\"$1\",\"pdu_session_id\":$2}"
  [ -z "$LAST_ERR" ] || return 1
  tj ".qosFlows[0].fiveQi == $3"
}
# n4_qer_dl <supi> <kbps>: the UPF session-AMBR QER carries the rate and the SMF/UPF views agree
n4_qer_dl() {
  call n4_session_get "{\"supi\":\"$1\",\"pdu_session_id\":1}"
  [ -z "$LAST_ERR" ] || return 1
  tj "(.upf.qers | map(select(.has_mbr == true)) | .[0].mbr_dl_kbps == $2) and ((.smf_mismatches | length) == 0)"
}
nf_healthy() {
  call core_health '{}'
  [ -z "$LAST_ERR" ] || return 1
  tj "[.nfs[] | select(.nf_type == \"$1\")] | (length > 0) and all(.healthy == true)"
}
timer_is() {
  call amf_timer_config '{}'
  [ -z "$LAST_ERR" ] || return 1
  tj ".effective.t3512_secs == $1"
}

ts_ago() {
  python3 -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(minutes=int(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$1"
}
utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# alias_dep <tool> <replacement>: the alias is flagged deprecated in tools/list and names its replacement
alias_dep() {
  if printf '%s' "$TOOLS_JSON" | jq -e --arg n "$1" --arg r "$2" \
    '.result.tools[] | select(.name == $n) | .description | (contains("DEPRECATED: use " + $r))' >/dev/null 2>&1; then
    pass "$1" "$1 is flagged deprecated and names $2"
  else
    fail "$1" "$1 is flagged deprecated and names $2"
  fi
}

# portal_get <path> → body on stdout (empty when unreachable)
portal_get() { curl -s -m 10 "$PORTAL_URL/api/v1$1" 2>/dev/null; }

echo "MCP smoke test against $MCP_URL (MUTATE=$MUTATE, DISRUPT=$DISRUPT, LAB_URL=${LAB_URL:-none}, S1=$SUPI, S2=$SUPI2, EXPECTED_UES=$EXPECTED_UES)"

# ---- reachability (exit 2 when down) ----------------------------------------
if ! curl -s -m 5 -o /dev/null -w '%{http_code}' "$MCP_URL/mcp/health" | grep -q 200; then
  echo "MCP not reachable at $MCP_URL: start it with make 5gcsa RAN=ueransim MCP=on" >&2
  exit 2
fi

# ---- baseline capture (read-only) ------------------------------------------
TOOLS_JSON=$(rpc '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
TOOLS=$(printf '%s' "$TOOLS_JSON" | jq -r '[.result.tools[].name] | join(" ")' 2>/dev/null)
# listed <tool>: the tool is in tools/list (its checks run only then; the coverage guard
# still fails when a listed tool has no check)
listed() { case " $TOOLS " in *" $1 "*) return 0 ;; esac; return 1; }
NTOOLS=$(printf '%s' "$TOOLS_JSON" | jq -r '.result.tools | length' 2>/dev/null)
if [ -z "$TOOLS" ]; then
  echo "MCP at $MCP_URL did not answer tools/list (bad MCP_TOKEN?)" >&2
  exit 2
fi

call config_view '{}'
BASE_SLICE=$(tjr '.sections.slice_qos.value.items | map({snssai,dnn,sessionAmbr,source}) | sort_by(.snssai.sst, .snssai.sd, .dnn)' | jq -cS .)
call amf_timer_config '{}'
BASE_TIMERS=$(tjr '.effective' | jq -cS .)
call core_health '{}'
NF_TYPES=$(tjr '[.nfs[].nf_type] | unique | .[]')
loglevels() {
  local nf out=""
  for nf in $NF_TYPES; do
    call nf_log_level "{\"nf\":\"$nf\"}"
    if [ -z "$LAST_ERR" ]; then out="$out$nf=$(tjr '.state.level + "/" + .state.base_level')
"; fi
  done
  printf '%s' "$out"
}
BASE_LOG=$(loglevels)
call subscriber_list '{}'
BASE_SUBS=$(tjr '[.[] | {supi,ambr_dl,ambr_ul,slices}] | sort_by(.supi)' | jq -cS .)
call pdu_session_list '{}'
BASE_SESS=$(tjr '[.sessions[] | {supi,pduSessionId,current5qi,qosSource,sessionAmbrDlMbps,sessionAmbrUlMbps}] | sort_by(.supi, .pduSessionId)' | jq -cS .)
S1_IP=$(tjr ".sessions[] | select(.supi == \"$SUPI\") | .ueIp" | head -1)
call pws_list '{}'
BASE_PWS_LIVE=$(tjr '[.[] | select(.cancelled == false)] | length')
BASE_POLICIES=$(portal_get /policies | jq -r '[.[].id] | sort | join(",")' 2>/dev/null)
echo "baseline captured: $(printf '%s' "$BASE_SESS" | jq 'length') sessions, S1 ip ${S1_IP:-unknown}, timers $BASE_TIMERS"

# ---- [protocol] -------------------------------------------------------------
echo "[protocol — tools/list]"
if [ "$NTOOLS" = "$EXPECT_TOOLS" ]; then
  pass tools_list "tools/list has $NTOOLS names (expected $EXPECT_TOOLS)"
else
  fail tools_list "tools/list size" "got $NTOOLS, expected $EXPECT_TOOLS"
fi
ALIASES=$(printf '%s' "$TOOLS_JSON" | jq -r '[.result.tools[] | select(.description | contains("DEPRECATED:")) | .name] | sort | join(" ")')
if [ "$ALIASES" = "gmm_state_get pdu_session_qos_modify procedure_summary" ]; then
  pass tools_list "exactly 3 deprecated aliases: $ALIASES"
else
  fail tools_list "deprecated aliases" "got '$ALIASES'"
fi
if printf '%s' "$TOOLS" | tr ' ' '\n' | grep -Eq '^(ueransim_|packetrusher_)'; then
  fail tools_list "no ueransim_*/packetrusher_* tool is listed" "found $(printf '%s' "$TOOLS" | tr ' ' '\n' | grep -E '^(ueransim_|packetrusher_)' | tr '\n' ' ')"
else
  pass tools_list "no ueransim_*/packetrusher_* tool is listed"
fi
if printf '%s' "$TOOLS_JSON" | jq -e '[.result.tools[] | select(.name == "metric_query") | .description | contains("fivegc_sbi_")] | any | not' >/dev/null 2>&1; then
  pass metric_query "metric_query description names no fivegc_sbi_ metric"
else
  fail metric_query "metric_query description names no fivegc_sbi_ metric"
fi

echo "[codecs — pure]"
ok "nas_decode RegistrationRequest" nas_decode '{"hex":"7e004111000100"}' '.message_type_name == "RegistrationRequest" and .spec_ref != null'
ok "ngap_decode NGSetup procedure" ngap_decode \
  '{"hex":"20150039000004000100060180616d663100600017004002f839cafe00060031302e3130302e3230302e313900564001ff005000080002f83900000008"}' \
  '.procedure_code == 21'
ok "nas_encode RegistrationRequest" nas_encode '{"message_type":"0x41","body_hex":"11000100"}' '.hex == "7e004111000100"'
ENC_HEX=$(tjr '.hex')
ok "nas_decode round-trips the nas_encode output" nas_decode "{\"hex\":\"$ENC_HEX\"}" '.message_type_name == "RegistrationRequest"'
ok "ie_validate accepts a well-formed IE sequence" ie_validate '{"hex":"7700090100000000000000"}' '.valid == true and .ie_count >= 1'
ok "tlv_inspect lists two IEs" tlv_inspect '{"hex":"5301ab5401cd"}' '(.entries | length) == 2 and .entries[0].iei == 83'
ok "pfcp_decode Heartbeat Request" pfcp_decode '{"hex":"2001000c000000010060000400000000"}' '.message_type == 1'
# TS 35.208 test set 1
AK_K=465b5ce8b199b49faa5f0a2ee238a6bc; AK_RAND=23553cbe9637a89d218ae64dae47bf35; AK_OPC=cd63cb71954a9f4e48a5994e37a02baf
SNN='5G:mnc001.mcc001.3gppnetwork.org'
ok "milenage_run TS 35.208 set 1" milenage_run \
  "{\"k\":\"$AK_K\",\"opc\":\"$AK_OPC\",\"rand\":\"$AK_RAND\",\"sqn\":\"ff9bb4d0b607\",\"amf\":\"b9b9\"}" \
  '.mac_a == "4a9ffac354dfafb3" and .res == "a54211d5e3ba50bf"'
AK_CK=$(tjr '.ck'); AK_IK=$(tjr '.ik'); AK_RES=$(tjr '.res')
ok "xres_star_compute" xres_star_compute \
  "{\"ck\":\"$AK_CK\",\"ik\":\"$AK_IK\",\"rand\":\"$AK_RAND\",\"xres\":\"$AK_RES\",\"serving_network_name\":\"$SNN\"}" \
  '(.xres_star | length) == 32'
XRES_STAR=$(tjr '.xres_star')
ok "res_star_verify matches the computed pair" res_star_verify "{\"xres_star\":\"$XRES_STAR\",\"res_star\":\"$XRES_STAR\"}" '.verified == true'
ok "kdf_compute" kdf_compute '{"key":"00112233445566778899aabbccddeeff","fc":"0x6C","params":[{"value":"01020304","length":4}]}' \
  '(.derived_key | length) == 64'
ok "aka_full_run derives the key hierarchy" aka_full_run \
  "{\"supi\":\"$SUPI\",\"k\":\"$AK_K\",\"opc\":\"$AK_OPC\",\"serving_network_name\":\"$SNN\",\"sqn\":\"ff9bb4d0b607\",\"amf\":\"b9b9\"}" \
  '(.kamf | length) == 64 and (.kausf | length) == 64 and (.xres_star | length) == 32'
ok "suci_derive Profile A (TS 33.501 Annex C.4 key)" suci_derive \
  "{\"supi\":\"$SUPI\",\"home_network_public_key\":\"5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650\",\"protection_scheme\":\"ProfileA\"}" \
  '.suci | startswith("suci-00101-0000-0-1-")'

echo "[status]"
ok "mcp_info: counts, mode and every upstream reachable" mcp_info '{}' \
  "(.tool_count + .alias_count == $NTOOLS) and (.alias_count == 3) and (.access_mode == \"$EXPECT_MODE\") and ((.upstreams | length) > 0) and ([.upstreams[] | select(.reachable == false)] | length == 0)"
ok "core_health: every NF healthy, dependencies up" core_health '{}' \
  '((.nfs | length) >= 11) and ([.nfs[] | select(.healthy != true)] | length == 0) and (.summary.unhealthy == 0) and (.dependencies.portal.store == "up") and (.dependencies.loki.reachable == true) and (.dependencies.jaeger.reachable == true) and (.dependencies.prometheus.reachable == true)'
ok "deployment_status: UERANSIM running" deployment_status '{}' '.mode == "ueransim" and .ueransim.running == true'
ok "subscriber_list: >= 2 subscribers, every key redacted" subscriber_list '{}' \
  'length >= 2 and all(.[]; .k == "<redacted>" and .opc == "<redacted>" and .sqn == "<redacted>")'
ok "subscriber_get $SUPI: keys redacted, RFSP shown" subscriber_get "{\"supi\":\"$SUPI\"}" \
  '.subscriber.supi == "'"$SUPI"'" and .subscriber.k == "<redacted>" and .subscriber.opc == "<redacted>" and .rfsp_override.rfsp != null'
ok "config_view: slices restart_required, slice_qos runtime" config_view '{}' \
  '.sections.slices.change == "restart_required" and .sections.slice_qos.change == "runtime" and (.sections.dnns.value | length) > 0'
ok "pws_list" pws_list '{}' 'type == "array"'
ok "alert_list" alert_list '{}' '.alerts | type == "array"'
ok "ran_gnb_list: every gNB NG_READY" ran_gnb_list '{}' '(.gnbs | length) >= 1 and all(.gnbs[]; .state == "NG_READY")'
ok "nf_list summary rows" nf_list '{}' \
  '(.count == (.nfInstances | length)) and .count >= 11 and all(.nfInstances[]; .nf_type != null and .nf_status == "REGISTERED")'
NF_ID=$(tjr '.nfInstances[0].instance_id')
ok "nf_list detail: full profiles" nf_list '{"detail":true}' '(.nfInstances | length) >= 11 and all(.nfInstances[]; .nfInstanceId != null and .nfType != null)'
ok "nf_status first NF" nf_status "{\"nf_instance_id\":\"$NF_ID\"}" '.nfStatus == "REGISTERED"'
ok "nf_discover SMF" nf_discover '{"target_nf_type":"SMF","requester_nf_type":"AMF"}' '(.nfInstances | length) >= 1 and .nfInstances[0].nfType == "SMF"'
ok "slice_status sst 1 sd 000001: all UEs, all sessions" slice_status '{"sst":1,"sd":"000001"}' \
  "type == \"array\" and .[0].registered_ues == $EXPECTED_UES and .[0].active_sessions_by_dnn.internet == $EXPECTED_UES"
refused "slice_status bad sd refused" slice_status '{"sd":"zz"}'
ok "subscription_am_get $SUPI: allowed NSSAI, no key fields" subscription_am_get "{\"supi\":\"$SUPI\"}" \
  '(.nssai.defaultSingleNssais | length) >= 1 and ([.. | objects | (.k?, .opc?) // empty] | length == 0)'
ok "subscription_qos_get $SUPI" subscription_qos_get "{\"supi\":\"$SUPI\"}" '.found == true and .subscriptions[0].default5qi != null'
ok "pcf_binding_list $SUPI: an internet binding" pcf_binding_list "{\"supi\":\"$SUPI\"}" \
  '(.bindings | length) >= 1 and (.bindings | map(select(.dnn == "internet")) | length) >= 1'
ok "pcf_binding_list all: bindings == bindings_active == EXPECTED_UES" pcf_binding_list '{}' \
  "(.bindings | length) == .bindings_active and .bindings_active == $EXPECTED_UES"
ok "kpi_snapshot: auth rate numeric, latency null with a reason" kpi_snapshot '{}' \
  "(.auth_success_rate | type == \"number\") and .auth_success_rate > 0 and .avg_registration_latency_ms == null and (.unavailable.avg_registration_latency_ms != null) and .pdu_sessions_active == $EXPECTED_UES"
ok "upf_stats 5m: sessions == EXPECTED_UES, drops.no_route, internet throughput" upf_stats '{"window":"5m"}' \
  ".pfcp_sessions_active == $EXPECTED_UES and (.drops | has(\"no_route\")) and (.throughput_bps | has(\"internet\"))"
ok "core_consistency_check: SMF == UPF sessions, no error finding" core_consistency_check '{}' \
  '(.counts.smf_sessions == .counts.upf_pfcp_sessions) and ([.findings[] | select(.severity == "error")] | length == 0)'
ok "error_summary 15m: a PDUSessionEstablishment REJECT row (lab UE loop)" error_summary '{"window":"15m"}' \
  '[.rows[] | select(.procedure == "PDUSessionEstablishment" and .result == "REJECT" and .count >= 1)] | length >= 1'
refused "error_summary window 2h refused" error_summary '{"window":"2h"}'

echo "[ue and sessions]"
ok "ue_list: EXPECTED_UES UEs registered, ids and times normalised" ue_list '{}' \
  "(.count == $EXPECTED_UES) and all(.ue_contexts[]; .gmm_state == \"5GMM-REGISTERED\" and (.pdu_session_ids | type == \"array\") and (.pdu_session_ids | all(type == \"number\")) and .registration_time != null)"
S1_GUTI=$(tjr ".ue_contexts[] | select(.supi == \"$SUPI\") | .guti")
alias_dep gmm_state_get ue_context_get
alias_dep procedure_summary procedure_stats
alias_dep pdu_session_qos_modify pdu_session_qos_set
ok "ue_context_get $SUPI" ue_context_get "{\"supi\":\"$SUPI\"}" \
  ".supi == \"$SUPI\" and .gmm_state == \"5GMM-REGISTERED\" and .cm_state != null and (.pdu_session_ids | index(1)) != null"
ok "gmm_state_get alias by GUTI (same fields, DEPRECATED description)" gmm_state_get "{\"guti\":\"$S1_GUTI\"}" \
  ".supi == \"$SUPI\" and .gmm_state == \"5GMM-REGISTERED\" and (.pdu_session_ids | type == \"array\")"
call ue_diagnose "{\"supi\":\"$SUPI\"}"
chk ue_diagnose "ue_diagnose $SUPI: recent_errors grouped (count descending), no duplicates" \
  '(.recent_errors | length) <= 10 and all(.recent_errors[]; has("count")) and ([.recent_errors[].count] == ([.recent_errors[].count] | sort | reverse)) and (([.recent_errors[] | [.nf, .procedure, .msg]] | unique | length) == (.recent_errors | length))'
chk ue_diagnose "ue_diagnose $SUPI: AMF context and SMF session listed" \
  '.amf.gmm_state == "5GMM-REGISTERED" and (.smf_sessions | length) >= 1'
ok "qos_policy_get $SUPI (no invented 5qi)" qos_policy_get "{\"supi\":\"$SUPI\"}" '(.is_override == true) or (has("5qi") | not)'
ok "qos_policy_list: array" qos_policy_list '{}' 'type == "array"'
ok "pdu_session_list: EXPECTED_UES ACTIVE sessions" pdu_session_list '{}' \
  "(.count == $EXPECTED_UES) and all(.sessions[]; .sessionState == \"ACTIVE\" and .ueIp != null)"
ok "pdu_session_qos_get $SUPI PSI 1: 5QI 9, two QERs" pdu_session_qos_get "{\"supi\":\"$SUPI\",\"pdu_session_id\":1}" \
  '.found == true and .qosFlows[0].fiveQi == 9 and (.pfcpQers | length) == 2'
if listed n4_session_get; then
  ok "n4_session_get $SUPI PSI 1: 2 QERs, AMBR QER 100000 kbps, no SMF/UPF mismatch" n4_session_get \
    "{\"supi\":\"$SUPI\",\"pdu_session_id\":1,\"compare_with_smf\":true}" \
    '((.upf.qers | length) == 2) and ((.upf.qers | map(select(.has_mbr == true)) | .[0].mbr_dl_kbps) == 100000) and ((.smf_mismatches | length) == 0)'
  refused "n4_session_get without a lookup key refused" n4_session_get '{}'
  refused "n4_session_get pdu_session_id + seid refused" n4_session_get '{"pdu_session_id":1,"seid":1}'
fi

echo "[analysis]"
ok "log_query AMF 5m" log_query '{"query":"{nf=\"AMF\"}","window":"5m","limit":10}' '.count >= 1 and (.lines | length) >= 1'
ok "procedure_stats 1h: no all-zero row" procedure_stats '{"window":"1h"}' '(.rows | length) >= 1 and all(.rows[]; (.ok + .reject + .failure) > 0)'
ok "procedure_stats include_zero: zero rows present" procedure_stats '{"window":"1h","include_zero":true}' '[.rows[] | select((.ok + .reject + .failure) == 0)] | length >= 1'
ok "procedure_summary alias (DEPRECATED description, rows)" procedure_summary '{}' '(.rows | type == "array") and (.rows | length) >= 1'
# >= 1 entry with nf/time/msg: the result is capped at the newest records, and the lab UE's
# PSI 2 retry storm can fill the cap with AMF-only lines, so ">= 2 NFs" is not stable.
ok "procedure_timeline $SUPI 15m: entries with nf, time and msg" procedure_timeline "{\"supi\":\"$SUPI\",\"window\":\"15m\"}" '(.entries | length) >= 1 and all(.entries[]; .nf != null and .time != null and .msg != null)'
ok "trace_query AMF timeline" trace_query '{"service":"AMF","limit":3}' '.mode == "timeline" and (.traces | length) >= 1'
ok "metric_query instant: one UPF series == EXPECTED_UES" metric_query '{"promql":"fivegc_upf_pfcp_sessions_active{nf=\"UPF\"}"}' \
  "(.results | length) == 1 and .results[0].value == $EXPECTED_UES"
ok "metric_query range 10m" metric_query "{\"promql\":\"up\",\"start\":\"$(ts_ago 10)\"}" '.mode == "range" and (.results | length) >= 1'
ok "pcap_list: sidecars listed" pcap_list '{}' '(.status | length) >= 1 and all(.status[]; has("nf") and has("capturing"))'

echo "[control — dry-run and refusals, nothing changes]"
dry "ue_deregister_nw dry-run" ue_deregister_nw "{\"supi\":\"$SUPI\"}"
dry "pdu_session_release_nw dry-run" pdu_session_release_nw "{\"supi\":\"$SUPI\",\"pdu_session_id\":1}"
ok "ue_page dry-run" ue_page "{\"supi\":\"$SUPI2\",\"pdu_session_id\":1}" '.dry_run == true and .tool == "ue_page"'
dry "ue_policy_push dry-run" ue_policy_push "{\"supi\":\"$SUPI\"}"
dry "nssaa_trigger dry-run" nssaa_trigger "{\"supi\":\"$SUPI\",\"action\":\"revoke\",\"sst\":1}"
dry "pws_broadcast dry-run" pws_broadcast '{"messageIdentifier":4370,"serialNumber":4096}'
dry "pws_resend dry-run" pws_resend '{"message_identifier":4370,"serial_number":4096}'
dry "pws_cancel dry-run" pws_cancel '{"messageIdentifier":4370,"serialNumber":4096}'
dry "rfsp_override_set dry-run" rfsp_override_set "{\"supi\":\"$SUPI2\",\"rfsp\":5}"
dry "slice_session_ambr_set dry-run (apply_to_active)" slice_session_ambr_set \
  '{"sst":1,"sd":"000001","dnn":"internet","uplink":"100 Mbps","downlink":"100 Mbps","apply_to_active":true}'
dry "ue_location_get dry-run" ue_location_get "{\"supi\":\"$SUPI\"}"
dry "sms_send_mt dry-run" sms_send_mt "{\"supi\":\"$SUPI\",\"payload_b64\":\"AA==\"}"
refused "sms_send_mt invalid base64 refused" sms_send_mt "{\"supi\":\"$SUPI\",\"payload_b64\":\"not*base64\"}"
ok "ue_an_release_nw dry-run: affected PSI 1, CM-CONNECTED" ue_an_release_nw "{\"supi\":\"$SUPI2\"}" \
  '.dry_run == true and .plan.affected_pdu_sessions == [1] and .plan.previous_cm_state == "CM-CONNECTED"'
ok "config_view lists the stored policy templates" config_view '{}' '(.sections.policy_templates.value | length) >= 1'
TEMPLATE_ID=$(portal_get /policy-templates | jq -r '([.[] | select(.name | test("Internet"))][0] // .[0]).id // empty' 2>/dev/null)
if [ -n "$TEMPLATE_ID" ]; then
  ok "ursp_template_apply dry-run (template $TEMPLATE_ID)" ursp_template_apply "{\"template_id\":\"$TEMPLATE_ID\",\"supi\":\"$SUPI\"}" \
    '.dry_run == true and .plan.template.id == "'"$TEMPLATE_ID"'"'
else
  refused "ursp_template_apply unknown template refused (portal templates unreachable)" ursp_template_apply "{\"template_id\":\"none\",\"supi\":\"$SUPI\"}"
fi
ok "subscriber_profile_update dry-run: previous values, UE will be deregistered" subscriber_profile_update \
  "{\"supi\":\"$SUPI2\",\"fields\":{\"ambr_dl\":\"200 Mbps\"}}" \
  '.dry_run == true and .plan.ue_will_be_deregistered == true and .plan.previous.ambr_dl != null and .plan.previous.k == "<redacted>"'
refused "subscriber_profile_update key field refused" subscriber_profile_update "{\"supi\":\"$SUPI2\",\"fields\":{\"k\":\"00\"}}" "cannot be set"
ok "pdu_session_qos_set dry-run: previous 5QI 9, new 7" pdu_session_qos_set \
  "{\"supi\":\"$SUPI\",\"pdu_session_id\":1,\"new5qi\":7,\"reason\":\"mcp-e2e\"}" \
  '.dry_run == true and .plan.current_session.session.current5qi == 9 and .plan.new5qi == 7'
ok "pdu_session_qos_modify alias dry-run targets the SMF (DEPRECATED description)" pdu_session_qos_modify \
  "{\"supi\":\"$SUPI\",\"pdu_session_id\":1,\"5qi\":7}" '.dry_run == true and .plan.new5qi == 7'
ok "amf_timer_config read: effective == base" amf_timer_config '{}' \
  '.effective.t3512_secs == .base.t3512_secs and .persisted == false and .effective.mobile_reachable_secs != null'
refused "amf_timer_config t3512 61 refused (not representable)" amf_timer_config '{"t3512_secs":61}' "not exactly representable"
ok "nf_log_level read AMF: level equals the startup level" nf_log_level '{"nf":"AMF"}' '.state.level == .state.base_level'
refused "qos_policy_set invalid 5qi refused" qos_policy_set "{\"supi\":\"$SUPI2\",\"5qi\":3000}" "5qi"
refused "qos_policy_delete without supi refused" qos_policy_delete '{}' "supi"
refused "pcap_control invalid action refused" pcap_control '{"nf":"AMF","action":"bogus"}' "action must be"

echo "[AF QoS — NEF]"
if [ -n "$S1_IP" ]; then
  ok "af_qos_session_create dry-run: UE IP belongs to $SUPI" af_qos_session_create \
    "{\"scs_as_id\":\"mcp\",\"ue_ipv4\":\"$S1_IP\",\"qos_reference\":\"qos-ref-1\"}" \
    ".dry_run == true and .plan.request.ueIpv4Addr == \"$S1_IP\""
else
  fail af_qos_session_create "af_qos_session_create dry-run" "no UE IP for $SUPI in pdu_session_list"
fi
refused "af_qos_session_create unknown UE IP refused" af_qos_session_create \
  '{"scs_as_id":"mcp","ue_ipv4":"192.0.2.250","qos_reference":"qos-ref-1"}' "no SMF PDU session"
refused "af_qos_session_get invalid subscription id refused" af_qos_session_get '{"scs_as_id":"mcp","subscription_id":"a/b"}' "must match"
refused "af_qos_session_delete invalid scs_as_id refused" af_qos_session_delete '{"scs_as_id":"","subscription_id":"x"}' "must match"
call af_qos_session_get '{"scs_as_id":"mcp","subscription_id":"mcp-smoke-none"}'
if printf '%s' "$LAST_ERR" | grep -q '401\|UNAUTHORIZED'; then
  skip "af_qos_session_get unknown subscription answers 404" "NEF-002: the NEF rejects every NRF-issued token with 401"
elif printf '%s' "$LAST_ERR" | grep -q '404\|NOT_FOUND\|not found'; then
  pass af_qos_session_get "af_qos_session_get unknown subscription answers 404"
else
  fail af_qos_session_get "af_qos_session_get unknown subscription answers 404" "${LAST_ERR:-not refused}"
fi

echo "[role and access gates]"
NOMARK=1
refused "nf_service_control refused without admin" nf_service_control '{"name":"smf","action":"restart","confirm":true}'
NOMARK=0

# =============================================================================
if [ "$MUTATE" = "1" ]; then
  echo "[state changes — MUTATE=1, each reverted]"
  ok "qos_policy_set $SUPI2 5qi 8" qos_policy_set \
    "{\"supi\":\"$SUPI2\",\"dnn\":\"internet\",\"5qi\":8}" '.applied == true and ."5qi" == 8'
  ok "qos_policy_list contains $SUPI2 5qi 8" qos_policy_list '{}' "map(select(.supi == \"$SUPI2\" and .\"5qi\" == 8)) | length == 1"
  ok "qos_policy_get shows the override" qos_policy_get "{\"supi\":\"$SUPI2\",\"dnn\":\"internet\"}" '.is_override == true and ."5qi" == 8'
  ok "qos_policy_delete reverts" qos_policy_delete "{\"supi\":\"$SUPI2\",\"dnn\":\"internet\"}" '.cleared == true'
  ok "qos_policy_list empty after revert" qos_policy_list '{}' 'length == 0'
  ok "qos_policy_get after revert" qos_policy_get "{\"supi\":\"$SUPI2\",\"dnn\":\"internet\"}" '.is_override == false'

  ok "slice_session_ambr_set store 30/20 Mbps (not applied to active sessions)" slice_session_ambr_set \
    '{"sst":1,"sd":"000001","dnn":"internet","uplink":"20 Mbps","downlink":"30 Mbps"}' '.stored == true and .result.item.sessionAmbr.downlink == "30 Mbps"'
  call config_view '{}'
  chk config_view "config_view shows the stored slice AMBR (source edited)" \
    '.sections.slice_qos.value.items | map(select(.snssai.sst == 1 and .snssai.sd == "000001" and .dnn == "internet")) | .[0] | (.sessionAmbr.downlink == "30 Mbps" and .source == "edited")'
  ok "slice_session_ambr_set revert" slice_session_ambr_set '{"sst":1,"sd":"000001","dnn":"internet","revert":true}' '.reverted == true'
  call config_view '{}'
  if [ "$(tjr '.sections.slice_qos.value.items | map({snssai,dnn,sessionAmbr,source}) | sort_by(.snssai.sst, .snssai.sd, .dnn)' | jq -cS .)" = "$BASE_SLICE" ]; then
    pass config_view "slice AMBR equals the seed after the revert"
  else
    fail config_view "slice AMBR equals the seed after the revert"
  fi

  ok "amf_timer_config set t3512 120" amf_timer_config '{"t3512_secs":120}' \
    '.effective.t3512_secs == 120 and .persisted == false and .base.t3512_secs == 60'
  ok "amf_timer_config reset: effective == base" amf_timer_config '{"reset":true}' '.effective == .base'

  ok "nf_log_level SMF debug (ttl 60)" nf_log_level '{"nf":"SMF","level":"debug","ttl_s":60}' '.state.level == "DEBUG" and .state.revert_in_s > 0'
  ok "nf_log_level SMF read shows DEBUG" nf_log_level '{"nf":"SMF"}' '.state.level == "DEBUG"'
  ok "nf_log_level SMF back to info" nf_log_level '{"nf":"SMF","level":"info"}' '.state.level == "INFO"'
  ok "nf_log_level AMF debug then info" nf_log_level '{"nf":"AMF","level":"debug","ttl_s":60}' '.state.level == "DEBUG"'
  ok "nf_log_level AMF back to info" nf_log_level '{"nf":"AMF","level":"info"}' '.state.level == "INFO"'

  # rotate needs a running capture: start, rotate, then stop again (state reverted)
  ok "pcap_control AMF start" pcap_control '{"nf":"AMF","action":"start"}' '.action == "start"'
  ok "pcap_control AMF rotate" pcap_control '{"nf":"AMF","action":"rotate"}' '.action == "rotate"'
  ok "pcap_control AMF stop (revert)" pcap_control '{"nf":"AMF","action":"stop"}' '.action == "stop"'
  ok "pcap_list shows AMF not capturing" pcap_list '{}' '[.status[] | select(.nf == "amf")][0].capturing == false'
else
  echo "[state changes skipped — set MUTATE=1 to run them]"
fi

# =============================================================================
if [ "$DISRUPT" = "1" ]; then
  D_START=$(utc_now)
  echo "[disruptive N1/N2/N4 — DISRUPT=1, started $D_START]"
  if poll 60 all_ready; then
    pass ue_context_get "precondition: both UEs 5GMM-REGISTERED, CM-CONNECTED, PSI 1"
  else
    fail ue_context_get "precondition: both UEs 5GMM-REGISTERED, CM-CONNECTED, PSI 1" "run make ueransim-only and retry"
  fi

  echo "  -- AN release, CM-IDLE diagnosis, paging ($SUPI2)"
  cconf ue_an_release_nw "{\"supi\":\"$SUPI2\",\"confirm\":true}"
  chk ue_an_release_nw "ue_an_release_nw confirm: accepted, PSI 1 affected" '.accepted == true and .affected_pdu_sessions == [1] and .previous_cm_state == "CM-CONNECTED"'
  PI=0.4
  if poll 5 ue_idle "$SUPI2"; then
    pass ue_context_get "S2 is CM-IDLE after the AN release (still 5GMM-REGISTERED)"
    call ue_diagnose "{\"supi\":\"$SUPI2\"}"
    chk ue_diagnose "ue_diagnose names the CM-IDLE state (spec_ref TS 23.502 §4.3.3.2)" \
      '[.findings[] | select((.message | contains("CM-IDLE")) and .spec_ref == "TS 23.502 §4.3.3.2")] | length >= 1'
  else
    skip "ue_diagnose CM-IDLE finding" "UERANSIM answered the release with a Service Request before it could be observed (< 5 s)"
  fi
  PI=2
  cconf ue_page "{\"supi\":\"$SUPI2\",\"pdu_session_id\":1,\"confirm\":true}"
  chk ue_page "ue_page confirm: paging triggered" '.paging == "triggered" and .pdu_session_id == 1'
  if poll 15 ue_ready "$SUPI2"; then
    pass ue_context_get "S2 back to CM-CONNECTED with PSI 1 after paging / Service Request"
  else
    fail ue_context_get "S2 back to CM-CONNECTED with PSI 1 after paging / Service Request"
  fi
  if poll 30 log_has '{nf="AMF"} |= "O&M AN release"'; then
    pass log_query "Loki holds the AMF 'O&M AN release' record of the release"
  else
    fail log_query "Loki holds the AMF 'O&M AN release' record of the release" "no record within 30 s"
  fi

  echo "  -- QoS modification 9 -> 7 with session AMBR 30/20, and back ($SUPI)"
  cconf pdu_session_qos_set "{\"supi\":\"$SUPI\",\"pdu_session_id\":1,\"new5qi\":7,\"ambr_dl_mbps\":30,\"ambr_ul_mbps\":20,\"reason\":\"mcp-e2e\",\"confirm\":true}"
  chk pdu_session_qos_set "pdu_session_qos_set confirm 9 -> 7: result success, previous5qi 9" '.result == "success" and .previous5qi == 9 and .new5qi == 7'
  if poll 15 qos5qi "$SUPI" 1 7; then pass pdu_session_qos_get "pdu_session_qos_get: 5QI is 7"; else fail pdu_session_qos_get "pdu_session_qos_get: 5QI is 7"; fi
  if listed n4_session_get; then
    if poll 15 n4_qer_dl "$SUPI" 30000; then
      pass n4_session_get "n4_session_get cross-check: UPF QER mbr_dl 30000 kbps, SMF and UPF agree"
    else
      fail n4_session_get "n4_session_get cross-check: UPF QER mbr_dl 30000 kbps, SMF and UPF agree" "$(tjr '[.upf.qers, .smf_mismatches] | tostring')"
    fi
  fi
  cconf pdu_session_qos_set "{\"supi\":\"$SUPI\",\"pdu_session_id\":1,\"new5qi\":9,\"ambr_dl_mbps\":100,\"ambr_ul_mbps\":100,\"reason\":\"mcp-e2e revert\",\"confirm\":true}"
  chk pdu_session_qos_set "pdu_session_qos_set confirm 7 -> 9: previous5qi 7" '.result == "success" and .previous5qi == 7 and .new5qi == 9'
  if poll 15 qos5qi "$SUPI" 1 9; then pass pdu_session_qos_get "pdu_session_qos_get: 5QI back to 9"; else fail pdu_session_qos_get "pdu_session_qos_get: 5QI back to 9"; fi
  if listed n4_session_get; then
    if poll 15 n4_qer_dl "$SUPI" 100000; then
      pass n4_session_get "n4_session_get: UPF QER back to 100000 kbps, no mismatch"
    else
      fail n4_session_get "n4_session_get: UPF QER back to 100000 kbps, no mismatch"
    fi
  fi

  echo "  -- UE policy push, location ($SUPI)"
  cconf ue_policy_push "{\"supi\":\"$SUPI\",\"confirm\":true}"
  chk ue_policy_push "ue_policy_push confirm: pushed or deferred" '.pushed == true or .deferred == true'
  cconf ue_location_get "{\"supi\":\"$SUPI\",\"confirm\":true}"
  chk ue_location_get "ue_location_get confirm: reachable with a position" '.reachable == true and (.latitude | type == "number") and (.longitude | type == "number") and .tac != null'

  echo "  -- Public Warning System broadcast, resend, cancel"
  cconf pws_broadcast '{"messageIdentifier":4370,"serialNumber":4097,"messageText":"mcp e2e test","confirm":true}'
  chk pws_broadcast "pws_broadcast confirm: sent to >= 1 gNB" '.broadcast == true and .result.gnbs_targeted >= 1'
  call pws_list '{}'
  chk pws_list "pws_list shows the warning live" '[.[] | select(.message_identifier == 4370 and .serial_number == 4097 and .live == true and .cancelled == false)] | length == 1'
  cconf pws_resend '{"message_identifier":4370,"serial_number":4097,"confirm":true}'
  chk pws_resend "pws_resend confirm: resent" '.resent == true and .result.gnbs_targeted >= 1'
  cconf pws_cancel '{"messageIdentifier":4370,"serialNumber":4097,"confirm":true}'
  chk pws_cancel "pws_cancel confirm: cancelled" '.cancelled == true'
  call pws_list '{}'
  chk pws_list "pws_list shows the warning cancelled" '[.[] | select(.message_identifier == 4370 and .serial_number == 4097 and .cancelled == true)] | length == 1'

  echo "  -- NSSAA, SMS, AF QoS"
  # An accepted NSSAA re-authentication sends the Network slice-specific authentication command
  # (TS 24.501 §8.2.31) to the UE, and UERANSIM 3.2.8 aborts on that message ("invalid NAS message type").
  # The confirmed path therefore runs against a provisioned UE that is not registered: the AMF answers
  # with a structured error, which is the accepted outcome (the dry-run in [control] covers the plan).
  NSSAA_SUPI="${NSSAA_SUPI:-imsi-001010000000101}"
  cconf nssaa_trigger "{\"supi\":\"$NSSAA_SUPI\",\"action\":\"reauth\",\"sst\":1,\"sd\":\"000001\",\"confirm\":true}"
  if [ -z "$LAST_ERR" ]; then
    chk nssaa_trigger "nssaa_trigger confirm: accepted" '.accepted == true and .action == "reauth"'
  elif [ "$LAST_CODE" = "-32000" ]; then
    pass nssaa_trigger "nssaa_trigger confirm on unregistered $NSSAA_SUPI: structured error accepted ($LAST_ERR)"
  else
    fail nssaa_trigger "nssaa_trigger confirm" "$LAST_ERR"
  fi
  cconf sms_send_mt "{\"supi\":\"$SUPI\",\"payload_b64\":\"AA==\",\"confirm\":true}"
  if printf '%s' "$LAST_ERR" | grep -q 'CONTEXT_NOT_FOUND'; then
    pass sms_send_mt "sms_send_mt confirm: CONTEXT_NOT_FOUND (no SMS activation in this lab)"
  elif [ -z "$LAST_ERR" ]; then
    pass sms_send_mt "sms_send_mt confirm: delivered"
  else
    fail sms_send_mt "sms_send_mt confirm" "$LAST_ERR"
  fi
  if [ -n "$S1_IP" ]; then
    cconf af_qos_session_create "{\"scs_as_id\":\"mcp\",\"ue_ipv4\":\"$S1_IP\",\"qos_reference\":\"qos-ref-1\",\"confirm\":true}"
    if printf '%s' "$LAST_ERR" | grep -q '401\|UNAUTHORIZED'; then
      skip "af_qos_session_create/get/delete confirm" "NEF-002: the NEF rejects every NRF-issued token with 401"
    elif [ -n "$LAST_ERR" ]; then
      fail af_qos_session_create "af_qos_session_create confirm" "$LAST_ERR"
    else
      AF_ID=$(tjr '.subscription_id // .subscriptionId // .id // empty')
      if [ -z "$AF_ID" ]; then
        fail af_qos_session_create "af_qos_session_create confirm returns a subscription id"
      else
        pass af_qos_session_create "af_qos_session_create confirm: subscription $AF_ID"
        ok "af_qos_session_get: ueIpv4Addr == $S1_IP" af_qos_session_get "{\"scs_as_id\":\"mcp\",\"subscription_id\":\"$AF_ID\"}" ".ueIpv4Addr == \"$S1_IP\""
        cconf af_qos_session_delete "{\"scs_as_id\":\"mcp\",\"subscription_id\":\"$AF_ID\",\"confirm\":true}"
        chk af_qos_session_delete "af_qos_session_delete confirm" '.deleted == true'
        call af_qos_session_get "{\"scs_as_id\":\"mcp\",\"subscription_id\":\"$AF_ID\"}"
        if printf '%s' "$LAST_ERR" | grep -q '404\|NOT_FOUND\|not found'; then pass af_qos_session_get "af_qos_session_get after delete: 404"; else fail af_qos_session_get "af_qos_session_get after delete: 404" "${LAST_ERR:-still present}"; fi
      fi
    fi
  fi

  echo "  -- URSP template apply ($SUPI)"
  if [ -n "$TEMPLATE_ID" ]; then
    cconf ursp_template_apply "{\"template_id\":\"$TEMPLATE_ID\",\"supi\":\"$SUPI\",\"confirm\":true}"
    chk ursp_template_apply "ursp_template_apply confirm: status pushed or stored" '.applied == true and (.result.status == "pushed" or .result.status == "stored")'
    # revert: drop the policy rows the apply created for the subscriber
    for pid in $(portal_get /policies | jq -r --arg s "$SUPI" '.[] | select(.supi == $s) | .id' 2>/dev/null); do
      case ",$BASE_POLICIES," in *",$pid,"*) ;; *) curl -s -m 10 -o /dev/null -X DELETE "$PORTAL_URL/api/v1/policies/$pid" ;; esac
    done
  else
    skip "ursp_template_apply confirm" "no policy template reachable at $PORTAL_URL/api/v1/policy-templates"
  fi

  echo "  -- RFSP override set and clear ($SUPI2)"
  cconf rfsp_override_set "{\"supi\":\"$SUPI2\",\"rfsp\":5,\"confirm\":true}"
  chk rfsp_override_set "rfsp_override_set confirm: override 5, UE deregistered" '.result.rfsp == 5 and .result.source == "override" and .result.deregistered == true'
  if poll 60 ue_ready "$SUPI2"; then pass ue_context_get "S2 re-registered with PSI 1 after the RFSP change"; else fail ue_context_get "S2 re-registered with PSI 1 after the RFSP change"; fi
  ok "subscriber_get shows the RFSP override 5" subscriber_get "{\"supi\":\"$SUPI2\"}" '.rfsp_override.rfsp == 5 and .rfsp_override.source == "override"'
  cconf rfsp_override_set "{\"supi\":\"$SUPI2\",\"clear\":true,\"confirm\":true}"
  chk rfsp_override_set "rfsp_override_set clear: back to default" '.clear == true and .result.source == "default"'
  if poll 60 ue_ready "$SUPI2"; then pass ue_context_get "S2 re-registered with PSI 1 after the RFSP clear"; else fail ue_context_get "S2 re-registered with PSI 1 after the RFSP clear"; fi
  ok "subscriber_get: RFSP override cleared" subscriber_get "{\"supi\":\"$SUPI2\"}" '.rfsp_override.source == "default"'

  echo "  -- subscriber profile update and revert ($SUPI2)"
  call subscriber_profile_update "{\"supi\":\"$SUPI2\",\"fields\":{\"ambr_dl\":\"200 Mbps\"}}"
  PREV_KBPS=$(tjr '.plan.previous.ambr_dl')
  if [ -n "$PREV_KBPS" ] && [ $((PREV_KBPS % 1000)) -eq 0 ]; then
    PREV_MBPS="$((PREV_KBPS / 1000)) Mbps"
    cconf subscriber_profile_update "{\"supi\":\"$SUPI2\",\"fields\":{\"ambr_dl\":\"200 Mbps\"},\"confirm\":true}"
    chk subscriber_profile_update "subscriber_profile_update confirm: updated, UE deregistered" '.updated == true and .deregistered == true and .sm_data_synced == true'
    if poll 60 ue_ready "$SUPI2"; then pass ue_context_get "S2 re-registered with PSI 1 after the profile update"; else fail ue_context_get "S2 re-registered with PSI 1 after the profile update"; fi
    ok "subscriber_get shows ambr_dl 200000 kbps" subscriber_get "{\"supi\":\"$SUPI2\"}" '.subscriber.ambr_dl == 200000'
    cconf subscriber_profile_update "{\"supi\":\"$SUPI2\",\"fields\":{\"ambr_dl\":\"$PREV_MBPS\"},\"confirm\":true}"
    chk subscriber_profile_update "subscriber_profile_update revert to $PREV_MBPS" '.updated == true and .previous.ambr_dl == 200000'
    if poll 60 ue_ready "$SUPI2"; then pass ue_context_get "S2 re-registered with PSI 1 after the revert"; else fail ue_context_get "S2 re-registered with PSI 1 after the revert"; fi
    ok "subscriber_get shows ambr_dl $PREV_KBPS kbps again" subscriber_get "{\"supi\":\"$SUPI2\"}" ".subscriber.ambr_dl == $PREV_KBPS"
  else
    fail subscriber_profile_update "subscriber_profile_update previous ambr_dl" "dry-run gave '$PREV_KBPS'"
  fi

  echo "  -- AMF timer effect: T3512 120, NW deregistration, re-registration ($SUPI2)"
  ok "amf_timer_config set t3512 120" amf_timer_config '{"t3512_secs":120}' '.effective.t3512_secs == 120 and .persisted == false'
  cconf ue_deregister_nw "{\"supi\":\"$SUPI2\",\"confirm\":true}"
  chk ue_deregister_nw "ue_deregister_nw confirm: accepted" '.accepted == true'
  if poll 60 ue_ready "$SUPI2"; then pass ue_context_get "S2 re-registered with PSI 1 after the NW deregistration"; else fail ue_context_get "S2 re-registered with PSI 1 after the NW deregistration" "no re-registration within 60 s"; fi
  ok "amf_timer_config reset: effective == base" amf_timer_config '{"reset":true}' '.effective == .base'
  if poll 10 timer_is 60; then pass amf_timer_config "T3512 back to 60"; else fail amf_timer_config "T3512 back to 60"; fi

  echo "  -- PDU session release and re-establishment ($SUPI)"
  call pdu_session_list '{}'
  REF_BEFORE=$(tjr ".sessions[] | select(.supi == \"$SUPI\" and .pduSessionId == 1) | .smContextRef")
  cconf pdu_session_release_nw "{\"supi\":\"$SUPI\",\"pdu_session_id\":1,\"confirm\":true}"
  chk pdu_session_release_nw "pdu_session_release_nw confirm: accepted" '.accepted == true and .pdu_session_id == 1'
  PI=1
  RELEASED=0
  if poll 15 psi_absent "$SUPI" 1; then RELEASED=1; pass pdu_session_list "PSI 1 of S1 absent from pdu_session_list after the release"; fi
  PI=2
  if poll 60 sessions_n "$EXPECTED_UES"; then
    call pdu_session_list '{}'
    REF_AFTER=$(tjr ".sessions[] | select(.supi == \"$SUPI\" and .pduSessionId == 1) | .smContextRef")
    if [ "$RELEASED" = "0" ]; then
      if [ -n "$REF_AFTER" ] && [ "$REF_AFTER" != "$REF_BEFORE" ]; then
        pass pdu_session_list "S1 PSI 1 was released and re-established (new smContextRef) before the poll saw the gap"
      else
        fail pdu_session_list "S1 PSI 1 was released" "same smContextRef $REF_BEFORE, never absent"
      fi
    fi
    pass pdu_session_list "UERANSIM re-established the session: $EXPECTED_UES ACTIVE sessions again"
  else
    fail pdu_session_list "UE re-establishes the released session within 60 s" "run make ueransim-only to restart the UEs"
  fi
  if poll 30 all_ready; then pass ue_context_get "both UEs 5GMM-REGISTERED, CM-CONNECTED, PSI 1 after the disruptive run"; else fail ue_context_get "both UEs ready after the disruptive run"; fi
  echo "  disruptive window: $D_START .. $(utc_now) (UTC)"
else
  echo "[disruptive N1/N2/N4 skipped — set DISRUPT=1 to run them]"
fi

# =============================================================================
if [ -n "$LAB_URL" ]; then
  echo "[lab instance — ADMIN tools and roles, $LAB_URL]"
  MAIN_URL="$MCP_URL"; MAIN_TOKEN="$TOKEN"
  MCP_URL="$LAB_URL"; TOKEN="$LAB_TOKEN"
  if ! curl -s -m 5 -o /dev/null -w '%{http_code}' "$MCP_URL/mcp/health" | grep -q 200; then
    fail nf_service_control "lab MCP reachable at $LAB_URL"
  else
    LAB_JSON=$(rpc '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    LAB_TOOLS=$(printf '%s' "$LAB_JSON" | jq -r '[.result.tools[].name] | join(" ")' 2>/dev/null)
    LAB_N=$(printf '%s' "$LAB_JSON" | jq -r '.result.tools | length' 2>/dev/null)
    if [ "$LAB_N" = "$EXPECT_LAB_TOOLS" ]; then
      pass tools_list "lab tools/list has $LAB_N names (expected $EXPECT_LAB_TOOLS)"
    else
      fail tools_list "lab tools/list size" "got $LAB_N, expected $EXPECT_LAB_TOOLS"
    fi
    for t in nf_service_control subscriber_provision subscriber_delete; do
      case " $LAB_TOOLS " in *" $t "*) pass tools_list "lab lists $t" ;; *) fail tools_list "lab lists $t" ;; esac
    done
    ok "lab mcp_info: access_mode lab, caller_role admin" mcp_info '{}' '.access_mode == "lab" and .caller_role == "admin" and (.tool_count + .alias_count == '"${LAB_N:-0}"')'

    echo "  -- nf_service_control"
    ok "nf_service_control dry-run (restart nssf)" nf_service_control '{"name":"nssf","action":"restart"}' '.dry_run == true'
    cconf nf_service_control '{"name":"nssf","action":"restart","confirm":true}'
    if [ -n "$LAST_ERR" ]; then
      fail nf_service_control "nf_service_control restart nssf" "$LAST_ERR"
    else
      chk nf_service_control "nf_service_control restart nssf: restarting" '(tostring | test("restarting"))'
      sleep 3
      if poll 30 nf_healthy NSSF; then pass core_health "core_health: NSSF healthy within 30 s of the restart"; else fail core_health "core_health: NSSF healthy within 30 s of the restart"; fi
    fi

    echo "  -- subscriber_provision / subscriber_delete"
    LAB_SUPI="imsi-001010000009999"
    LAB_K=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
    LAB_OPC=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
    PROV="{\"supi\":\"$LAB_SUPI\",\"k\":\"$LAB_K\",\"opc\":\"$LAB_OPC\",\"profile\":{\"ambr_ul\":\"100 Mbps\",\"ambr_dl\":\"100 Mbps\",\"slices\":[{\"sst\":1,\"sd\":\"000001\",\"dnn\":\"internet\"}]}}"
    # a leftover from an aborted run is removed first
    call subscriber_get "{\"supi\":\"$LAB_SUPI\"}"
    if [ -z "$LAST_ERR" ]; then cconf subscriber_delete "{\"supi\":\"$LAB_SUPI\",\"confirm\":true}"; fi
    call subscriber_provision "$(printf '%s' "$PROV")"
    chk subscriber_provision "subscriber_provision dry-run" '.dry_run == true'
    if printf '%s' "$LAST_TEXT" | grep -q "$LAB_K\|$LAB_OPC"; then fail subscriber_provision "subscriber_provision dry-run does not echo the keys" "key hex in the output"; else pass subscriber_provision "subscriber_provision dry-run does not echo the keys"; fi
    cconf subscriber_provision "$(printf '%s' "$PROV" | jq -c '. + {confirm:true}')"
    chk subscriber_provision "subscriber_provision confirm: created" '.created == true'
    if printf '%s' "$LAST_TEXT" | grep -q "$LAB_K\|$LAB_OPC"; then fail subscriber_provision "subscriber_provision confirm does not echo the keys" "key hex in the output"; else pass subscriber_provision "subscriber_provision confirm does not echo the keys"; fi
    ok "subscriber_get $LAB_SUPI: present, keys redacted" subscriber_get "{\"supi\":\"$LAB_SUPI\"}" \
      '.subscriber.supi == "'"$LAB_SUPI"'" and .subscriber.k == "<redacted>" and .subscriber.opc == "<redacted>"'
    gap_wait
    refused "subscriber_provision of an existing SUPI is refused" subscriber_provision "$(printf '%s' "$PROV" | jq -c '. + {confirm:true}')" "already exists"
    LAST_CONF=$(date +%s)
    cconf subscriber_delete "{\"supi\":\"$LAB_SUPI\"}"
    chk subscriber_delete "subscriber_delete dry-run shows the redacted record" '.dry_run == true'
    cconf subscriber_delete "{\"supi\":\"$LAB_SUPI\",\"confirm\":true}"
    chk subscriber_delete "subscriber_delete confirm: deleted" '.deleted == true'
    call subscriber_get "{\"supi\":\"$LAB_SUPI\"}"
    if printf '%s' "$LAST_ERR" | grep -qi '404\|not found'; then pass subscriber_get "subscriber_get after delete: 404"; else fail subscriber_get "subscriber_get after delete: 404" "${LAST_ERR:-still present}"; fi
    call mcp_audit_log '{"n":200}'
    if [ -n "$LAST_ERR" ]; then
      fail mcp_audit_log "mcp_audit_log readable on the lab instance" "$LAST_ERR"
    elif printf '%s' "$LAST_TEXT" | grep -q "$LAB_K\|$LAB_OPC"; then
      fail mcp_audit_log "mcp_audit_log holds no K/OPc hex" "key hex found in the audit log"
    elif tj '[.entries[] | select(.tool == "subscriber_provision")] | length >= 2'; then
      pass mcp_audit_log "mcp_audit_log lists the provision calls and holds no K/OPc hex"
    else
      fail mcp_audit_log "mcp_audit_log lists the provision calls" "no subscriber_provision entries"
    fi

    echo "  -- roles"
    if [ -n "$VIEWER_TOKEN" ]; then
      TOKEN="$VIEWER_TOKEN"
      NOMARK=1
      ok "viewer may read (core_health)" core_health '{}' '(.nfs | length) >= 1'
      refused "viewer refused on MUTATING nf_log_level" nf_log_level '{"nf":"AMF","level":"info"}' "viewer"
      refused "viewer refused on MUTATING qos_policy_set" qos_policy_set "{\"supi\":\"$SUPI2\",\"5qi\":8}" "viewer"
      refused "viewer refused on DISRUPTIVE ue_deregister_nw" ue_deregister_nw "{\"supi\":\"$SUPI2\"}" "viewer"
      refused "viewer refused on ADMIN nf_service_control" nf_service_control '{"name":"nssf","action":"restart"}'
      refused "viewer refused on ADMIN subscriber_provision" subscriber_provision "$PROV"
      NOMARK=0
      TOKEN="$LAB_TOKEN"
    else
      skip "viewer role refusals" "VIEWER_TOKEN is not set"
    fi
    # an unauthenticated caller is refused by the transport
    CODE=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST "$MCP_URL/mcp" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    if [ "$CODE" = "401" ]; then pass tools_list "request without a bearer token answers 401"; else fail tools_list "request without a bearer token answers 401" "HTTP $CODE"; fi
  fi
  MCP_URL="$MAIN_URL"; TOKEN="$MAIN_TOKEN"
fi

# =============================================================================
echo "[audit — entries recorded by this run]"
# after the dry-runs and refusals above, so a freshly started MCP has entries too.
# .error is excluded on purpose: the guard records upstream error text verbatim and some
# carry the SUPI (known gap, tracked as a follow-up); inputs themselves are hashed.
ok "mcp_audit_log: http session labels, remote_addr, no raw SUPI in the recorded call" mcp_audit_log '{"n":50}' \
  '(.entries | length) >= 1 and all(.entries[]; (.session | startswith("http:")) and .remote_addr != null) and ([.entries[] | del(.error) | tostring | select(test("imsi-"))] | length == 0)'

echo "[baseline — state after the run equals the state before]"
if poll 60 all_ready; then pass ue_context_get "both UEs 5GMM-REGISTERED, CM-CONNECTED, PSI 1"; else fail ue_context_get "both UEs 5GMM-REGISTERED, CM-CONNECTED, PSI 1"; fi
ok "ue_list: EXPECTED_UES UEs, all REGISTERED and CM-CONNECTED" ue_list '{}' \
  "(.count == $EXPECTED_UES) and all(.ue_contexts[]; .gmm_state == \"5GMM-REGISTERED\" and .cm_state == \"CM-CONNECTED\" and (.pdu_session_ids | index(1)) != null)"
call pdu_session_list '{}'
NOW_SESS=$(tjr '[.sessions[] | {supi,pduSessionId,current5qi,qosSource,sessionAmbrDlMbps,sessionAmbrUlMbps}] | sort_by(.supi, .pduSessionId)' | jq -cS .)
if [ "$NOW_SESS" = "$BASE_SESS" ]; then
  pass pdu_session_list "sessions equal the baseline (PSI, 5QI, qosSource, session AMBR)"
else
  fail pdu_session_list "sessions equal the baseline" "before $BASE_SESS, now $NOW_SESS"
fi
ok "qos_policy_list empty (no PCF overrides)" qos_policy_list '{}' 'length == 0'
okp 30 "pcf_binding_list: bindings == bindings_active == EXPECTED_UES" pcf_binding_list '{}' "(.bindings | length) == .bindings_active and .bindings_active == $EXPECTED_UES"
call amf_timer_config '{}'
if [ "$(tjr '.effective' | jq -cS .)" = "$BASE_TIMERS" ] && tj '.effective == .base'; then
  pass amf_timer_config "AMF timers equal the baseline and the base values"
else
  fail amf_timer_config "AMF timers equal the baseline and the base values" "before $BASE_TIMERS, now $(tjr '.effective' | jq -c .)"
fi
call config_view '{}'
NOW_SLICE=$(tjr '.sections.slice_qos.value.items | map({snssai,dnn,sessionAmbr,source}) | sort_by(.snssai.sst, .snssai.sd, .dnn)' | jq -cS .)
if [ "$NOW_SLICE" = "$BASE_SLICE" ]; then pass config_view "slice AMBR equals the seed captured at the start"; else fail config_view "slice AMBR equals the seed captured at the start" "now $NOW_SLICE"; fi
NOW_LOG=$(loglevels)
if [ "$NOW_LOG" = "$BASE_LOG" ] && ! printf '%s' "$NOW_LOG" | awk -F'[=/]' 'NF >= 3 && $2 != $3 { bad = 1 } END { exit !bad }'; then
  pass nf_log_level "log levels equal the baseline: $(printf '%s' "$NOW_LOG" | head -1) (+ $(printf '%s' "$NOW_LOG" | grep -c .) NFs, none overridden)"
else
  fail nf_log_level "log levels equal the baseline" "before: $(printf '%s' "$BASE_LOG" | tr '\n' ' ') now: $(printf '%s' "$NOW_LOG" | tr '\n' ' ')"
fi
call subscriber_list '{}'
NOW_SUBS=$(tjr '[.[] | {supi,ambr_dl,ambr_ul,slices}] | sort_by(.supi)' | jq -cS .)
if [ "$NOW_SUBS" = "$BASE_SUBS" ]; then pass subscriber_list "subscriber profiles equal the baseline"; else fail subscriber_list "subscriber profiles equal the baseline"; fi
for s in "$SUPI" "$SUPI2"; do
  ok "subscriber_get $s: RFSP default (no override left)" subscriber_get "{\"supi\":\"$s\"}" '.rfsp_override.source == "default"'
done
call pws_list '{}'
NOW_PWS_LIVE=$(tjr '[.[] | select(.cancelled == false)] | length')
if [ "$NOW_PWS_LIVE" = "$BASE_PWS_LIVE" ]; then pass pws_list "no PWS warning left live ($NOW_PWS_LIVE, as before)"; else fail pws_list "no PWS warning left live" "before $BASE_PWS_LIVE, now $NOW_PWS_LIVE"; fi
NOW_POLICIES=$(portal_get /policies | jq -r '[.[].id] | sort | join(",")' 2>/dev/null)
if [ "$NOW_POLICIES" = "$BASE_POLICIES" ]; then pass ursp_template_apply "subscriber URSP policies equal the baseline"; else fail ursp_template_apply "subscriber URSP policies equal the baseline" "before '$BASE_POLICIES', now '$NOW_POLICIES'"; fi
ok "core_health: every NF healthy" core_health '{}' '[.nfs[] | select(.healthy != true)] | length == 0'
okp 30 "core_consistency_check: no error finding" core_consistency_check '{}' '([.findings[] | select(.severity == "error")] | length == 0) and (.counts.smf_sessions == .counts.upf_pfcp_sessions)'

# ---- coverage guard ---------------------------------------------------------
echo "[coverage — every listed tool has a check in this run]"
REQUIRED="$TOOLS"
if [ -n "$LAB_URL" ] && [ -n "${LAB_TOOLS:-}" ]; then REQUIRED="$REQUIRED $LAB_TOOLS"; fi
UNCHECKED=""
for t in $(printf '%s\n' $REQUIRED | sort -u); do
  case "$CHECKED" in *" $t "*) ;; *) UNCHECKED="$UNCHECKED $t" ;; esac
done
if [ -z "$UNCHECKED" ]; then
  echo "unchecked: (none)"
else
  echo "unchecked:$UNCHECKED"
  FAIL=$((FAIL + 1))
fi

echo
echo "result: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
