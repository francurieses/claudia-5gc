<!-- tier: public -->
# Features

What ClaudIA 5GC does, how to try each feature, and its known limits. Commands assume the
stack is running (`make up-obs`, or `make ueransim` for core + gNB + UE) — see
[`getting-started.md`](getting-started.md). Per-NF completeness is in
[`implementation-status.md`](implementation-status.md); settings are in
[`configuration.md`](configuration.md).

Each feature lists: what it does · the 3GPP reference · how to try it · limits.

## Registration & security

### UE registration and authentication
- **What**: Initial Registration with SUCI→SUPI resolution, 5G-AKA mutual authentication, NAS security mode and a Registration Accept carrying a GUTI and periodic-update timer.
- **Spec**: TS 23.502 §4.2.2.2.2, TS 33.501 §6.1.3.2.
- **Try**: `make ueransim`, then `docker exec ueransim-ue nr-cli imsi-001010000000001 --dump` → `MM-REGISTERED/NORMAL-SERVICE`.
- **Limits**: authentication re-synchronisation edge cases are partial.

### EAP-AKA′ primary authentication
- **What**: EAP-AKA′ as an alternative to 5G-AKA, run between AMF, AUSF and UDM.
- **Spec**: TS 33.501 §6.1.3.1, RFC 5448.

### SUCI concealment (Profile A)
- **What**: SUPI deconcealment with X25519 ECIES; the null scheme is the default.
- **Spec**: TS 33.501 §6.12, Annex C.3.
- **Try**: `make ueransim-profile-a` (clean up with `make ueransim-profile-a-down`).
- **Limits**: development key pair only.

### Slice-specific authentication (NSSAA)
- **What**: EAP-based authentication per network slice, relayed through the AUSF to a simulated AAA server (control plane).
- **Spec**: TS 23.502 §4.2.9.

### Deregistration
- **What**: UE- and network-initiated deregistration, including PDU-session teardown, UDM context cleanup and NGAP release. Network-initiated deregistration asks the UE to re-register automatically ("re-registration required").
- **Spec**: TS 23.502 §4.2.2.3.
- **Try**: `curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/$SUPI`, or Portal → Sessions → force deregister.
- **Limits**: automatic UE re-registration needs the patched UERANSIM image built by this repo.

### UE context transfer (inter-AMF)
- **What**: the old-AMF side of UE context transfer over `Namf_Communication`.
- **Spec**: TS 29.518 §5.3.2.
- **Limits**: no registration-request integrity replay and no registration-status-update consumer.

## Sessions & QoS

### PDU session establishment and release
- **What**: UE-requested session set-up (IP allocation, N4 session install, N2 resource set-up, N1 Accept) and release, plus network-initiated release.
- **Spec**: TS 23.502 §4.3.2, §4.3.4.
- **Try**:
  ```bash
  docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
  docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-release 1"
  ```
  then `ping -I uesimtun0 172.30.3.100` from the UE container.

### PDU session modification (QoS)
- **What**: UE-requested and network-initiated 5QI / AMBR changes across SMF, PCF, UPF and AMF.
- **Spec**: TS 23.502 §4.3.3.2, TS 23.501 §5.7, TS 29.512 §5.2.2.3.
- **Try**: `curl -sk -X POST https://localhost:8004/nsmf-management/v1/sessions/1/qos -H 'Content-Type: application/json' -d '{"5qi":7,"reason":"upgrade"}'`
- **Note**: 5QI precedence is PCF override > subscription (UDM) > operator default.

### QoS policy enforcement
- **What**: PCF authorises 5QI and Session-AMBR; the SMF installs them in the UPF as QERs.
- **Spec**: TS 23.501 §5.7, TS 29.512, TS 29.244 §7.5.2.5.
- **Try**: `curl -sk https://localhost:8004/nsmf-management/v1/sessions | jq`

### Session-AMBR enforcement
- **What**: the UPF polices uplink and downlink to the Session-AMBR (token-bucket, drop-based) using several QERs per session.
- **Spec**: TS 23.501 §5.7.1.8, TS 29.244 §5.4.4.
- **Try**: `iperf3` UDP above the AMBR is delivered at roughly the AMBR; `fivegc_upf_packet_drops_total{reason="qer_mbr_exceeded"}` rises. Tune with `qos.mbr_enforcement` / `qos.burst_ms` in the UPF config.
- **Limits**: drop-based policing (TCP reaches roughly 50–80 % of the AMBR); GBR is not guaranteed.

### Per slice/DNN Session-AMBR
- **What**: the subscribed Session-AMBR is stored per (S-NSSAI, DNN) in the UDR and edited from the portal (Slices → *Session-AMBR* tab, with revert and "apply to active sessions").
- **Spec**: TS 23.501 §5.7.2.6, TS 29.503 §6.1.6.2.9.
- **Limits**: the SMF applies whole Mbps; changes take effect on the next session (or via "apply").

### Network slicing
- **What**: Allowed-NSSAI computation via the NSSF with per-UE subscription checks. Four development slices: internet (1/000001), gold (1/000002), silver (2/000001), bronze (3/000001). A PDU session on an unauthorised slice is rejected (5GMM cause #90), never moved silently.
- **Spec**: TS 23.501 §5.15, TS 29.531.
- **Try**: `make ueransim-slices`, then `make test-slices` (suite T0–T9).
- **Limits**: a new slice also needs adding to the UE's configured NSSAI and to the operator config — see [`configuration.md`](configuration.md).

### DNN subnet isolation and IPv6
- **What**: per-DNN UE IP pools, dedicated N6 networks and one TUN per DNN. IPv6 and IPv4v6 sessions get a delegated `/64`, router advertisements from the UPF and IPv6 egress to N6.
- **Spec**: TS 23.501 §5.6.5, §5.8.2.2.
- **Try**: add a DNN in Portal → Network Slices; IPv6 sessions via `nr-cli … ps-establish IPv6 <dnn>` on the patched UERANSIM image.

### Secondary authentication (DN-AAA)
- **What**: for DNNs flagged `secondary_auth`, the SMF acts as EAP authenticator during establishment against a simulated in-core DN-AAA; failure rejects the session with 5GSM cause #29.
- **Spec**: TS 23.501 §5.6.6, TS 23.502 §4.3.2.3.
- **Limits**: DN-AAA is simulated; stock UERANSIM does not answer the EAP exchange.

## Policy

### URSP policy delivery
- **What**: UE Route Selection Policy delivered through UE policy delivery (DL NAS Transport, MANAGE UE POLICY COMMAND). Push on demand, per subscriber.
- **Spec**: TS 24.526, TS 29.525, TS 24.501 Annex D.
- **Try**: `make validate-ursp`, or `curl -X POST http://localhost:9002/amf/v1/ue-contexts/$SUPI/push-policies`; or Portal → Policies.
- **Limits**: stock UERANSIM has no URSP support; use the patched image (`make ueransim`).

### Network-triggered additional PDU session
- **What**: the network steers a UE to open an additional session by delivering a URSP rule plus a DNN-scoped QoS override.
- **Spec**: TS 23.503 §6.6.2, TS 23.502 §4.3.2.2.1.
- **Try**: Portal → QoS → *NW-Triggered PDU Session*, or `POST /api/v1/qos/nw-sessions` on the portal.

### UE configuration update
- **What**: UE Configuration Update command and policy delivery, triggered per UE from Portal → Policies.
- **Spec**: TS 24.501 §8.2.19.

### AM policy association and service-area restriction
- **What**: access-and-mobility policy association with the PCF and service-area restrictions applied at registration.
- **Spec**: TS 29.507, TS 23.501 §5.3.4.

## Mobility

### Xn handover
- **What**: gNB-to-gNB handover with Path Switch through the AMF and SMF, including NH/NCC key chaining and the user-plane downlink switch at the UPF.
- **Spec**: TS 23.502 §4.9.1.2, TS 38.413 §8.4, TS 33.501 §6.9.2.
- **Try**: `make handover-test` (PacketRusher) or Portal → PacketRusher; clean up with `make handover-down`.

### N2 handover
- **What**: source/target gNB handover through the AMF (preparation, command, notify) with SMF involvement and user-plane switch.
- **Spec**: TS 23.502 §4.9.1.3.
- **Try**: `make handover-n2-test` or Portal → PacketRusher → N2.
- **Limits**: indirect data forwarding and End Marker are not implemented.

### Paging and network-triggered service request
- **What**: a downlink-data trigger makes the AMF page a CM-IDLE UE; the UE answers with a Service Request and the user plane is restored.
- **Spec**: TS 23.502 §4.2.3.3, TS 38.413 §9.2.8.
- **Limits**: the UPF buffers downlink per session in a bounded FIFO (configurable); the Service Accept does not yet carry the re-activation result.

### UE-triggered service request
- **What**: a CM-IDLE UE with pending uplink data re-activates its PDU sessions; Service Accept carries the PDU-session status and re-activation result.
- **Spec**: TS 23.502 §4.2.3.2, TS 24.501 §5.6.1.
- **Limits**: requires the patched UERANSIM gNB.

## Messaging & warnings

### SMS over NAS (SMSF)
- **What**: MO/MT SMS carried in NAS, anchored by the SMSF, with a loopback echo destination.
- **Spec**: TS 23.502 §4.13, TS 29.540.
- **Limits**: UERANSIM has no SMS-over-NAS support, so there is no live UE leg.

### Public Warning System
- **What**: ETWS/CMAS-style broadcast (NGAP Write-Replace Warning, PWS Cancel) to every connected gNB, with the portal acting as the cell-broadcast centre. Alphabet and language selection follow TS 23.038.
- **Spec**: TS 23.041, TS 38.413 §8.9.
- **Try**: Portal → Public Warning, or `curl -X POST http://localhost:9002/amf/v1/pws/broadcast -H 'Content-Type: application/json' -d '{"messageIdentifier":4370,"serialNumber":1,"messageText":"Test alert"}'`.

## Exposure & location

### Binding Support Function (BSF)
- **What**: registry of which PCF serves which PDU session; the PCF registers and deregisters bindings automatically, consumers discover the serving PCF by UE IP.
- **Spec**: TS 29.521 §5. Port 8010.

### Network Exposure Function (NEF)
- **What**: northbound API for an Application Function to request QoS for a UE flow (`AsSessionWithQoS`), OAuth2-protected, mapped onto PCF policy authorization via BSF discovery.
- **Spec**: TS 29.522 §4.4.13, TS 29.514. Port 8011.
- **Limits**: no live AF in the lab; exercised with mocks.

### UE location (LMF)
- **What**: `Nlmf_Location` positioning with automatic method selection and fallback: Cell-ID, E-CID over NRPPa, and A-GNSS over LPP. Supports periodic and area-of-interest event subscriptions and cancel. Under the `rel19` release profile, `DetermineLocation` can also activate periodic or area-triggered deferred location reported to an HTTPS callback. Positions appear on Portal → UE Location.
- **Spec**: TS 29.572, TS 23.273, TS 38.455, TS 37.355. Port 8012.
- **Try**: `make ueransim`, then `curl -sk --cert pki/smf.crt --key pki/smf.key --cacert pki/ca.crt -X POST https://localhost:8012/nlmf-loc/v1/determine-location -H 'Content-Type: application/json' -d '{"supi":"'$SUPI'","req5gsLoc":true,"reqCurrentLoc":true}'`; patched-UERANSIM checks: `bash scripts/validate-ueransim-mod.sh location|gnss`.
- **Limits**: Cell-ID coordinates are synthesised around the configured cell position; GMLC interface not implemented.

## User plane & operations

### Usage reporting (URR)
- **What**: the SMF installs usage reporting rules; the UPF counts per-session volume and duration and sends PFCP Session Report Requests on volume-threshold and periodic triggers — the hook point for charging.
- **Spec**: TS 29.244 §5.2.2.4, §7.5.5.

### PFCP node-level recovery
- **What**: the SMF supervises the UPF with Association Setup and heartbeats; after a UPF restart it releases stale sessions so UEs re-establish.
- **Spec**: TS 29.244 §6.2, TS 23.007 §19A.
- **Try**: `make ueransim UE_COUNT=1`, then `SERVICES=upf make services-restart-check`.
- **Limits**: sessions are released, not restored.

### Downlink checksum repair
- **What**: the UPF fixes wrong TCP/UDP checksums on the downlink path (seen on Docker Desktop for Mac). On by default via `n6.l4_checksum_repair`.
- **Spec**: TS 29.281 §5; RFC 1071.

### Throughput benchmarking
- **What**: bench tooling and a tuned zero-allocation GTP-U datapath. Headline figures are in [`performance/summary.md`](performance/summary.md).
- **Try**: `make perf-up`, then `make perf-dn` / `make perf-multi-ue` / `make perf-bench`.

### SBI feature negotiation
- **What**: AMF, SMF, AUSF, UDM, NEF, BSF, SMSF, LMF, NSSF, PCF, NRF and UDR negotiate the SBI `supportedFeatures` bitmask per API (intersection of both sides). On by default (`rel19` is the default release profile); `release.profile: rel17` (or `NF_RELEASE_PROFILE=rel17`) restores the frozen legacy behaviour, which keeps the previous messages byte for byte. The BSF, SMSF, LMF, NSSF and PCF producers answer the intersection too (the PCF on SM policy, AM policy, UE policy and application-session creation); none of them implements an optional feature yet, so under `rel19` they offer `"0"`. The NRF implements the Service-Map feature and reports its own feature set (`"1"` for NF management, `"20"` for discovery) in `nrfSupportedFeatures`; the UDR offers `"0"`.
- **Spec**: TS 29.500 §6.6.2, TS 29.571 §5.2.2, TS 29.502 / TS 29.518 §6.1.8.
- **Try**: set `NF_RELEASE_PROFILE=rel19` on `amf`, `smf`, `ausf`, `udm` (and `nef`), or set `release: {profile: rel19}` in the `bsf`/`smsf`/`lmf`/`nssf`/`pcf`/`nrf`/`udr` YAML, restart, register a UE and open a PDU session, then `docker logs ausf | grep FeatureNegotiation`.
- **HTTP redirection**: the AMF and SMF SBI clients follow HTTP 307/308 redirects (same method, body and headers, at most 5, never from https to http) and advertise the ES3XX feature bit under `rel19`; 301/302/303 are not followed.
- **Limits**: only the ES3XX bit is implemented, so the negotiated AMF-SMF set is empty (`0`); AMF, SMF, AUSF, UDM and NEF take part so far; the AUSF, UDM and NEF implement no optional feature (they answer `0`). The NEF also takes part as a client of the PCF (application sessions) and the BSF (discovery), offering the ES3XX bit under `rel19`; its outbound SBI client follows HTTP 307/308 redirects.

### Mixed-release deployments
- **What**: Rel-19 and Rel-17 NFs run in the same core. Each NF takes its release profile from `release.profile` or `NF_RELEASE_PROFILE`; the AMF also infers each gNB's release at NG Setup (default Rel-17) and can cap it per gNB with `ngap.ran_profiles`. Legacy peers receive byte-identical messages.
- **Spec**: TS 29.500 §6.6.2, TS 38.413.
- **Try**: `make ueransim UE_COUNT=1 && make mixed-release-e2e` (Rel-19 AMF against Rel-17 SMF/PCF and the reverse, ~150 s).
- **Limits**: only the profiles `rel17` and `rel19` exist; Rel-18/19 features stay opt-in.

### NGAP error handling
- **What**: the AMF handles transfer-syntax and abstract-syntax errors and unknown IEs per their criticality (reject / ignore / notify), answering with NGAP Error Indication where the spec requires it.
- **Spec**: TS 38.413 §8.7.5, §10.
- **Try**: send a malformed or unknown-IE NGAP message from a test gNB, then `docker logs amf | grep ErrorIndication`.
- **Limits**: AMF side only.

### Roaming (SEPP)
- **What**: a SEPP and hSEPP pair with N32-c capability handshake and N32-f forwarding between two PLMNs, registered in each PLMN's NRF.
- **Spec**: TS 29.573, TS 23.501 §4.2.4.
- **Try**: `docker compose --profile core --profile roaming up -d sepp hsepp hnrf` (test peer), then `make sepp-e2e` (`PROFILE=rel17|rel19`).
- **Limits**: N32-f runs in TLS protection mode and carries NF discovery in the E2E; see [`implementation-status.md`](implementation-status.md).
- **Roaming partners**: the default core ships with no partner; add one through the roaming partners file (`ROAMING_PARTNERS_FILE`) or the portal Roaming page, with per-PLMN N32 trust anchors separate from the SBI CA. Checklist: [`n32-interop-profile.md`](n32-interop-profile.md). PRINS-only partners cannot interwork.
- **Roaming registration**: a UE of a foreign home PLMN (AMF `roaming:` block) is authenticated by the home AUSF/UDM through the SEPP; `make roaming-e2e` (live-validated against the test home PLMN 001/02). Home-routed PDU sessions (V-SMF/H-SMF over N16, V-UPF/H-UPF over N9) are live-validated against the same test home network. Guide: [`roaming.md`](roaming.md); config keys: [`configuration.md`](configuration.md).

## Tooling

### Management portal
- **What**: operator UI at `http://localhost:8080` (`make 5gcsa`) — see the page list in [`implementation-status.md`](implementation-status.md).

### MCP server
- **What**: AI-tooling server (stdio and SSE on port 9300) exposing NAS codec, discovery, UE inspection, QoS, crypto, metrics and UERANSIM control tools — see [`mcp-tools.md`](mcp-tools.md).

### Observability
- **What**: Prometheus metrics (`fivegc_*`), Jaeger traces per procedure, Grafana dashboards and Loki logs, plus per-NF packet capture — see [`observability.md`](observability.md).

## More detail

Sequence diagrams, information elements, error cases, clause-level conformance and validation
recipes for each procedure are part of the **members documentation**
(<https://www.claudia5gc.dev/docs/members/>).

## v3.1.1 release notes

Documentation patch release; no behaviour change. Public documentation no longer carries
internal task identifiers, and the public documentation checks now reject them.

## v3.1.0 release notes

Changes since v3.0.0. Rel-19 stays the default release profile; Rel-15/16/17 peers keep
getting byte-identical messages under the `rel17` profile.

### New features

- **NAS security algorithms**: 128-NEA1 (SNOW 3G) and 128-NEA3 (ZUC) ciphering, and 128-NIA1
  and 128-NIA3 integrity, verified against the TS 35.217 / 35.223 test vectors. The AMF picks
  algorithms from an operator-ordered list and never falls back silently to a null algorithm;
  `null_ciphering` now selects NEA0 only when the UE advertises EA0 [TS 33.501 §6.7.1.1, §6.7.2,
  Annex D].
- **Downlink data buffering for idle UEs**: the UPF buffers downlink packets (bounded queue),
  reports them to the SMF with a PFCP Downlink Data Report, the AMF pages the UE, and the first
  buffered packet is delivered after the Service Request [TS 23.502 §4.2.3.3; TS 29.244
  §5.2.3.1].
- **SMF restart recovery**: after an SMF restart, PDU sessions it lost are released towards
  the UE with 5GSM cause #39, so the UE re-establishes them without a manual step; idle UEs are
  paged first [TS 23.527 §4.4.2].
- **NG Reset**: a gNB-initiated NG RESET (whole interface or a UE list) is answered with
  NG RESET ACKNOWLEDGE and the affected UE contexts are released [TS 38.413 §8.7.4].
- **UDM-triggered network deregistration**: deregistration notifications from the UDM are
  acted on per reason (Deregistration Request + N2 release for connected UEs, implicit
  deregistration for idle UEs) [TS 23.502 §4.2.2.3].
- **Registration NSSAI handling**: default S-NSSAI fallback, `singleNssais` from the
  subscription, NSSAA-capability gating and mapped S-NSSAIs in the Extended rejected NSSAI
  [TS 23.501 §5.15.5.2.1; TS 24.501 §5.5.1.2.4].
- **Service Accept error causes**: when some PDU sessions cannot be re-activated, Service
  Accept carries the PDU session reactivation result error cause IE with one 5GMM cause per
  failed session [TS 24.501 §8.2.17.1.1, §9.11.3.43].
- **Per-slice DNNs**: each slice in `config/operator.yaml` can name its DNN; the seeded
  subscriber data follows it, so slice sessions get their subscribed 5QI and Session-AMBR
  instead of the operator default.
- **Subscribed UE-AMBR**: the UDM serves the UE-AMBR provisioned in the UDR instead of a fixed
  100 Mbps [TS 29.503 §5.2.2.2.3].
- **NRF feature negotiation (Rel-19 profile)**: discovery, profile retrieval and status
  notifications return `nfServices` or `nfServiceList` according to the negotiated
  Service-Map feature; Inter-Plmn-Fqdn is supported; subscribe returns SubscriptionData;
  400 errors use `application/problem+json` [TS 29.510 §6.1.6.2.2].
- **UERANSIM gNB reconnects to the AMF**: after the AMF link drops, the gNB bars the cell,
  reconnects with backoff, redoes NG Setup and unbars the cell, without restarting the
  container; a connected UE then performs a mobility registration update [TS 38.413 §8.7.1].
- **UERANSIM UE-AMBR enforcement**: the gNB enforces the subscribed UE-AMBR and Session-AMBR
  changes from PDU Session Resource Setup / Modify [TS 38.413 §8.2.1.2, §9.3.4.3].

### Improvements and fixes

- **SM policy decisions follow TS 29.512**: `qosId`, full ARP enums, `sessRuleId`,
  `authSessAmbr`, `refQosData` and `flowDescription`; invalid ARP settings stop the PCF at
  startup.
- **QoS modification**: the network-requested PDU Session Resource Modify now carries the
  Session-AMBR and the QoS flow list [TS 38.413 §8.2.3].
- **AN release** keeps downlink data buffered (BUFF+NOCP) instead of dropping it [TS 23.502
  §4.2.6].
- **Empty Allowed NSSAI**: the AMF never sends Initial Context Setup with an empty Allowed
  NSSAI and does not activate user plane in that case [TS 24.501 §5.6.1.4.1].
- **Registration**: 5G-S-TMSI resolution by AMF Set ID and Pointer, stored radio capability
  cleared on request, stricter Service Accept decoding.
- **Rolling upgrade**: AUSF and UDM also accept the legacy v2.6 SUCI string on input, so a
  Rel-17 AMF can stay in service during an upgrade.
- **Startup robustness**: AMF, SMF, AUSF and NRF wait (with backoff) for PostgreSQL and Redis
  and exit if they never come up, instead of silently running in memory; PostgreSQL and Redis
  restart with the Docker daemon like the NFs.
- **NEF accepts NRF-issued OAuth2 tokens**: one signing-secret source (`OAUTH2_SECRET` env,
  then YAML) for both NFs.
- **AMF defaults**: the AMF configuration decides whether URSP is delivered (off by default)
  and the operator network name defaults to `ClaudIA`.
- **Codec robustness**: round-trip fuzzing of the NAS, NRPPa, LPP and PFCP codecs
  (`make fuzz-smoke`); truncated mandatory IEs are now rejected.
- **Security hardening**: constant-time NIA1 multiply.

### Upgrade notes

- **Breaking (Npcf_SMPolicyControl)**: the PCF now sends the session AMBR as `authSessAmbr`,
  as in the TS 29.512 schema, instead of `sessAmbr`. The bundled SMF reads both; an external
  SMF reading `sessAmbr` must be updated.
- `URSP_ENABLED` is no longer forced on by docker-compose; set it (or the AMF config) if you
  rely on URSP delivery.

### Known limits

- After an AMF restart, the UERANSIM UE registers again but does not re-establish its PDU
  session; restart the UE container to restore the data plane.
- After a long UPF outage while UEs are idle, sessions can stay stale until the UE
  re-establishes them.
- The Service Accept error-cause IE is covered by functional tests; it has not yet been
  observed in a live capture.
