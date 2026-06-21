# CLAUDE.md — SMF (Session Management Function)

> Read the root `CLAUDE.md` for global conventions.

## 1. Function

PDU Session manager. Orchestrates creation/modification/deletion coordinating with PCF (policies) and UPF (user plane).

**Primary specifications:** TS 23.501 §6.2.4 · TS 23.502 §4.3.2 · TS 29.502 · TS 29.244 (PFCP) · TS 29.512 (Npcf_SMPolicyControl)

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| N4 | UPF | PFCP/UDP | TS 29.244 |
| N7 | PCF | Npcf_SMPolicyControl/HTTPS | TS 29.512 |
| N11 | AMF | Nsmf_PDUSession/HTTPS | TS 29.502 |
| N13 | UDM | Nudm_SDM/HTTPS | TS 29.503 |

## 3. Implemented Procedures

| Procedure | Spec | Status |
|---|---|---|
| PDU Session Establishment | TS 23.502 §4.3.2.1 | ✅ |
| PDU Session Modification (UE-requested) | TS 23.502 §4.3.3.1 | ✅ |
| PDU Session Release | TS 23.502 §4.3.4 | ✅ |
| SM Policy Association Create | TS 29.512 §5.2.2.2 | ✅ |
| SM Policy Association Delete | TS 29.512 §5.2.2.4 | ✅ |
| PDU Session Modification (NW-initiated, QoS) | TS 23.502 §4.3.3.2 | ✅ |
| SDM subscription fetch (N10, subscribed default QoS) | TS 29.503 §6.1.6.2.7 | ✅ |
| DL-data notification → AMF N1N2MessageTransfer (CN paging trigger) | TS 23.502 §4.2.3.3 | 🟡 |

## 3b. QoS / Management API (internal, not 3GPP)

5QI selection precedence at establishment: **PCF override > UDM sm-data (subsDefQos) > operator default** —
the chosen source is tracked per session (`qosSource`) and logged. PFCP Session Establishment carries a
Create QER (QFI=1, MBR = session AMBR in kbps, TS 29.244 §7.5.2.5); QoS modification pushes an Update QER
and waits for the UPF ack before N1/N2 signalling.

```
GET  /nsmf-management/v1/sessions                 # session list (supi, psi, dnn, snssai, 5qi, source, ambr, state)
GET  /nsmf-management/v1/sessions/{psi}[?supi=]   # one session + qosFlows + SMF-side QER view
POST /nsmf-management/v1/sessions/{psi}/qos       # {"5qi":7,"reason":"...","supi":...} → full §4.3.3.2 flow
POST /nsmf-management/v1/sessions/{psi}/dl-data-notification[?supi=]  # simulate UPF DDN → CN paging
```
The QoS endpoint delegates N1/N2 delivery to the AMF management API (`peers.amf_mgmt`, plain HTTP :9002);
the AMF calls back into `UpdateSMContext` (policyUpdate) which updates the session, pushes the QER to the
UPF and returns the 5GSM Modification Command (0xCB with IEs 0x2A/0x7A/0x79) + N2SM Modify Transfer.

**DL-data notification (CN paging trigger, `internal/server/paging.go`)** simulates the UPF Downlink
Data Report (PFCP Session Report) for a session and calls **Namf_Communication_N1N2MessageTransfer**
on the AMF over **mTLS SBI** (`peers.amf` = `amf:8001`, not the plain-HTTP mgmt API). The AMF pages the
UE if CM-IDLE (202 `ATTEMPTING_TO_REACH_UE`) or delivers directly if CM-CONNECTED (200
`N1_N2_TRANSFER_INITIATED`). The real N4 PFCP DDN is UPF-001 (PFCP session-management path = hard stop).
The SMF SBI client (`server.go`) uses `sbi.NewMTLSClient` when cert/key are configured so it can reach
the AMF's `RequireAndVerifyClientCert` server. Ref: TS 23.502 §4.2.3.3.

## 4. Architecture

```
cmd/smf/main.go        Bootstrap + config + wiring
internal/config/       Config YAML
internal/server/       HTTP/2 SBI server + handlers (n2sm_test.go, smf_modify_test.go)
internal/session/      Session context + IP pool
```

## 5. IP Pool

One thread-safe `IPPool` per DNN (TS 23.501 §5.6.5). `ipPools map[string]*IPPool` is keyed by DNN name.
`IPPool.Allocate()` / `IPPool.Release(ip net.IP)`.
Default pools: `internet → 10.60.0.0/24`, `ims → 10.61.0.0/24`.
The DNN-specific pool is selected at session establishment; fallback is the `internet` pool.
To add a new DNN: add entry in `nf/smf/config/dev.yaml` `dnns:` and `config/operator.yaml` `dnns:`.

## 6. N1SM and N2SM

**N2SM — critical**: `PDUSessionResourceSetupRequestTransfer` is extensible SEQUENCE (has `...` in NGAP ASN.1). Use **`aper.MarshalWithParams(transfer, "valueExt")`** — without this parameter the APER prefix bit is omitted and the entire bitstream shifts 1 bit → no decoder (UERANSIM, Wireshark) can parse it. Ref: TS 38.413 §9.3.4.5 Annex B.

**N1SM**: response to AMF includes `dnn` and `allocated_ip` (UERANSIM requires both). Encode in base64 for SBI transport (TS 29.502).

**PDU Session Modification** (`handleUpdateSMContext`): `bytes[3] == 0xC9` → respond with 0xCB (`WrapPDUSessionModificationCommandBody`) + empty N2SM Modify Transfer (`buildPDUSessionResourceModifyRequestTransfer()` = 3 bytes APER).

```bash
go test ./nf/smf/... -v
go test ./nf/smf/internal/server/... -v -run "TestN2SMModifyTransferRoundTrip|TestHandleUpdateSMContext"
```

## 7. PostgreSQL Persistence

Table: `smf_sessions (sm_context_ref PK, supi, dnn, ue_ip, ul_teid, seid, sst, sd, created_at TIMESTAMPTZ DEFAULT NOW())`.

`loadFromStore` on startup reconstructs `sessions`, `IPPool.allocated`, `nextSEID`, `nextTEID` from the database.

`DATABASE_URL=postgres://5gc:5gc-dev@postgres:5432/5gc?sslmode=disable` — nil-safe (in-memory if not configured).

## 8. External Dependencies

- `github.com/free5gc/ngap` — NGAP types to build N2SM
- `github.com/wmnsk/go-pfcp` — PFCP marshaling (used by UPF; SMF not yet directly)

## 9. Commands

```bash
make -C nf/smf build
make -C nf/smf test
make -C nf/smf docker
```

## 10. Debugging

```bash
docker logs -f smf | jq '.procedure, .pdu_session_id, .result'
./scripts/pcap-control.sh list smf
```
