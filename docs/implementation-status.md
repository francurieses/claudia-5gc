# Implementation Status — 5GC Rel-17

Technical reference for implementation status, protocol quirks, and validation.
For code conventions and workflow, see root `CLAUDE.md`.

---

## Operational NFs

| NF | Status | Notes |
|---|---|---|
| NRF | ✅ | Register/Discover/Deregister + Heartbeat TTL eviction + OAuth2 HS256 JWT + mTLS; Redis backend (`REDIS_URL`) |
| AMF | ✅ | Registration + PDU Session Establishment/Release/Modification; NAS security NIA2+NEA2; NSSAI validation + NSSF delegation; PostgreSQL UE contexts + Redis TMSI; timers T3512/MobileReachable/ImplicitDetach/PendingRemoval |
| AUSF | 🟡 | 5G-AKA happy path; SUCI null-scheme via UDM; Redis auth context store (TTL 5 min, `ausf:auth:{id}`) |
| UDM | 🟡 | Auth + AM data + UECM; SUCI deconcealment implemented |
| UDR | ✅ | PostgreSQL 16 + fallback in-memory; pgx/v5; auto-migrate; `UE_COUNT` seeded subscribers |
| SMF | ✅ | PDU Session Establishment + Modification; IP allocation; N1SM/N2SM encoding e2e; 4 SNSSAIs on NRF; PostgreSQL sessions |
| PCF | ✅ | SM Policy Control (N7, config-driven QoS/AMBR); UE Policy Control N15 (TS 29.525) + URSP delivery (TS 24.526); per-subscriber UDR override; config-default fallback |
| UPF | ✅ | PFCP session table; GTP-U decap + ext. header skip; TUN `upfgtp0` + iptables MASQUERADE; e2e ping verified |
| NSSF | ✅ | Nnssf_NSSelection_Get; static NSSAI intersection; NRF registration; 8 unit tests |

## Web Management Portal

`http://localhost:8080` after `make portal`. See `tools/mgmt-portal/CLAUDE.md` for full stack.

| Page | Status |
|--------|--------|
| Dashboard | ✅ KPIs + grid of 9 NFs + active PDU sessions table |
| Subscribers | ✅ PostgreSQL CRUD |
| Network Slices | ✅ Add/remove S-NSSAIs + restart AMF/SMF/NSSF |
| Services | ✅ Start/Stop/Restart containers |
| Sessions | ✅ PDU sessions + AMF UE contexts |
| UERANSIM | ✅ Container grid + UEs table + ping + nr-cli + inline logs |
| Logs | ✅ WebSocket streaming Docker logs |
| PCAP | ✅ Start/Stop sidecars + file download |
| Policies | ✅ URSP rule CRUD + per-UE push (trigger UCU) |

---

## UERANSIM Integration

- UERANSIM v3.2.8 built from source (GitHub tarball) via `tools/ueransim/Dockerfile`.
- `make ueransim [UE_COUNT=N]` — brings up core + observability + gNB + N UEs.
- Config: `config/ueransim/gnb.yaml`, `config/ueransim/ue.yaml`.
- SUCI: `protectionScheme: 0` (null-scheme). MSIN `0000000001` in BCD low-nibble-first → bytes `[00 00 00 00 10]`.
- Multi-UE: `nr-ue -c ue.yaml -n N` increments IMSI from `imsi-001010000000001`. Changing `UE_COUNT` requires `make ueransim` (not `ueransim-only`) to reseed UDR.

### Multi-Slice (TS 23.501 §5.15)

Four development slices:

| Slice | SST | SD | Type | Assigned UE |
|---|---|---|---|---|
| internet | 1 | 000001 | eMBB default | UE1 — internet only |
| gold | 1 | 000002 | eMBB premium | UE2 — internet + gold |
| silver | 2 | 000001 | URLLC | UE3 — internet + silver |
| bronze | 3 | 000001 | MIoT | UE4 — internet + bronze |

Multi-slice gNB (`gnb-ms.yaml`): NCI `0x000000011`, GTP IP `172.30.3.4` (distinct from `gnb.yaml` to avoid conflicts).

```bash
make ueransim-slices       # bring up core + obs + 4 UEs
make test-slices           # suite T0–T9
make ueransim-slices-down
```

### Test Suite T0–T9 (`scripts/test-slices.sh`)

| Test | What It Validates |
|---|---|
| T0 | All 10 containers in `multi-slice` profile are running |
| T1 | NRF — SMF announces 4 SNSSAIs |
| T2 | NSSF — NSSelection returns correct slices; unknown slice → empty |
| T3 | UDR — each SUPI has correct NSSAI profile in `am-data` |
| T4 | 4 UEs reach `MM-REGISTERED` (timeout 45 s) |
| T5 | AMF — correct `AllowedNSSAI` per UE; no spurious `NSSAI_NOT_ALLOWED` |
| T6 | PDU sessions established; SMF has logs per IMSI |
| T7 | `uesimtun0` active + ping `172.30.3.100` from each UE |
| T8 | Rejection test: `ue-unauth.yaml` (IMSI-1 requests gold) → `NSSAI_NOT_ALLOWED` |
| T9 | Prometheus metrics accessible on all containers |

---

## E2E Validation (May 2026)

- ✅ Initial Registration: UE shows `MM-REGISTERED/NORMAL-SERVICE`
- ✅ N2SM Transfer: gNB decodes transfer, `PDU session resource(s) setup ... count[1]`
- ✅ N1SM PDU Session Establishment Accept: UE shows `PDU Session establishment is successful`
- ✅ PDU Session Establishment on first attempt (~250 ms, no T3580 retry)
- ✅ TUN `uesimtun0` active with IP assigned by SMF
- ✅ Data plane: `ping -I uesimtun0 172.30.3.100` → 0% packet loss, ~1.8ms RTT
- ✅ PDU Session Release: UE shows `Performing local release` without crash

## NRF Registration (Jun 2026)

All NFs now register with NRF successfully on startup.

**Root causes fixed:**
- AMF was missing `https://` prefix when constructing the NRF URL → `http2: unsupported scheme`. Fixed in `nf/amf/cmd/amf/main.go` by computing `nrfBase = "https://" + cfg.Peers.NRFAddress` once and using it for the token URL, discovery client, and NRF client.
- AUSF, NSSF, PCF, SMF, UDM used `sbi.NewHTTP2Client` (TLS-only, no client cert) when connecting to NRF. The NRF server requires mTLS (`tls.RequireAndVerifyClientCert`). Fixed by switching to `sbi.NewMTLSClient` when `cert_file`/`key_file` are configured — consistent with AMF which already had this guard.

**Invariant:** All NF SBI outbound clients must use `sbi.NewMTLSClient` (not `NewHTTP2Client`) when cert/key are available. The cert paths are `/etc/5gc/pki/<nf>.crt` and `/etc/5gc/pki/<nf>.key`, mounted from `pki/` by docker-compose.

## HTTP/2 / ALPN Conformance (Jun 2026) — TS 29.500 §4.4

All SBI connections verified as HTTP/2 over mTLS (`Go-http-client/2.0` in NRF access logs).

**Bugs fixed:**
- **NSSF ALPN** (`nf/nssf/internal/server/server.go`): `http2.ConfigureServer` was called before `TLSConfig` was assigned, so "h2" was added to a temp config that was immediately overwritten. Clients using `golang.org/x/net/http2.Transport` check `NegotiatedProtocol == "h2"` and would fail. Fixed by adding `NextProtos: []string{"h2"}` to `tlsCfg` and assigning `TLSConfig` before `ConfigureServer`. Ref: TS 29.500 §4.4.2.
- **NRF NFStatusNotify client** (`nf/nrf/internal/server/server.go`): Used `newH2CClient()` (cleartext H2C) for outbound POST callbacks to subscriber NFs. All NF SBI servers require mTLS → every notify would fail at TLS handshake. Fixed by using `sbi.NewMTLSClient` when cert/key are configured. Ref: TS 29.500 §4.4.1, TS 33.501 §13.

**Known implementation gap:** AMF has no inbound SBI server (`namf-comm`, port 8001). Outbound calls from AMF work; NFs cannot call back into AMF over SBI yet.

**Server-side rule for new NFs:** always set `TLSConfig` before calling `http2.ConfigureServer`, and include `NextProtos: []string{"h2"}` in the `tls.Config` struct. See NRF/AUSF/UDM/SMF/PCF `internal/server/server.go` as reference.

---

## NAS/NGAP Codec — Key invariants

These are non-obvious behaviors distilled from fixed bugs (May 2026).
Full root-cause history is in the dev branch commits.

### shared/nas/transport.go

- **IEI 0x12 (PDU Session ID)**: TV format (2 bytes total), **not TLV**. Ref: TS 24.501 Table 8.7.1.2-2.
- **Request Type (IEI 0x8-)**: nibble IEI; UERANSIM sends `0x81`. Detect with mask `iei & 0xF0 == 0x80`. Ref: TS 24.501 Table 8.7.1.2-2.
- **Payload Container**: LV-E length (2 bytes big-endian), not 1 byte. Ref: TS 24.501 §9.10.1.

### shared/nas/pdu_session.go

- **5GSM Header**: EPD | PSI | PTI | MT are 4 separate octets. Do not pack PSI and PTI into a single octet.
- **Mandatory IEs in PDU Session Establishment Accept**: *Authorized QoS rules* is LV-E (length 2 octets, no IEI); *Session-AMBR* is LV (1 octet, no IEI). Ref: TS 24.501 §8.3.2.
- **5GSM Cause in PDU Session Release Command**: send only the value byte (no IEI 0x59). UERANSIM v3.2.8 uses `mandatoryIE` which reads 1 byte without prefix. Ref: TS 24.501 §8.3.9.

### nf/smf/internal/server/

- **N2SM APER**: `PDUSessionResourceSetupRequestTransfer` is extensible SEQUENCE (`...`). Use `aper.MarshalWithParams(transfer, "valueExt")`. Without `valueExt` the bitstream shifts 1 bit. Ref: TS 38.413 §9.3.4.5 Annex B.

### nf/amf/internal/ngap/ngap.go

- **`ProcPDUSessionResourceRelease = 28`** (not 30; that is `PDUSessionResourceNotify`). Ref: TS 38.413 Table 9.1-1.
- **Serial dispatch**: NGAP messages processed serially per SCTP association. Without `go s.dispatch`. Necessary for `UplinkCount` ordering.

### nf/amf/internal/nas/nas.go

- **DL N1SM**: a 5GSM never travels alone — wrap in `DLNASTransport` (5GMM) + encrypt with `sendNASSecured` (SHT=0x02).
- **`ue.PendingRemoval = true`** before `SendUEContextReleaseCommandForUE`. Watchdog does not arm if done after.

### nf/upf/internal/gtpu/server.go

- **GTP-U extension headers**: UERANSIM sends PDU Session Container (type 0x85, TS 38.415). Initial `hdrLen` = 12; then walk the chain: while `pkt[hdrLen-1] != 0`, read `extLen = pkt[hdrLen] * 4`, advance `hdrLen += extLen`. For UERANSIM, inner IP is at offset 16. Ref: TS 29.281 §5.2.1.

### NAS Security — AMF

- **N1/N2SM Serialization**: base64 on both sides (not hex). Ref: TS 29.502.
- **KAMF**: SUPI without "imsi-" prefix (digits only). UERANSIM `Supi::Parse` does `substr(5)`. Ref: TS 33.501 §A.7.1.
- **NEA2 IV**: `COUNT(32b)|BEARER(5b)|DIR(1b)|0(90b)` — the 90 low bits are zero. Ref: TS 33.401 §B.1.2.
- **MAC**: encrypt first → MAC over `SQN||ciphertext`. Integrity-only → MAC over `SQN||plaintext`. Ref: TS 33.501 §D.3.3.

---

## SUCI Deconcealment (`shared/crypto/suci/`)

- `ParseSUCIString`: parses `suci-{mccmnc}-{ri}-0-{psi}-{hex}`.
- `DeconceaNull`: MSIN in BCD low-nibble-first (3GPP OTA format).
- `DeconceaProfileA/B`: ECIES X25519/secp256r1 implemented and tested.
- UDM automatically resolves SUCI→SUPI before querying UDR.

---

## Relevant external dependencies

- `github.com/free5gc/aper` + `github.com/free5gc/ngap`: NGAP codec. `NASPDU` is struct with `.Value` field. `aper.BitString` uses `.Bytes`. `UESecurityCapabilities` fields are lowercase: `NRencryptionAlgorithms`, etc.
- `golang.org/x/crypto/curve25519`: X25519 for SUCI Profile A.
- `github.com/wmnsk/go-pfcp`: PFCP marshaling (UPF).
