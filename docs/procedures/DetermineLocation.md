# Procedure: DetermineLocation (Nlmf_Location — UE Cell-ID Positioning)

**Spec:** TS 23.273 §6 (architecture) · §7.2 (UE positioning) · TS 29.572 §5.2.2.2 (Nlmf_Location DetermineLocation) · TS 29.518 §5.2.2.6 (Namf_Location producer) · TS 38.413 §8.17.1 (NGAP LocationReportingControl / LocationReport) · TS 23.501 §6.2.18 (LMF) · TS 29.510 §6.1.6.3.3 (NRF NFType=LMF)
**Status:** 🟡 In progress (MVP — Cell-ID only)
**Primary NF:** LMF (Nlmf_Location producer)
**Other NFs involved:** AMF (Namf_Location producer + NGAP relay to RAN), gNB, UE, LCS Client (5GC-internal consumer of Nlmf)

## Context

The **Location Management Function (LMF)** is the 5GC NF responsible for UE positioning
(TS 23.501 §6.2.18). It lives entirely in the core network and reaches the RAN **only
through the AMF acting as an NGAP relay** — the LMF never has a direct N2 (NGAP/SCTP)
association to the gNB.

This procedure implements the **MVP** of TS 23.273 §7.2: **Cell-ID positioning only**.
The serving cell of the UE (its NRCGI + TAI, reported by the gNB) is returned as the
location estimate. There is no LPP/NRPPa measurement exchange, no GMLC, no UDM
location-privacy check (all deferred — see *Out of scope*).

Two NFs participate:

- **LMF** (`nf/lmf/`, SBI port 8012, Prometheus 9113): hosts the `Nlmf_Location`
  `DetermineLocation` endpoint. On request it calls the AMF's `Namf_Location` producer to
  obtain the UE's current serving cell, maps NRCGI→coordinates, and returns `LocationData`.
- **AMF** (`nf/amf/`, existing SBI port 8001): hosts a new `Namf_Location` producer
  endpoint. On receipt it builds and sends an **NGAP LocationReportingControl** (ProcCode=16)
  to the UE's serving gNB, then blocks until the matching **NGAP LocationReport**
  (ProcCode=18) arrives, decodes `UserLocationInformationNR` → NRCGI + TAI, and returns it.

### Endpoints

| Service | Producer | Endpoint |
|---|---|---|
| `Nlmf_Location` | LMF (:8012) | `POST /nlmf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info` |
| `Namf_Location` | AMF (:8001) | `POST /namf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info` |

`{ueContextId}` is the UE identifier (`imsi-<digits>` SUPI, or a 5G-GUTI form) the consumer
supplies. The AMF resolves it to an active UE context to obtain the `AMF-UE-NGAP-ID` /
`RAN-UE-NGAP-ID` pair and the serving gNB association.

## Specifications

| Topic | Reference |
|---|---|
| LMF functional description | TS 23.501 §6.2.18 |
| Location services architecture | TS 23.273 §6 |
| UE positioning procedure | TS 23.273 §7.2 |
| Nlmf_Location DetermineLocation (stage 3) | TS 29.572 §5.2.2.2 |
| LocationData / RequestLocInfo data model | TS 29.572 §6.1.6.2.2 |
| Namf_Location ProvideLocationInfo (AMF producer) | TS 29.518 §5.2.2.6 |
| NGAP LocationReportingControl / LocationReport | TS 38.413 §8.17.1 |
| NRF registration NFType=LMF | TS 29.510 §6.1.6.3.3 |

## NF interaction overview

```
LCS Client ──Nlmf_Location──▶ LMF ──Namf_Location──▶ AMF ══NGAP (N2 relay)══▶ gNB
                              │                       ▲                         │
                              │◀──── LocationData ────┘◀── NGAP LocationReport ─┘
```

- **Nlmf_Location** (SBI, mTLS+HTTP/2): LCS Client / requesting NF → LMF.
- **Namf_Location** (SBI, mTLS+HTTP/2): LMF → AMF (LMF is the consumer here).
- **NGAP N2** (SCTP): AMF ↔ gNB. The AMF is the only NF with an N2 association; it relays
  the positioning control and report on behalf of the LMF.

## Sequence Diagram

Each message is annotated with its governing TS section. `[M]` = mandatory step in the
Cell-ID flow; `[C]` = conditional.

```mermaid
sequenceDiagram
    participant LCS as LCS Client / Consumer
    participant LMF
    participant AMF
    participant gNB
    participant UE

    Note over LCS,LMF: TS 29.572 §5.2.2.2 — Nlmf_Location DetermineLocation
    LCS->>LMF: [M] POST /nlmf-loc/v1/ue-contexts/{id}/provide-loc-info<br/>RequestLocInfo {supi/gpsi, locationQoS, priority}
    Note over LMF: TS 23.273 §7.2 — select positioning method = Cell-ID (MVP)

    Note over LMF,AMF: TS 29.518 §5.2.2.6 — Namf_Location ProvideLocationInfo
    LMF->>AMF: [M] POST /namf-loc/v1/ue-contexts/{id}/provide-loc-info<br/>RequestLocInfo {req5gsLoc, supportedGADShapes}
    Note over AMF: Resolve {id} → UEContext.<br/>Check CM-CONNECTED (N2 association exists).<br/>Insert pending entry keyed by AMF-UE-NGAP-ID.

    Note over AMF,gNB: TS 38.413 §8.17.1 — NGAP relay (AMF on behalf of LMF)
    AMF->>gNB: [M] NGAP LocationReportingControl (ProcCode=16)<br/>AMF-UE-NGAP-ID(10), RAN-UE-NGAP-ID(85),<br/>LocationReportingRequestType(33): EventType=Direct, ReportArea=Cell
    gNB->>AMF: [M] NGAP LocationReport (ProcCode=18)<br/>AMF-UE-NGAP-ID(10), RAN-UE-NGAP-ID(85),<br/>UserLocationInformation(121) → UserLocationInformationNR(NRCGI + TAI)
    Note over AMF: Decode ULI-NR → NRCGI + TAI.<br/>Resolve pending channel by AMF-UE-NGAP-ID.

    AMF-->>LMF: [M] 200 OK Namf LocationData {nrCellId, tai}
    Note over LMF: TS 29.572 §6.1.6.2.2 — build LocationData.<br/>Map NRCGI → coordinate (config map) or placeholder.
    LMF-->>LCS: [M] 200 OK LocationData {locationEstimate(POINT), nrCellId, ageOfLocationEstimate}
```

## Information Elements

### Nlmf_Location request — `RequestLocInfo` (LCS Client → LMF, TS 29.572 §6.1.6.2.x)

| IE | Type | M/O | Notes |
|---|---|---|---|
| `supi` | string | C | UE permanent identity; one of `supi`/`gpsi` identifies the UE |
| `gpsi` | string | C | Generic public subscription identifier (alternative to `supi`) |
| `locationQoS` | object | O | Requested accuracy / response-time class (`hAccuracy`, `vAccuracy`, `responseTime`) |
| `priority` | enum | O | `LCS_Priority`: `HIGHEST_PRIORITY` / `NORMAL_PRIORITY` |
| `supportedGADShapes` | array | O | GAD shapes the client can decode; MVP returns `POINT` |

> Carried in the path as `{ueContextId}`; body conveys the QoS/priority. MVP uses `supi`.

### Namf_Location request — `RequestLocInfo` (LMF → AMF, TS 29.518 §6.1.6.2.x)

| IE | Type | M/O | Notes |
|---|---|---|---|
| `req5gsLoc` | boolean | M | Request 5GS location (TAI + NRCGI of the serving cell) |
| `reqCurrentLoc` | boolean | O | Request the current (not last-known) location → triggers fresh NGAP report |
| `supportedGADShapes` | array | O | GAD shapes the consumer accepts |

### Namf_Location response — `LocationData` (AMF → LMF) / Nlmf response (LMF → LCS), TS 29.572 §6.1.6.2.2

| IE | Type | M/O | Notes |
|---|---|---|---|
| `locationEstimate` | object | M | `GeographicArea`: `{shape:"POINT", point:{lat, lon}}` for MVP |
| `nrCellId` | string | C | Serving cell, NRCGI rendered as hex (36-bit cell id) |
| `tai` | object | C | Tracking Area Identity `{plmnId:{mcc,mnc}, tac}` |
| `ageOfLocationEstimate` | integer | O | Minutes since the estimate; `0` for a fresh report |
| `positioningDataList` | array | O | Methods used; MVP reports `cellID` |

Example MVP body:

```json
{
  "locationEstimate": { "shape": "POINT", "point": { "lat": 0, "lon": 0 } },
  "nrCellId": "000000010",
  "ageOfLocationEstimate": 0
}
```

> For Cell-ID, `lat`/`lon` are derived from a config map `plmn→cell→coord`; when no entry
> exists, `lat=0, lon=0` is an acceptable placeholder (the authoritative output is `nrCellId`).

### NGAP LocationReportingControl — ProcedureCode 16 (AMF → gNB, TS 38.413 §8.17.1, §9.2.x)

UE-associated, class-1-less control message; carried on the existing N2 association.

| IE (id) | M/O | Notes |
|---|---|---|
| AMF-UE-NGAP-ID (10) | M | AMF-side UE association id |
| RAN-UE-NGAP-ID (85) | M | gNB-side UE association id |
| LocationReportingRequestType (33) | M | `EventType = Direct (0)` (report once now); `ReportArea = Cell (0)` |

### NGAP LocationReport — ProcedureCode 18 (gNB → AMF, TS 38.413 §8.17.1)

| IE (id) | M/O | Notes |
|---|---|---|
| AMF-UE-NGAP-ID (10) | M | Correlation key for the pending request map |
| RAN-UE-NGAP-ID (85) | M | gNB-side UE association id |
| UserLocationInformation (121) | M | `UserLocationInformationNR` → **NRCGI** (PLMN + 36-bit cell id) + **TAI** (PLMN + TAC) |
| LocationReportingRequestType (33) | O | Echo of the requested reporting type |

## Error / cause table

| Trigger | NF | HTTP | Cause / NGAP result | Behaviour |
|---|---|---|---|---|
| `{ueContextId}` has no UE context in the AMF | AMF | 404 | `CONTEXT_NOT_FOUND` (ProblemDetails) | Namf_Location rejected; LMF propagates failure to LCS Client |
| UE is **CM-IDLE** (no N2 association) | AMF | 409 / 504 | `UE_NOT_REACHABLE` (or trigger paging — deferred) | Cannot send NGAP control; MVP returns failure. *(Paging-then-locate is a follow-up.)* |
| No NGAP LocationReport before timeout | AMF | 504 | `LOCATION_FAILURE` / timeout | Pending channel closed on `ctx` deadline; failure result returned |
| gNB returns failure / cannot determine cell | AMF | 504 | `POSITIONING_DENIED` / `UNSPECIFIED` | Decoded error relayed as failure |
| Missing mandatory IE in the request body | LMF / AMF | 400 | `MANDATORY_IE_MISSING` | Request rejected before any NGAP signalling |
| UE not identifiable (`supi`/`gpsi` both absent) | LMF | 400 | `MANDATORY_IE_MISSING` | Rejected at the Nlmf producer |
| LMF cannot reach AMF / AMF discovery fails | LMF | 504 | `LOCATION_FAILURE` | Returned to LCS Client |

> Cause/status names follow TS 29.572 §6.1.x and TS 29.571 ProblemDetails; where a 3GPP
> cause string is not pinned down for Cell-ID MVP it is noted as `[VERIFY: clause unclear]`.
> `[VERIFY: clause unclear]` — exact ProblemDetails `cause` enum for positioning timeout in
> TS 29.572 (vs. generic `TIMED_OUT`) to be confirmed against the Rel-17 YAML.

## Implementation notes (for the NF developer)

- **LMF NF** (`nf/lmf/`): root-module member (no per-NF `go.mod`; imports
  `github.com/.../5gc-rel17/...`), template Dockerfile shape, SBI :8012, Prometheus :9113.
  Wire into CI docker matrix, root `Makefile` `NFS :=`, and `docker-compose.yml`
  (service + `pcap-lmf` sidecar, `profiles: [core]`). Add `lmf` to `gen-pki.sh`.
- **NRF registry**: add `NFTypeLMF NFType = "LMF"` and `NFTypeGMLC NFType = "GMLC"`
  constants to `nf/nrf/internal/registry/registry.go`. LMF registers with service
  `nlmf-loc` (TS 29.510 §6.1.6.3.3).
- **AMF Namf_Location producer**: new handler on the existing :8001 SBI server,
  `POST /namf-loc/v1/ue-contexts/{id}/provide-loc-info`. Resolve `{id}` → `UEContext`;
  require CM-CONNECTED (an N2 association with a `RAN-UE-NGAP-ID`).
- **Pending-request correlation**: `sync.Map` keyed by `AMF-UE-NGAP-ID` → `chan LocationResult`.
  The Namf_Location handler (1) inserts the channel, (2) builds + sends NGAP
  LocationReportingControl, (3) blocks on the channel with a `ctx` timeout (recommend a
  dedicated positioning timeout constant with a TS doc comment). The NGAP LocationReport
  handler looks up the channel by `AMF-UE-NGAP-ID`, decodes `UserLocationInformationNR`,
  and resolves it. Always `defer` deletion of the map entry to avoid leaks on timeout.
- **NGAP builder/decoder**: builder for LocationReportingControl (ProcCode=16, EventType=Direct,
  ReportArea=Cell); decoder for LocationReport (ProcCode=18) extracting NRCGI (PLMN + 36-bit
  cell id) and TAI (PLMN + TAC). Keep the NGAP code in the AMF reference-point package,
  separate from SBI handlers (anti-pattern: mixing SBI and N2 in one handler).
- **NRCGI rendering**: NRCGI hex string for `nrCellId`; coordinate mapping via a config map
  (`plmn → cell → {lat,lon}`). Absent mapping → `POINT` with `lat=0,lon=0`.
- **Logging**: `logging.NewProcedureLogger(ctx, "DetermineLocation")`. `nf=LMF`/`AMF`;
  `interface` = `Nlmf` / `Namf` / `N2`; `spec_ref` per step (e.g. `TS 38.413 §8.17.1`).
  Conditional fields: `supi`, `amf_ue_ngap_id`, `ran_ue_ngap_id`, `result`, `cause`,
  `duration_ms`.
- **Metrics**: `fivegc_lmf_locate_total{result}` on :9113.

## Out of scope (deferred — follow-up tasks LMF-002+)

- LPP / NRPPa relay for E-CID / OTDOA / NR-ECID / GNSS (TS 38.413 §8.17.2, TS 37.355).
- Nlmf_Location EventSubscription / periodic / area-of-interest (TS 29.572 §5.2.3).
- CancelLocation (TS 29.572 §5.2.2.5).
- GMLC integration / N56 interface (TS 29.515).
- UDM location-privacy check (TS 29.503 §5.2.2 `lcsData`).
- Nlmf_Broadcast service for OTDOA assistance (TS 29.572 §5.3).
- LocationContextTransfer during handover (TS 23.273 §7.8).
- Paging-then-locate for a CM-IDLE UE (combine with network-triggered Service Request).

## Validation approach

- **Unit (in-process):** the LocationReportingControl builder encodes to a valid NGAP PDU
  that round-trips through the free5gc/ngap decoder (IEs 10/85/33 present, EventType=Direct,
  ReportArea=Cell). The LocationReport decoder extracts NRCGI + TAI from a captured
  `UserLocationInformationNR`. DetermineLocation handler maps a known NRCGI → expected
  `LocationData`.
- **Functional (godog, ≥3 scenarios):** happy path (200 + `nrCellId`); UE-not-found → 404
  `CONTEXT_NOT_FOUND`; gNB-location-failure / timeout → failure result. AMF pending-map
  correlation tested with a simulated async LocationReport.
- **NRF registration:** LMF registers as `NFType=LMF` with service `nlmf-loc`; discoverable
  by the LCS Client / consumer.
- **mTLS + HTTP/2:** both Nlmf and Namf endpoints set `TLSConfig` (`NextProtos: ["h2"]`)
  before `http2.ConfigureServer` and require client certs (TS 29.500 §4.4, TS 33.501 §13).
- **E2E (UERANSIM):** `make ueransim` → register UE → POST
  `/nlmf-loc/v1/ue-contexts/imsi-001010000000001/provide-loc-info` → expect NRCGI in the
  response. UERANSIM's gNB does answer NGAP LocationReportingControl with a Cell-ID-level
  LocationReport, so live E2E is achievable.
