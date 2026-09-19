# PFCP Usage Reporting — URR with Active Usage Reports (TS 29.244 §5.2.2.4 — UPF + SMF)

**Spec:** TS 29.244 §5.2.2.4 (Usage Reporting Rule handling) · §7.5.5 (PFCP Session Report Request) ·
§7.5.8 (Usage Report IE within Session Report) · §7.5.9 (PFCP Session Report Response) ·
§8.2.41 (Reporting Triggers) · §8.2.13 (Volume Threshold) · §8.2.14 (Time Threshold) ·
§8.2.44 (Usage Report Trigger) · §8.2.5 (Volume Measurement) · §8.2.42 (Duration Measurement)
**Status:** 🟡 Planned (this doc gates UPF-001)
**Primary NF:** UPF (measurement + report emission)
**Other NFs involved:** SMF (URR provisioning + report consumption). PCF / CHF charging are
**out of scope, downstream** — the SMF only logs consumed usage for now; it does not yet forward it
over N28 (Nchf) or apply policy.

## Purpose

The SMF installs Usage Reporting Rules (URRs) into the UPF at PDU Session Establishment, but the
current UPF **parses only Create PDR / FAR / QER — never Create URR — and keeps no per-session
byte/packet counters**, so no Usage Reports are ever emitted. This procedure adds the full active
reporting loop required as a prerequisite for charging (TS 32.255 offline/online charging):

- the **SMF** provisions a **Create URR** (volume-threshold + periodic) in the Session Establishment
  Request and links it from the Create PDR;
- the **UPF measures** per-session uplink and downlink volume (bytes + packets) against the URR;
- when a **volume threshold is crossed** or the **periodic measurement timer fires**, the UPF emits a
  **PFCP Session Report Request** (message type 56) carrying a **Usage Report** IE;
- the **SMF consumes** the report — logs total/UL/DL volume, duration and trigger — and answers with a
  **PFCP Session Report Response** (message type 57, Cause = Request accepted); after a volume-threshold
  report the UPF **re-arms** the threshold (resets the baseline) so subsequent crossings fire again.

> **Report addressing — no docker-compose change.** The UPF already learns the SMF's source address
> (`raddr.IP`) and the CP F-SEID on the Session Establishment Request. It sends the Session Report
> Request to `<smfIP>:8805` with the message **SEID = CP F-SEID**. Because intra-Docker-network UDP
> needs no published port, `docker-compose.yml` service definitions are **not** changed. This does,
> however, require the SMF — today a **PFCP client only** (`net.DialUDP` per op, ephemeral socket) —
> to run a **persistent PFCP receiver bound to `0.0.0.0:8805`** inside its own container. The receiver
> is **additive**: the existing establishment / modification / deletion sends stay on ephemeral client
> sockets and are unchanged.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant gNB
    participant UPF
    participant SMF
    participant CHF as PCF / CHF (out of scope)

    Note over SMF,UPF: PDU Session Establishment — URR provisioning (TS 29.244 §7.5.2)
    SMF->>UPF: PFCP Session Establishment Request (msg 50)<br/>Create PDR (URR ID list → 1) + Create FAR + Create QER<br/>Create URR {URR ID=1, Meas.Method=VOLUM+DURAT,<br/>Reporting Triggers=VOLTH+PERIO, Volume Threshold, Time Threshold,<br/>Measurement Period} — TS 29.244 §7.5.2.4 / §5.2.2.4
    UPF-->>SMF: PFCP Session Establishment Response (msg 51)<br/>Cause=Request accepted, UP F-SEID — TS 29.244 §7.5.3
    Note over UPF: UPF stores smfIP=raddr.IP, cpSEID, URR state<br/>(counters zeroed, thresholds armed, periodic timer started)

    Note over gNB,UPF: User-plane traffic accumulates volume (TS 29.244 §5.2.2.4)
    gNB->>UPF: GTP-U uplink packets (N3 → N6)
    UPF->>gNB: GTP-U downlink packets (N6 → N3)
    Note over UPF: UPF increments ULVOL/ULPKT and DLVOL/DLPKT per session

    Note over UPF,SMF: (a) Volume threshold crossed — VOLTH (TS 29.244 §8.2.44)
    UPF->>SMF: PFCP Session Report Request (msg 56) SEID=cpSEID<br/>Report Type=USAR + Usage Report {URR ID=1, UR-SEQN,<br/>Usage Report Trigger=VOLTH, Volume Measurement (TOVOL/ULVOL/DLVOL),<br/>Duration Measurement, Start Time, End Time} — TS 29.244 §7.5.5 / §7.5.8
    SMF->>SMF: match SEID→session; log volume+duration+trigger<br/>(nf=SMF procedure=UsageReporting interface=N4 direction=IN)
    SMF-->>UPF: PFCP Session Report Response (msg 57)<br/>Cause=Request accepted — TS 29.244 §7.5.9
    Note over UPF: re-arm volume threshold (reset baseline)

    Note over UPF,SMF: (b) Periodic measurement timer fires — PERIO (TS 29.244 §8.2.41)
    UPF->>SMF: PFCP Session Report Request (msg 56) SEID=cpSEID<br/>Report Type=USAR + Usage Report {URR ID=1, UR-SEQN++,<br/>Usage Report Trigger=PERIO, Volume Measurement, Duration Measurement,<br/>Start/End Time} — TS 29.244 §7.5.5
    SMF-->>UPF: PFCP Session Report Response (msg 57) Cause=Request accepted
    Note over UPF: restart periodic timer

    SMF--xCHF: (downstream, out of scope) Nchf usage report / charging
```

Mandatory vs conditional per TS 29.244 §5.2.2.4:

- The **Create URR + Create PDR URR-ID link** at establishment are **mandatory for this feature**
  (without them no measurement occurs). In the wider spec a URR is only present when the SMF wants
  reporting; here it is always installed for the default flow.
- The **Session Report Request/Response pair** is **mandatory** whenever a configured trigger
  (VOLTH or PERIO) fires.
- **Start Time / End Time / Duration Measurement** IEs are **conditional** — included because
  Measurement Method has DURAT set; if only VOLUM were set they would be omitted.

## Information Elements

### Create URR — SMF → UPF, in Session Establishment Request (TS 29.244 §7.5.2.4, IE Type 6)

Library: `github.com/wmnsk/go-pfcp`, package `ie`. Constructor names verified against `go-pfcp@v0.0.14`.

| IE | IE Type | M/C | Value (this design) | go-pfcp constructor | Spec |
|---|---|---|---|---|---|
| Create URR (grouping) | 6 | M | contains the IEs below | `ie.NewCreateURR(...)` | §7.5.2.4 |
| URR ID | 81 | M | `1` | `ie.NewURRID(1)` | §8.2.54 |
| Measurement Method | 62 | M | VOLUM=1, DURAT=1, EVENT=0 | `ie.NewMeasurementMethod(0, 1, 1)` *(event, volum, durat)* | §8.2.40 |
| Reporting Triggers | 37 | M | VOLTH + PERIO | `ie.NewReportingTriggers(triggers)` *(uint16 bitmask)* | §8.2.41 |
| Volume Threshold | 31 | C | total-volume threshold from SMF config (bytes) | `ie.NewVolumeThreshold(flags, tvol, uvol, dvol)` | §8.2.13 |
| Time Threshold | 32 | C | seconds from SMF config | `ie.NewTimeThreshold(seconds)` | §8.2.14 |
| Measurement Period | 64 | C | periodic period, e.g. 60 s | `ie.NewMeasurementPeriod(60*time.Second)` | §8.2.42 |

Notes for the developer:

- **Reporting Triggers bitmask (`ie.NewReportingTriggers(uint16)`).** The go-pfcp constructor takes a
  raw `uint16`; the library exposes no named per-bit constants, so define local constants from
  TS 29.244 §8.2.41 Figure 8.2.41-1. `[VERIFY: exact bit positions/octet order for PERIO and VOLTH in the go-pfcp uint16 argument — confirm against ie/reporting-triggers.go and TS 29.244 §8.2.41 before hardcoding]`.
- **Volume Threshold flags octet** selects which of TOVOL/ULVOL/DLVOL fields are present
  (TS 29.244 §8.2.13). For a total-volume threshold set the TOVOL flag and pass the byte count as `tvol`.
- **PDR linkage.** The existing `ie.NewCreatePDR(...)` in `sendPFCPSessionEstablishment`
  (`nf/smf/internal/server/server.go` ~line 1573) must add a **URR ID** child (`ie.NewURRID(1)`) so the
  PDR references the URR — this is the "URR ID list within the PDR" (TS 29.244 §7.5.2.2, IE Type 81
  repeated inside the Create PDR). Without the link the UPF measures nothing.
- **Measurement Period vs Time Threshold.** Periodic reporting (PERIO) is driven by **Measurement
  Period** (§8.2.42). Time Threshold (§8.2.14) is the TIMTH trigger for elapsed session time. Both are
  documented; the MVP arms **PERIO via Measurement Period** and **VOLTH via Volume Threshold**.
  `[VERIFY: whether the periodic cadence should be provisioned as Measurement Period (§8.2.42, PERIO) or Time Threshold (§8.2.14, TIMTH) — task descriptor lists both; pick one and keep the trigger flag consistent]`.

### PFCP Session Report Request — UPF → SMF (msg type 56, TS 29.244 §7.5.5)

`message.NewSessionReportRequest(mp, fo uint8, seid uint64, seq uint32, pri uint8, ies ...*ie.IE)` —
`seid` = the CP F-SEID recorded at establishment.

| IE | IE Type | M/C | Value | go-pfcp constructor | Spec |
|---|---|---|---|---|---|
| Report Type | 39 | M | USAR=1 | `ie.NewReportType(0, 0, 1, 0)` *(upir, erir, usar, dldr)* | §8.2.21 |
| Usage Report (grouping) | 80 | M | contains the IEs below | `ie.NewUsageReportWithinSessionReportRequest(...)` | §7.5.8 |
| URR ID | 81 | M | `1` | `ie.NewURRID(1)` | §8.2.54 |
| UR-SEQN | 52 | M | monotonically increasing per URR | `ie.NewSequenceNumber(seqn)` | §8.2.44 |
| Usage Report Trigger | 63 | M | VOLTH or PERIO | `ie.NewUsageReportTrigger(octets ...uint8)` | §8.2.44 |
| Volume Measurement | 66 | C | TOVOL/ULVOL/DLVOL (+ pkt counts) | `ie.NewVolumeMeasurement(flags, tvol, uvol, dvol, tpkt, upkt, dpkt)` | §8.2.5 |
| Duration Measurement | 67 | C | seconds since Start Time | `ie.NewDurationMeasurement(dur time.Duration)` | §8.2.42 |
| Start Time | 75 | C | measurement window start | `ie.NewStartTime(t time.Time)` | §8.2.45 |
| End Time | 76 | C | measurement window end | `ie.NewEndTime(t time.Time)` | §8.2.46 |

Notes:

- **UR-SEQN** (Usage Report Sequence Number, §8.2.44) is carried as an IE of type **Sequence Number
  (52)**; go-pfcp models it via `ie.NewSequenceNumber(uint32)`. `[VERIFY: that Sequence Number (type 52) is the correct encoding go-pfcp expects for UR-SEQN inside the Usage Report grouping — confirm the SMF parse path reads it back as UR-SEQN]`.
- **Usage Report Trigger** constructor takes variadic trigger octets (`...uint8`); set the VOLTH bit for
  a threshold report and the PERIO bit for a periodic report per TS 29.244 §8.2.44 Figure 8.2.44-1.
  `[VERIFY: exact octet/bit layout for VOLTH and PERIO passed to ie.NewUsageReportTrigger]`.
- **Volume Measurement flags** octet (§8.2.5) declares which volume/packet fields are present. Populate
  TOVOL = UL+DL, ULVOL, DLVOL and, if desired, the packet-count fields (TONOP/ULNOP/DLNOP).

### PFCP Session Report Response — SMF → UPF (msg type 57, TS 29.244 §7.5.9)

`message.NewSessionReportResponse(mp, fo, seid, seq, pri, ies...)` — `seid` = UP F-SEID (echo of the
value the UPF used), `seq` echoes the request sequence.

| IE | IE Type | M/C | Value | go-pfcp constructor | Spec |
|---|---|---|---|---|---|
| Cause | 19 | M | Request accepted (1) | `ie.NewCause(ie.CauseRequestAccepted)` | §8.2.1 |
| Offending IE | 40 | C | on reject only | `ie.NewOffendingIE(...)` | §8.2.22 |

## Error / edge cases

| Trigger | PFCP Cause | NF | Response / behaviour |
|---|---|---|---|
| Session Report arrives for a SEID with no matching SMF session | Session context not found (`ie.CauseSessionContextNotFound`) | SMF | Session Report Response (msg 57) with the not-found cause; log at WARN, do not create a session. Mirrors the UPF's existing SessionModification not-found path. |
| Usage Report references a URR ID the SMF never installed | Request accepted (report still logged) or Mandatory IE incorrect | SMF | MVP: accept + log a WARN `unknown URR ID`; do not fail the response. `[VERIFY: whether spec prefers Cause "Mandatory IE incorrect" here — TS 29.244 §7.5.9 / Table 8.2.1-1]`. |
| UPF cannot reach the SMF (UDP send error / no route) | — | UPF | Log the send error at WARN and drop the report; **never panic**. No blocking, no crash of the receive loop. Best-effort for MVP. |
| Session Report Response missing or late | — | UPF | Best-effort: **no retransmission** for the MVP (matches the SMF client's existing "no response" tolerance on establishment). Counters keep accumulating; the next trigger produces a fresh report with an incremented UR-SEQN. |
| Threshold crossed repeatedly before a response | — | UPF | Re-arm only **after** emitting; coalesce — one in-flight report per URR at a time to avoid a report storm. |
| Session deleted while a report is in flight | Session context not found | SMF | SMF answers not-found; UPF stops the periodic timer and clears URR state on Session Deletion. |

## NF interaction map (N4 only — no SBI in this procedure)

- `SMF → UPF: PFCP Session Establishment Request (msg 50)` — now carrying **Create URR** + PDR URR-ID link.
- `UPF → SMF: PFCP Session Report Request (msg 56)` — **new**, Usage Report (USAR).
- `SMF → UPF: PFCP Session Report Response (msg 57)` — **new**.
- Downstream `SMF → CHF/PCF` (Nchf / Npcf) charging is **out of scope** for UPF-001.

## Implementation notes

Grounded in the real code layout — no invented packages.

### UPF side (`nf/upf/internal/pfcp/server.go`, `nf/upf/internal/gtp/`)

- **Parse Create URR** in `handleSessionEstablishment` alongside the existing `req.CreatePDR` /
  `req.CreateQER` loops: iterate `req.CreateURR`, read URR ID, Measurement Method, Reporting Triggers,
  Volume Threshold, Time Threshold / Measurement Period. Store on a new `URRState` field of `Session`
  (sibling of the existing `QERState` struct) with: `URRID uint32`, `MeasVolume/MeasDuration bool`,
  `Triggers` bitmask, `VolThreshold uint64`, `Period time.Duration`, live counters
  `ULBytes/DLBytes/ULPkts/DLPkts uint64`, `StartTime time.Time`, `URSeqn uint32`, and a `baseline` for
  re-arming after a VOLTH report.
- **Record the SMF address at establishment.** Add `SMFAddr *net.UDPAddr` (from `raddr`) and reuse the
  already-extracted `CPSEID` on `Session`. The report is sent to `SMFAddr` (its IP, port 8805) with
  message SEID = `CPSEID`. Note `handleSessionEstablishment` currently learns `raddr` — persist it.
- **Count volume** on the data path. The GTP-U fast paths already look sessions up
  (`sessions.GetByULTEID` uplink, `sessions.GetByUEIP` downlink). Increment the session's UL counters in
  the N3→N6 path and DL counters in the N6→N3 path. Use `atomic` or the existing `SessionTable.mu` —
  keep the fast path lock-light (per-session atomics preferred; the table already uses `sync.RWMutex`).
- **Trigger evaluation.** After incrementing, if `ULBytes+DLBytes - baseline >= VolThreshold` and VOLTH
  is armed → build+send a Session Report Request, then set `baseline = ULBytes+DLBytes`. Run a
  **periodic goroutine** (per session or a single sweeper ticking at `Period`) that emits a PERIO report
  and restarts. Guard one in-flight report per URR.
- **Build the report** with `pfcpmsg.NewSessionReportRequest(0,0, cpSEID, seq, 0, ie.NewReportType(...),
  ie.NewUsageReportWithinSessionReportRequest(...))`; send via a `net.DialUDP` to `SMFAddr` (mirror
  `sendResponse`, but this is a new client send to the SMF, not a reply on the listener socket) — read
  the Session Report Response best-effort with a short deadline.
- **Cleanup.** On Session Deletion stop the periodic timer and drop `URRState`.

### SMF side (`nf/smf/internal/server/server.go`, `cmd/smf/main.go`)

- **Install the URR.** In `sendPFCPSessionEstablishment` add `ie.NewCreateURR(...)` to the
  establishment request and add `ie.NewURRID(1)` inside the existing `ie.NewCreatePDR(...)`. Provide
  volume threshold / period from SMF config (new `usage_reporting:` block in `nf/smf/config/dev.yaml`,
  e.g. `volume_threshold_bytes`, `periodic_seconds`).
- **New persistent PFCP receiver.** Add a listener bound to `0.0.0.0:8805` (e.g.
  `internal/server/pfcp_receiver.go` or a small `internal/pfcp/` package) started from `cmd/smf/main.go`
  alongside the SBI server. It must dispatch `*pfcpmsg.SessionReportRequest`, look the session up by
  **header SEID → CP F-SEID** (the SMF assigns `Session.SEID`; today it maps by SUPI/PSI — add a
  `map[uint64]*Session` SEID index, or scan `sessions`), parse the Usage Report, and reply with
  `pfcpmsg.NewSessionReportResponse(0,0, seid, seq, 0, ie.NewCause(ie.CauseRequestAccepted))`.
  Because SMF sends (establishment/modification/deletion) use ephemeral `DialUDP` client sockets, the new
  receiver on `:8805` does not collide with them.
- **Consume + log.** Use `logging.NewProcedureLogger(ctx, "UsageReporting")` with the mandatory field
  set: `nf=SMF`, `procedure=UsageReporting`, `interface=N4`, `direction=IN`,
  `spec_ref="TS 29.244 §7.5.5"`, plus `seid`, `supi`, `pdu_session_id`, and conditional
  `total_bytes`/`ul_bytes`/`dl_bytes`/`duration_ms`/`trigger`/`ur_seqn`. This satisfies acceptance
  criterion "SMF consumes the report and logs volume/time".

### Protocol-encoding rule (CLAUDE.md § Protocol Encoding Rules)

PFCP (N4) is **TLV (IE Type + Length + Value)** per TS 29.244, encoded via `shared/pfcp` conventions —
here realised through `github.com/wmnsk/go-pfcp` `ie`/`message` (already the UPF's PFCP library). **No
bespoke binary format.** PFCP is **UDP/8805** — there is **no SCTP** on N4 (SCTP is N2/NGAP only).

## Validation approach

- **Unit (UPF, `nf/upf/internal/pfcp/`):** parse a Session Establishment Request containing a Create URR
  → assert `URRState` (URR ID, method, triggers, threshold, period) is populated; build a Session Report
  Request and round-trip it through `pfcpmsg.Parse`, asserting the Usage Report grouping (URR ID,
  UR-SEQN, trigger, Volume/Duration Measurement) decodes back byte-for-byte.
- **Unit (SMF, `nf/smf/internal/server/`):** the establishment builder now emits a Create URR + PDR
  URR-ID link (existing IPv4 path otherwise unchanged); the receiver parses a Usage Report and produces a
  Session Report Response with Cause = Request accepted; SEID→session lookup resolves and returns
  not-found for an unknown SEID.
- **Functional (godog):** (1) happy volume-threshold report — install URR, feed volume past the
  threshold, assert a Session Report Request (USAR/VOLTH) is emitted and answered, and the threshold is
  re-armed; (2) periodic report — advance the timer, assert a PERIO report; (3) session-not-found —
  report for an unknown SEID returns Cause = Session context not found.
- **Live PCAP (`make ueransim` + `scripts/pcap-control.sh list upf`):** between `upf` and `smf` on
  **UDP/8805**, Wireshark must dissect a **PFCP Session Report Request (type 56)** with a well-formed
  Usage Report IE and a **PFCP Session Report Response (type 57)** with Cause = Request accepted. Confirm
  **no SCTP** appears (N4 is UDP). Drive volume with `ps-establish` + traffic through the UE, or wait for
  the periodic timer.

## Conformance Notes — 2026-07-21

**Verdict**: DEVIATION:TS 29.244 §7.5.8.3 (mandatory UR-SEQN mis-encoded)

Audited task UPF-001 against TS 29.244 (uncommitted work on `dev`). Bit layouts and IE
flag octets were verified against the go-pfcp v0.0.14 source and the TS bit tables.

### Findings
| # | Severity | Finding | TS Clause | Recommendation |
|---|----------|---------|-----------|----------------|
| 1 | BLOCKER | UR-SEQN inside the Usage Report is encoded as the **Sequence Number** IE (type 52) via `pfcpie.NewSequenceNumber` on the UPF (server.go:655) and read back as `pfcpie.SequenceNumber` on the SMF (pfcp_report.go:226). UR-SEQN is a **mandatory** IE of the Usage Report and is a distinct IE, **type 104** (`NewURSEQN`). A spec-compliant decoder / Wireshark finds no mandatory UR-SEQN and an unexpected Sequence-Number IE. Round-trips only because both endpoints share the wrong type, so all unit/godog tests pass while the wire is non-conformant. | §7.5.8.3 (Usage Report — UR-SEQN "M"), §8.2.45 (UR-SEQN IE, type 104) | UPF: `pfcpie.NewSequenceNumber(urSeqn)` → `pfcpie.NewURSEQN(urSeqn)`. SMF: `case pfcpie.SequenceNumber` → `case pfcpie.URSEQN` and `child.SequenceNumber()` → `child.URSEQN()`. Update the tests' helper constructors/accessors accordingly. |
| 2 | MINOR | Usage Report Trigger encoded as a single octet (`NewUsageReportTrigger(0x02)`). §8.2.44 defines the trigger flags over octets 5–7; go-pfcp's own raw `UsageReportTrigger()` getter requires ≥3 octets. Bit positions (PERIO=0x01, VOLTH=0x02 in octet 1) are correct and the `Has*` accessors tolerate 1 octet, so interop with go-pfcp holds, but Wireshark may flag the IE as truncated. | §8.2.44 | Pass at least two octets (e.g. `NewUsageReportTrigger(trigger, 0x00)`), ideally three for Rel-17. |
| 3 | MINOR | UPF derives the SMF report destination from the establishment transport source IP (`raddr.IP`), not the CP F-SEID node address — because the SMF advertises F-SEID with IP `0.0.0.0` (server.go:1594). Pragmatic and documented; SEID value itself = CP F-SEID and is correct. | §5.2.2 (F-SEID semantics), §7.5.5 | Acceptable-with-note for the MVP. Longer term the SMF should advertise its real N4 IP in the CP F-SEID and the UPF resolve the destination from it. |
| 4 | INFO | Volume Measurement reports **cumulative** volume since session start (counters never reset); only the VOLTH detection baseline (`LastReportedVolume`) advances. Correct for threshold re-arm (§5.2.2.4, verified), but once N28/CHF charging is wired in the reported measurement is normally the delta since the previous report. | §5.2.2.4 | Revisit reset-vs-cumulative semantics before charging (Nchf) integration; harmless while charging is out of scope. |
| 5 | INFO | Unknown-URR-ID Usage Report → Cause = Request accepted + WARN. §7.5.9 mandates no specific reject cause when the session context exists; "Session context not found" would be wrong and "Mandatory IE incorrect" targets malformed IEs. Accept + log is defensible. | §7.5.9 | Acceptable MVP. |
| 6 | INFO | Single URR per session (id always 1). | §7.5.2.4 | Acceptable MVP simplification. |

### Conformant items (verified against the TS bit tables + go-pfcp v0.0.14)
- Create URR → Create PDR URR-ID link (PDR references URR ID 1). §7.5.2.2/§7.5.2.4.
- Measurement Method `NewMeasurementMethod(0,1,1)` → 0x03 = VOLUM(bit2)+DURAT(bit1). §8.2.40.
- Reporting Triggers `0x0300` → octet-1 0x03 = PERIO(bit1)+VOLTH(bit2). §8.2.41.
- Volume Threshold `NewVolumeThreshold(0x01,…)` → TOVOL flag + total value. §8.2.13.
- Volume Measurement flags `0x3F` = TOVOL|ULVOL|DLVOL|TONOP|ULNOP|DLNOP. §8.2.5.
- Report Type USAR set (msg 56); Session Report Response Cause = Request accepted / Session context not found (msg 57), no session fabricated on unknown SEID. §7.5.5/§7.5.9.
- Msg types 56/57 and SEID = CP F-SEID. §7.5.5.
