# UERANSIM — Modified Features & Command Reference

Stock UERANSIM v3.2.8 lacks UE-side support for several 5GC Rel-17 procedures.
This build applies the patch set in `tools/ueransim/patches/` on top of the upstream tarball to
close those gaps. This file describes **what each patch adds** and is the **command reference**
for the new `nr-cli` verbs (URSP / QoS modification, patches 0001–0030); the later patches add no
`nr-cli` commands.
Everything below is available after `make ueransim` (or any profile that builds
`5gc/ueransim:dev`).

---

## What was added

### Patch 0001 — Skip unknown optional NAS IEs
Stock UERANSIM crashes when it receives a `RegistrationAccept` or
`ConfigurationUpdateCommand` that contains a TLV-E IE it doesn't recognise
(e.g. a URSP container, IEI 0x70–0x7E). This patch makes the decoder skip
unknown optional IEs instead of asserting, matching the TS 24.007 §11.2.4
robustness rule. **No new commands — it just stops crashes.**

### Patch 0010 — UE policy delivery (URSP over NAS)
The UE now handles the **MANAGE UE POLICY COMMAND** carried inside a
`DL NAS Transport` with payload-container type `0x05` (TS 24.501 Annex D).
When the PCF pushes URSP rules via the AMF, the UE:

1. Decodes the URSP TLV container (TS 24.526 §5.2).
2. Stores the rules internally.
3. Replies with **MANAGE UE POLICY COMPLETE** so the AMF/PCF know delivery succeeded.

Previously the UE logged `Unhandled payload container type [5]` and did nothing.
The stored rules are immediately available to `ursp-show`, `ursp-match`, and
`ursp-establish`.

### Patch 0020 — URSP evaluation and new nr-cli verbs
Adds URSP rule matching (`MatchUrspTarget`) and four new nr-cli commands:
`ursp-show`, `ursp-match`, `ursp-establish`, and `ps-modify`.
See the **Command Reference** below.

### Patch 0030 — PDU session modification (NW-initiated QoS)
The UE now handles the **PDU SESSION MODIFICATION COMMAND** (NAS msg type 0xCB)
that the SMF sends when QoS is modified network-side (TS 23.502 §4.3.3.2).
The UE applies the new QoS parameters and replies with
**PDU SESSION MODIFICATION COMPLETE** (0xCC).

The gNB side is also fixed: stock UERANSIM drops `PDUSessionResourceModify`
as an unhandled NGAP message. The patched gNB forwards it, completing the N2
leg of the modification flow.

This is the protocol layer that `ps-modify` (UE-requested) and the NW-initiated
QoS flow both rely on.

### Patch 0040 — Location reporting (gNB)
Stock gNB drops NGAP `LocationReportingControl` as an unhandled initiating message.
The patched gNB replies with a `LocationReport` carrying the serving NR-CGI + TAI
(TS 38.413 §8.12), enabling the live LMF Cell-ID positioning path.

### Patch 0041 — NRPPa transport (gNB)
gNB handles `DownlinkUEAssociatedNRPPaTransport` (ProcCode 8) — decodes the `shared/nrppa`
APER E-CID messages and answers over `UplinkUEAssociatedNRPPaTransport` (ProcCode 50):
PositioningInformation and E-CIDMeasurementInitiation responses plus the measurement report
with the AP position (TS 38.455). Enables live E-CID positioning.

### Patch 0042 — LPP / A-GNSS (UE)
UE-side LPP endpoint over NAS payload container type `0x03` (TS 24.501 §9.11.3.40,
TS 37.355): answers RequestCapabilities, stores ProvideAssistanceData (reference time +
quantized reference location) and answers RequestLocationInformation with synthetic GNSS
code-phase measurements. `LPP_GNSS_NONE=1` makes the UE report no A-GNSS capability, which
exercises the LMF fallback to E-CID.

### Patch 0050 — Network-initiated deregistration → re-registration (UE)
Implements the stock v3.2.8 TODO in `NasMm::receiveDeregistrationRequest`: on "re-registration
required" the UE returns to `MM-DEREGISTERED` and starts a fresh registration
(TS 24.501 §5.5.2.3.2), then re-establishes PDU sessions. Without it a portal subscriber
edit leaves the UE stuck.

### Patch 0051 — gNB AMF selection without Requested NSSAI
Initial NAS messages that carry no NSSAI (Service Request from CM-IDLE, secured
Registration Update, Deregistration) left `requestedSliceType == -1` and stock `selectAmf`
dropped them ("Could not find a suitable AMF"). Fallback: any AMF that completed NG Setup
(TS 23.501 §6.3.5).

### Patch 0052 — Paging AMF Pointer bit-string fix
The gNB RRC decoded the 6-bit `aMFPointer` with `GetBitStringInt<10>`, which returned 0,
so the 5G-S-TMSI never matched and CN Paging was silently ignored. Now decoded as `<6>`
(TS 38.413 §9.3.3.19).

### Patch 0060 — IPv6 / IPv4v6 PDU sessions
Removes the five artificial "IPv4 only" guards in stock UERANSIM (PDU type selection,
address decode, TUN configuration, RA handling and the GTP-U uplink IP-version filter)
and adds an IPv6 TUN path. Needed for SMF-002 prefix delegation E2E. Details in
`docs/procedures/ipv6-prefix-delegation.md`.

### Patch 0070 — PWS: Write-Replace Warning / PWS Cancel (gNB)
gNB handles NGAP Write-Replace Warning Request (ProcCode 51) and PWS Cancel Request
(ProcCode 32), decodes the CBS page structure per the DataCodingScheme (GSM7 / 8-bit /
UCS2 + language prefix) and answers with BroadcastCompletedAreaList / BroadcastCancelledAreaList
(TS 38.413 §8.9). Enables live PWS E2E (`docs/procedures/PublicWarningSystem.md`).

---

## Command Reference

All commands are sent via `nr-cli`. General form:

```bash
nr-cli <imsi> -e "<command> [args]"
# inside a running container:
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "<command>"
```

To list every available command:
```bash
nr-cli imsi-001010000000001 -e "commands"
```

---

### Existing commands (unchanged)

| Command | What it does |
|---|---|
| `info` | Static information about the UE (SUPI, IMEI, config) |
| `status` | Current MM/CM state, current cell, last procedure result |
| `timers` | Dump all active NAS timers and their remaining time |
| `rls-state` | Radio link simulation layer state |
| `coverage` | Cells and PLMNs visible to the UE |
| `ps-list` | List all active PDU sessions with PSI, DNN, UE IP, and QoS |
| `ps-establish <type> [--dnn <dnn>] [--sst <sst>] [--sd <sd>]` | Establish a PDU session |
| `ps-release <psi> [psi ...]` | Release one or more PDU sessions by PSI (1–15) |
| `ps-release-all` | Release all active PDU sessions |
| `deregister <mode>` | Deregister the UE. Modes: `normal`, `switch-off`, `disable-5g`, `remove-sim` |

---

### New commands

#### `ursp-show`
Prints the URSP rules currently stored in the UE, as delivered by the PCF via
the UE policy delivery service (TS 24.526).

```bash
nr-cli imsi-001010000000001 -e "ursp-show"
```

Sample output:
```
URSP rules (2 total):
  Rule [precedence=10] traffic-descriptor: dnn=internet
    RSD [precedence=1] SSC=1  SNSSAI=1:000001  DNN=internet  type=IPv4
  Rule [precedence=255] traffic-descriptor: match-all
    RSD [precedence=1] SSC=1  SNSSAI=1:000001  DNN=internet  type=IPv4
```

If no rules are stored: `No URSP rules provisioned.`

---

#### `ursp-match <target>`
Evaluates the stored URSP rules against a target string (DNN, app name, or FQDN)
and prints which rule matches and which route-selection descriptor would be used.
**Does not establish a session.**

```bash
nr-cli imsi-001010000000001 -e "ursp-match internet"
nr-cli imsi-001010000000001 -e "ursp-match cloud-gaming"
nr-cli imsi-001010000000001 -e "ursp-match ims"
```

Matching logic (in priority order):
1. A route-selection descriptor whose DNN equals the target exactly.
2. An FQDN component in the traffic descriptor that contains the target.
3. A `match-all` traffic descriptor.

Sample output:
```
Rule matched: rule precedence 10 matched on DNN 'internet'
  -> DNN=internet  SNSSAI=1:000001  SSC=1  PDU type=IPv4
```
```
No URSP rule matches 'ims'
```

---

#### `ursp-establish <target>`
Same matching logic as `ursp-match`, but if a rule matches it goes on to
**establish the PDU session** steered by that rule's route-selection descriptor
(DNN, S-NSSAI, SSC mode, PDU session type).

```bash
nr-cli imsi-001010000000001 -e "ursp-establish internet"
nr-cli imsi-001010000000001 -e "ursp-establish cloud-gaming"
```

Sample output:
```
Rule matched: rule precedence 10 matched on DNN 'internet'
Establishing PDU session — DNN=internet  SNSSAI=1:000001 ...
PDU session established. PSI=2  UE IP=10.60.0.2
```

Note: UERANSIM has a UAC (Unified Access Control) timing constraint. If the
first attempt is barred the UE retransmits on T3580 expiry (~16 s). This is
normal behaviour, not a core issue.

---

#### `ps-modify <psi> [--5qi <value>]`
Triggers a **UE-requested PDU session modification** (TS 23.502 §4.3.3.1).
The UE sends a `PDU SESSION MODIFICATION REQUEST` for the given PSI; the SMF
and PCF authorize the change and reply with a `MODIFICATION COMMAND`. The `--5qi`
flag lets the UE request a specific QoS class — the network may grant a different
value.

```bash
# Request modification with no specific QoS change (trigger only)
nr-cli imsi-001010000000001 -e "ps-modify 1"

# Request a specific 5QI (network authorizes the actual value)
nr-cli imsi-001010000000001 -e "ps-modify 1 --5qi 7"
```

PSI is the PDU Session Identity shown in `ps-list` (integer 1–15).

---

## Quick-start examples

```bash
# 1. Start the standard scenario
make ueransim

# 2. Check UE status
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "status"

# 3. Establish a session on the internet DNN
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish IPv4 --dnn internet"

# 4. Check what URSP rules the PCF delivered
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ursp-show"

# 5. Simulate an app matching against URSP rules
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ursp-match internet"

# 6. Let URSP steer a new session autonomously
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ursp-establish internet"

# 7. List sessions (find the PSI)
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"

# 8. Request a QoS modification on session 1
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-modify 1 --5qi 7"

# 9. Release a specific session
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-release 1"

# 10. Deregister cleanly
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "deregister normal"
```

---

## Portal integration

All of the above are available as buttons in the management portal
(`http://localhost:8080/ueransim`). Open the **NR-CLI** panel for any registered
UE to access:

- **Info & Status** section: `info`, `status`, `timers`, `rls-state`, `coverage`, `ps-list`
- **PDU Session — Establish**: editable DNN field → `ps-establish IPv4`
- **PDU Session — Release**: one button per active session + `ps-release-all`
- **QoS Modify**: PSI selector + optional 5QI input → `ps-modify`
- **URSP**: `ursp-show` + target field → `ursp-match` / `ursp-establish`
- **Deregistration**: all four modes as separate buttons

---

## End-to-end validation

```bash
# Full suite (requires running stack: make ueransim first)
./scripts/validate-ueransim-mod.sh

# Makefile shortcuts
make ursp-e2e          # URSP delivery + match + establish
make qos-mod-e2e       # NW-initiated QoS modification
make nw-session-e2e    # NW-triggered additional PDU session (URSP steering)
make ueransim-mod-e2e  # all of the above
```
