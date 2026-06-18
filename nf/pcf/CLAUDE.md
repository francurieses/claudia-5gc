# CLAUDE.md — PCF (Policy and Charging Function)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

PCF decides session control and charging policies. During PDU Session Establishment, SMF
queries PCF for QoS rules, AMBR, and charging info (N7). At registration, AMF queries PCF
for URSP (UE Route Selection Policy) rules that are delivered to the UE as IEI 0x7B (N15).

**Primary specifications:**
- TS 23.501 §6.3.4 — PCF architecture
- **TS 29.512** — Npcf_SMPolicyControl (N7, Stage 3)
- **TS 29.525** — Npcf_UEPolicyControl (N15, Stage 3)
- **TS 24.526** — URSP encoding and Traffic Descriptor / Route Selection Descriptor types
- TS 23.503 — Policy & Charging Control architecture

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| N7 | SMF | Npcf_SMPolicyControl/HTTPS | TS 29.512 |
| N15 | AMF | Npcf_UEPolicyControl/HTTPS | TS 29.525 |
| N36 | UDR | Nudr_DataRepository/HTTPS | TS 29.504 |

## 3. Provided SBI Services

| Service | Operation | Route | Spec |
|---|---|---|---|
| Npcf_SMPolicyControl | Create SM Policy | `POST /npcf-smpolicycontrol/v1/sm-policies` | TS 29.512 §5.2.2.2 |
| Npcf_SMPolicyControl | Delete SM Policy | `DELETE /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}` | TS 29.512 §5.2.2.4 |
| Npcf_UEPolicyControl | Create UE Policy | `POST /npcf-ue-policy-control/v1/ue-policies` | TS 29.525 §4.2.2.2 |
| Npcf_UEPolicyControl | Delete UE Policy | `DELETE /npcf-ue-policy-control/v1/ue-policies/{polAssoId}` | TS 29.525 §4.2.2.3 |

## 4. SM Policy (N7) — Config-Driven Response

SM policy values are all read from `config/dev.yaml` (`default_sm_policy:` section).
No hardcoded values in Go code. Default configuration:

| Parameter | Default | Config key |
|-----------|---------|-----------|
| Session AMBR UL | 100 Mbps | `session_ambr_uplink` |
| Session AMBR DL | 100 Mbps | `session_ambr_downlink` |
| 5QI | 9 (best-effort non-GBR) | `5qi` |
| ARP Priority Level | 8 | `arp_priority_level` |
| ARP Preemption Capability | NOT_PREEMPT | `arp_preempt_cap` |
| ARP Preemption Vulnerability | NOT_PREEMPTABLE | `arp_preempt_vuln` |
| Flow Description | permit out ip from any to assigned | `flow_description` |
| Flow Precedence | 100 | `flow_precedence` |

### Per-subscriber QoS overrides (internal management API — not 3GPP SBI)

```
PUT    /pcf-internal/v1/subscribers/{supi}/sm-policy-override          # body: {"5qi", "dnn"?, "arp_priority_level"?, "ambr_uplink"?, "ambr_downlink"?}
GET    /pcf-internal/v1/subscribers/{supi}/sm-policy-override[?dnn=]   # 404 if none
DELETE /pcf-internal/v1/subscribers/{supi}/sm-policy-override[?dnn=]
```

QoS decision precedence at `SmPolicyControl_Create` (the chosen source is reported in the
additive `x5gcQosSource` response field): **DNN-scoped override (`supi|dnn`) > subscriber-wide
override (`supi`) > `subsDefQos` from SMF (UDM sm-data) > operator config defaults**.
The optional `dnn` field scopes an override to one DNN — used by the NW-triggered additional
PDU session flow (`docs/procedures/nw-triggered-pdu-session.md`) so the new session gets its
own 5QI/AMBR without disturbing the subscriber's other sessions. In-memory only (reset on restart).

## 5. UE Policy Control (N15) — URSP Delivery

At UE registration, AMF calls `POST /npcf-ue-policy-control/v1/ue-policies` with the UE's SUPI.
PCF resolves URSP rules (priority: UDR per-subscriber override → config defaults) and encodes
them as a binary UE Policy Container per TS 24.526 §4.2. The container is returned as base64
in `uePolicySections[*].uePolicySectionContent`.

**Policy resolution priority:**
1. UDR `subscription_policy` WHERE `supi = ?` (per-subscriber override)
2. `config/dev.yaml` → `default_ursp.rules` (operator-default fallback)

Default URSP configuration example:
```yaml
default_ursp:
  rules:
    - precedence: 255
      traffic_descriptor:
        match_all: true
      route_descriptors:
        - precedence: 1
          ssc_mode: 1
          snssai: { sst: 1, sd: "000001" }
          dnn: "internet"
          pdu_session_type: 1
```

## 6. URSP Binary Encoding (TS 24.526)

Implemented in `internal/policy/ursp.go`. Wraps rules in a UE Policy Section Management
List (TS 24.501 §9.11.4.15). No Go-side hardcoded values — all config-driven.

Traffic Descriptor type codes: 0x01=match-all, 0x08=DNN, 0x21=FQDN, 0x23=IPv4, 0x25=protocol-id, 0x26=port-range.
Route Selection Descriptor type codes: 0x01=SSC-mode, 0x02=S-NSSAI, 0x03=DNN, 0x04=PDU-session-type.

## 7. Architecture

```
cmd/pcf/
  main.go           Bootstrap + config + NRF registration + UDR client wiring
internal/
  config/config.go  Config struct: SBI, Peers (NRF+UDR), DefaultSMPolicy, DefaultURSP
  policy/ursp.go    URSP binary codec (TS 24.526 §4.2)
  server/
    server.go       HTTP/2 SBI server + route registration
    n15.go          N15 Npcf_UEPolicyControl handlers
    udr_client.go   HTTP UDR client (N36 policy-data lookup)
config/
  dev.yaml          Default SM policy + default URSP rules (no hardcoded values in Go)
features/
  ursp.feature      BDD scenarios for URSP delivery
```

## 8. Dependencies

| Peer | Env / Config | Purpose |
|------|--------------|---------|
| NRF | `peers.nrf` | Service registration + heartbeat |
| UDR | `peers.udr` | Per-subscriber URSP rule lookup (N36); optional |

## 9. Commands

```bash
make -C nf/pcf build
make -C nf/pcf test
make -C nf/pcf docker
make -C nf/pcf run
```

## 10. Debugging

```bash
docker logs -f pcf | jq '.procedure, .pol_asso_id, .rule_count, .result'
# N15 logs: procedure=UEPolicyCreate|UEPolicyDelete, supi, rule_count, container_bytes
# N7 logs:  procedure=SmPolicyCreate|SmPolicyDelete, smPolicyId
```

N7 and N15 traffic available via PCAP sidecars.
