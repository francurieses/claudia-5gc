# UPF Session-AMBR / QER MBR Enforcement (task UPF-005)
#
# Design contract: docs/procedures/AmbrEnforcement.md (sections "Enforcement algorithm",
# "Error / edge cases", "Test plan"). Step definitions live in ambr_enforcement_steps_test.go
# (build tag `functional`; run with `make -C nf/upf test-functional`).
#
# Spec refs: TS 23.501 §5.7.1.8 (UPF enforces UL and DL Session-AMBR),
#            TS 23.501 §5.7.2.6 (Session-AMBR, non-GBR flows), §5.7.2.5 (excess may be discarded),
#            TS 29.244 §5.2.5 (QER handling), §5.4.3 (gating control), §5.4.4 (QoS control: MBR),
#            TS 29.244 §7.5.2.2 (QER ID list in Create PDR), §7.5.2.5 (Create QER),
#            TS 29.244 §7.5.4.5 (Update QER), §7.5.4.9 (Remove QER),
#            TS 29.244 §8.2.7 (Gate Status), §8.2.8 (MBR, kbps), §8.2.75 (QER ID), §8.2.89 (QFI),
#            TS 29.244 §8.2.1 (Cause), TS 38.415 §5.5.2.1 (DL PDU Session Information / QFI).
#
# Harness contract for the godog suite (in-process, no real network):
#   - PFCP: real PFCP over loopback UDP against an in-process pfcp.Server (same as
#     downlink_checksum_steps_test.go). Cause values are read from the PFCP responses.
#   - Clock: the enforcement clock is injected and controlled by the test ("the enforcement clock is
#     at t=0 ms", "the clock advances by N ms"). No wall-clock-dependent assertions.
#   - Offered traffic: "N packets of B bytes are offered uplink" calls the UL admission hook the
#     GTP-U handlePacket uses (inner IP packet length B); "... downlink" calls the DL hook used by
#     startTUNReader. A packet is "forwarded" when the hook admits it, "dropped" otherwise.
#   - Rate arithmetic used below: MBR 8000 kbps = 1000 bytes per ms. Bucket depth =
#     max(MBR_kbps * burst_ms, 4500 bytes * 8 bits) (qosBurstFloorBytes = 3 x 1500). Buckets start full.
#     With burst_ms 10: 8000 kbps -> 10000 bytes, 4000 kbps -> 5000 bytes, 2000 kbps -> 4500 bytes (floor).
#   - Counter: fivegc_upf_packet_drops_total{reason}; reasons "qer_mbr_exceeded" and "qer_gate_closed".
#     "increased by N" is relative to the value read in Background.
#   - Scenarios tagged @e2e @manual need the live UERANSIM stack and scripts/perf and are gated by
#     E2E_TEST=1 (reported pending/skipped when unset).

@UPF-005
Feature: UPF Session-AMBR and QER MBR enforcement in the GTP-U datapath
  As the UPF serving a PDU session
  I want to police uplink and downlink traffic against the Session-AMBR QER and the QoS-flow QERs
  So that a UE cannot exceed its authorized Session-AMBR or flow MBR

  Background:
    Given a UPF PFCP server with QoS knob "qos.mbr_enforcement" true and "qos.burst_ms" 10
    And the enforcement clock is at t=0 ms
    And the counter "fivegc_upf_packet_drops_total" is read for reasons "qer_mbr_exceeded" and "qer_gate_closed"

  # ---- Happy path: multi-QER provisioning (TS 29.244 §7.5.2.2, §7.5.2.5, §5.2.5) ----

  @happy
  Scenario: Session Establishment with a Session-AMBR QER and a QoS-flow QER is accepted and both QERs are stored
    # TS 29.244 §7.5.2.5: QER 1 carries the Session-AMBR (no QFI); QER 2 carries the QFI (no MBR, non-GBR)
    # TS 29.244 §7.5.2.2: Create PDR lists several QER ID IEs
    When the SMF sends a PFCP Session Establishment Request with
      | rule       | id | gate_ul | gate_dl | mbr_ul_kbps | mbr_dl_kbps | qfi    | pdr_qer_ids |
      | Create PDR | 1  |         |         |             |             |        | 1,2         |
      | Create QER | 1  | OPEN    | OPEN    | 8000        | 8000        | absent |             |
      | Create QER | 2  | OPEN    | OPEN    | absent      | absent      | 1      |             |
    Then the PFCP Session Establishment Response has Cause 1 "Request accepted"
    And the UPF session stores QER 1 with MBR UL 8000 kbps and MBR DL 8000 kbps and no QFI
    And the UPF session stores QER 2 with QFI 1 and no MBR
    And PDR 1 references QER IDs 1 and 2 in that order

  @happy
  Scenario: Downlink GTP-U PDU Session Container carries QFI 1 taken from the QoS-flow QER
    # TS 38.415 §5.5.2.1 / TS 29.244 §8.2.89: QFI comes from the QER that carries one (QER 2), not QER 1
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And the session has DL TEID 0x1001 and gNB address "172.30.3.10"
    When 1 packets of 500 bytes are offered downlink
    Then exactly 1 GTP-U datagram is sent to the gNB
    And the GTP-U TEID is 0x1001 and the PDU Session Container carries QFI 1

  # ---- Uplink Session-AMBR (TS 23.501 §5.7.1.8, TS 29.244 §5.4.4) ----

  @happy
  Scenario: Uplink traffic within the Session-AMBR is forwarded and not counted as dropped
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When 10 packets of 1000 bytes are offered uplink at t=0 ms
    Then 10 packets are forwarded and 0 packets are dropped
    And the drop counter with reason "qer_mbr_exceeded" has increased by 0

  @error
  Scenario: Uplink burst above the Session-AMBR is dropped with reason qer_mbr_exceeded
    # Depth 10000 bytes: 10 x 1000 B pass at t=0, the remaining 5 are policed
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When 15 packets of 1000 bytes are offered uplink at t=0 ms
    Then 10 packets are forwarded and 5 packets are dropped
    And the drop counter with reason "qer_mbr_exceeded" has increased by 5
    And the drop counter with reason "qer_gate_closed" has increased by 0

  @error
  Scenario: Uplink tokens refill at the Session-AMBR rate as the clock advances
    # 8000 kbps = 1000 bytes per ms: after 3 ms exactly 3 x 1000 B are admitted again
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And 10 packets of 1000 bytes were offered uplink at t=0 ms
    When the clock advances by 3 ms
    And 5 packets of 1000 bytes are offered uplink
    Then 3 packets are forwarded and 2 packets are dropped
    And the drop counter with reason "qer_mbr_exceeded" has increased by 2

  @error
  Scenario: A policed uplink packet consumes no URR volume
    # AmbrEnforcement.md "URR interaction": policed packets are not counted in the usage report
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When 15 packets of 1000 bytes are offered uplink at t=0 ms
    Then the session UL volume equals 10000 bytes

  # ---- Downlink Session-AMBR ----

  @happy
  Scenario: Downlink traffic within the Session-AMBR is forwarded
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And the session has DL TEID 0x1001 and gNB address "172.30.3.10"
    When 10 packets of 1000 bytes are offered downlink at t=0 ms
    Then 10 packets are forwarded and 0 packets are dropped
    And exactly 10 GTP-U datagrams are sent to the gNB

  @error
  Scenario: Downlink burst above the Session-AMBR is dropped with reason qer_mbr_exceeded
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And the session has DL TEID 0x1001 and gNB address "172.30.3.10"
    When 15 packets of 1000 bytes are offered downlink at t=0 ms
    Then 10 packets are forwarded and 5 packets are dropped
    And the drop counter with reason "qer_mbr_exceeded" has increased by 5
    And exactly 10 GTP-U datagrams are sent to the gNB
    And the session DL volume equals 10000 bytes

  @error
  Scenario: Uplink and downlink use independent buckets with the per-direction MBR
    # TS 29.244 §8.2.8: UL and DL MBR are separate fields. UL 8000 kbps -> 10000 B, DL 4000 kbps -> 5000 B
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000 kbps UL, 4000 kbps DL, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And the session has DL TEID 0x1001 and gNB address "172.30.3.10"
    When 10 packets of 1000 bytes are offered uplink at t=0 ms
    And 10 packets of 1000 bytes are offered downlink at t=0 ms
    Then the uplink result is 10 forwarded and 0 dropped
    And the downlink result is 5 forwarded and 5 dropped
    And the drop counter with reason "qer_mbr_exceeded" has increased by 5

  @error
  Scenario: UPF-originated downlink traffic is exempt from policing
    # AmbrEnforcement.md "UL vs DL": SendDownlink/sendGTPU (RA, ICMP echo reply) is not N6 user traffic
    Given a PFCP session with Session-AMBR QER 1 (MBR 2000/2000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And the session has DL TEID 0x1001 and gNB address "172.30.3.10"
    And 3 packets of 1500 bytes were offered downlink at t=0 ms so the DL bucket is empty
    When the UPF sends an ICMPv6 Router Advertisement to the UE via sendGTPU
    Then exactly 1 more GTP-U datagram is sent to the gNB
    And the drop counter with reason "qer_mbr_exceeded" has increased by 0

  # ---- Multiple QERs per PDR: all must pass (TS 29.244 §5.2.5) ----

  @happy
  Scenario: A per-flow QER MBR more restrictive than the Session-AMBR wins
    # QER 1 8000 kbps (10000 B), QER 2 4000 kbps (5000 B): packet must pass both -> 5 pass
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, MBR 4000/4000 kbps) on PDR 1
    When 10 packets of 1000 bytes are offered uplink at t=0 ms
    Then 5 packets are forwarded and 5 packets are dropped
    And the drop counter with reason "qer_mbr_exceeded" has increased by 5

  @happy
  Scenario: A Session-AMBR more restrictive than the per-flow QER MBR wins
    # QER 1 4000 kbps (5000 B), QER 2 8000 kbps (10000 B) -> 5 pass
    Given a PFCP session with Session-AMBR QER 1 (MBR 4000/4000 kbps, no QFI) and flow QER 2 (QFI 1, MBR 8000/8000 kbps) on PDR 1
    When 10 packets of 1000 bytes are offered downlink at t=0 ms
    Then 5 packets are forwarded and 5 packets are dropped
    And the drop counter with reason "qer_mbr_exceeded" has increased by 5

  @error
  Scenario: A packet dropped by the Session-AMBR does not consume the per-flow QER budget
    # AmbrEnforcement.md step 3 "refund": flow QER 2 8000 kbps (10000 B), Session-AMBR 4000 kbps (5000 B).
    # 10 packets: 5 pass; packets 6-10 pass QER 2 first, are rejected by QER 1 and must be refunded.
    # After Remove QER 1 only QER 2 applies: it must still hold 5000 B, so 5 x 1000 B pass and 1 is dropped.
    Given a PFCP session with Session-AMBR QER 1 (MBR 4000/4000 kbps, no QFI) and flow QER 2 (QFI 1, MBR 8000/8000 kbps) on PDR 1
    And 10 packets of 1000 bytes were offered uplink at t=0 ms
    When the SMF sends a PFCP Session Modification Request with Remove QER 1 and Update PDR 1 QER list "2"
    And 6 packets of 1000 bytes are offered uplink
    Then the PFCP Session Modification Response has Cause 1 "Request accepted"
    And 5 packets are forwarded and 1 packets are dropped

  @happy
  Scenario: The Session-AMBR bucket is shared across all PDRs that reference QER 1
    # TS 29.244 §7.5.2.5: the Session-AMBR QER is referenced by the PDRs of all non-GBR flows
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI), flow QER 2 (QFI 1, no MBR) on PDR 1 and flow QER 3 (QFI 5, no MBR) on PDR 2 that also references QER 1
    When 6 packets of 1000 bytes are offered uplink matching PDR 1 at t=0 ms
    And 6 packets of 1000 bytes are offered uplink matching PDR 2 at t=0 ms
    Then 10 packets are forwarded and 2 packets are dropped
    And the drop counter with reason "qer_mbr_exceeded" has increased by 2

  # ---- Update QER (TS 29.244 §7.5.4.5) ----

  @happy
  Scenario: Update QER lowering the Session-AMBR takes effect for new traffic
    # Bucket tokens are clamped to the new depth (no refill): 8000 -> 4000 kbps gives depth 5000 B
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Modification Request with Update QER 1 MBR 4000 kbps UL and 4000 kbps DL and no QFI
    Then the PFCP Session Modification Response has Cause 1 "Request accepted"
    When 10 packets of 1000 bytes are offered uplink at t=0 ms
    Then 5 packets are forwarded and 5 packets are dropped

  @happy
  Scenario: Update QER raising the Session-AMBR admits more traffic once tokens refill
    Given a PFCP session with Session-AMBR QER 1 (MBR 4000/4000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And 10 packets of 1000 bytes were offered uplink at t=0 ms
    When the SMF sends a PFCP Session Modification Request with Update QER 1 MBR 16000 kbps UL and 16000 kbps DL and no QFI
    And the clock advances by 5 ms
    And 10 packets of 1000 bytes are offered uplink
    Then the PFCP Session Modification Response has Cause 1 "Request accepted"
    And 10 packets are forwarded and 0 packets are dropped

  @happy
  Scenario: Update QER for QER 1 leaves QER 2 and its QFI unchanged
    # TS 29.244 §7.5.4.5: only IEs that are present overwrite; other QERs are untouched
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Modification Request with Update QER 1 MBR 4000 kbps UL and 4000 kbps DL and no QFI
    Then the UPF session stores QER 2 with QFI 1 and no MBR
    And the UPF session stores QER 1 with MBR UL 4000 kbps and MBR DL 4000 kbps and no QFI

  @happy
  Scenario: Update QER without an MBR IE keeps the stored MBR
    # TS 29.244 §7.5.4.5: an absent conditional IE leaves the stored value unchanged
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Modification Request with Update QER 1 Gate Status UL OPEN DL OPEN and no MBR
    And 15 packets of 1000 bytes are offered uplink at t=0 ms
    Then the PFCP Session Modification Response has Cause 1 "Request accepted"
    And 10 packets are forwarded and 5 packets are dropped

  # ---- Gate Status (TS 29.244 §5.4.3, §8.2.7) ----

  @error
  Scenario: Uplink gate CLOSED drops uplink packets with reason qer_gate_closed and consumes no tokens
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And the session has DL TEID 0x1001 and gNB address "172.30.3.10"
    When the SMF sends a PFCP Session Modification Request with Update QER 2 Gate Status UL CLOSED DL OPEN
    And 4 packets of 1000 bytes are offered uplink at t=0 ms
    Then 0 packets are forwarded and 4 packets are dropped
    And the drop counter with reason "qer_gate_closed" has increased by 4
    And the drop counter with reason "qer_mbr_exceeded" has increased by 0
    And the QER 1 uplink bucket still holds 10000 bytes of tokens

  @error
  Scenario: Uplink gate CLOSED does not affect the downlink direction
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And the session has DL TEID 0x1001 and gNB address "172.30.3.10"
    When the SMF sends a PFCP Session Modification Request with Update QER 2 Gate Status UL CLOSED DL OPEN
    And 4 packets of 1000 bytes are offered downlink at t=0 ms
    Then 4 packets are forwarded and 0 packets are dropped
    And the drop counter with reason "qer_gate_closed" has increased by 0

  @error
  Scenario: Downlink gate CLOSED drops downlink packets with reason qer_gate_closed
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And the session has DL TEID 0x1001 and gNB address "172.30.3.10"
    When the SMF sends a PFCP Session Modification Request with Update QER 1 Gate Status UL OPEN DL CLOSED
    And 4 packets of 1000 bytes are offered downlink at t=0 ms
    Then 0 packets are forwarded and 4 packets are dropped
    And the drop counter with reason "qer_gate_closed" has increased by 4
    And exactly 0 GTP-U datagrams are sent to the gNB

  @error
  Scenario: Reopening a closed gate restores forwarding
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    And the SMF has sent Update QER 2 Gate Status UL CLOSED DL CLOSED
    When the SMF sends a PFCP Session Modification Request with Update QER 2 Gate Status UL OPEN DL OPEN
    And 3 packets of 1000 bytes are offered uplink at t=0 ms
    Then 3 packets are forwarded and 0 packets are dropped

  @error
  Scenario: Gate Status with a spare value is interpreted as CLOSED
    # TS 29.244 §8.2.7 (Tables 8.2.7-1/-2): spare values 2 and 3 shall not be sent; if received they are
    # interpreted as 1 (CLOSED). The UPF still logs a WARN. The DL gate (OPEN) is unaffected.
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Modification Request with Update QER 2 Gate Status octet with spare UL value 2 and DL OPEN
    And 3 packets of 1000 bytes are offered uplink at t=0 ms
    Then the PFCP Session Modification Response has Cause 1 "Request accepted"
    And 0 packets are forwarded and 3 packets are dropped
    And the drop counter with reason "qer_gate_closed" has increased by 3
    And the drop counter with reason "qer_mbr_exceeded" has increased by 0
    And the UPF logged a WARN for QER 2 Gate Status

  # ---- Unlimited MBR values (TS 29.244 §7.5.2.5; local policy, AmbrEnforcement.md "Deviations" #2) ----

  @happy
  Scenario Outline: MBR "<case>" means not limited
    # Absent IE is spec-backed (§7.5.2.5); 0 and >= 0xFFFFFFFF kbps are local policy (gtpu-bench compatibility)
    Given a PFCP session whose only QER 1 has QFI 1 and MBR "<mbr>"
    When 100 packets of 1500 bytes are offered uplink at t=0 ms
    And 100 packets of 1500 bytes are offered downlink at t=0 ms
    Then the uplink result is 100 forwarded and 0 dropped
    And the downlink result is 100 forwarded and 0 dropped
    And the drop counter with reason "qer_mbr_exceeded" has increased by 0

    Examples:
      | case                | mbr             |
      | MBR IE absent       | absent          |
      | MBR 0 kbps          | 0/0             |
      | MBR 0xFFFFFFFF kbps | 4294967295/4294967295 |

  @happy
  Scenario: MBR 0 in one direction is unlimited only in that direction
    Given a PFCP session whose only QER 1 has QFI 1 and MBR "8000/0"
    When 15 packets of 1000 bytes are offered uplink at t=0 ms
    And 15 packets of 1000 bytes are offered downlink at t=0 ms
    Then the uplink result is 10 forwarded and 5 dropped
    And the downlink result is 15 forwarded and 0 dropped

  @happy
  Scenario: Legacy single-QER peer (QFI 1 with MBR 0xFFFFFFFF, as tools/gtpu-bench sends) keeps working
    # Backward compatibility: one Create QER {QER ID 1, Gate OPEN/OPEN, MBR max, QFI 1}, PDR with one QER ID
    When the SMF sends a PFCP Session Establishment Request with
      | rule       | id | gate_ul | gate_dl | mbr_ul_kbps | mbr_dl_kbps | qfi | pdr_qer_ids |
      | Create PDR | 1  |         |         |             |             |     | 1           |
      | Create QER | 1  | OPEN    | OPEN    | 4294967295  | 4294967295  | 1   |             |
    Then the PFCP Session Establishment Response has Cause 1 "Request accepted"
    And the UPF session stores QER 1 with QFI 1
    When the session has DL TEID 0x1001 and gNB address "172.30.3.10"
    And 200 packets of 1500 bytes are offered downlink at t=0 ms
    Then 200 packets are forwarded and 0 packets are dropped
    And the GTP-U TEID is 0x1001 and the PDU Session Container carries QFI 1

  @happy
  Scenario: Burst depth never drops below one MTU-sized burst floor
    # qosBurstFloorBytes = 3 x 1500: MBR 2000 kbps x 10 ms = 2500 B < 4500 B floor, so depth is 4500 B
    Given a PFCP session with Session-AMBR QER 1 (MBR 2000/2000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When 5 packets of 1500 bytes are offered uplink at t=0 ms
    Then 3 packets are forwarded and 2 packets are dropped

  @happy
  Scenario: An idle bucket never holds more than its depth
    # Idle for 10 s must not accumulate credit beyond depth (10000 B): overflow clamp
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the clock advances by 10000 ms
    And 15 packets of 1000 bytes are offered uplink
    Then 10 packets are forwarded and 5 packets are dropped

  # ---- Config knob qos.mbr_enforcement ----

  @error
  Scenario: Knob qos.mbr_enforcement=false disables MBR policing at line rate
    Given a UPF PFCP server with QoS knob "qos.mbr_enforcement" false and "qos.burst_ms" 10
    And a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When 100 packets of 1000 bytes are offered uplink at t=0 ms
    Then 100 packets are forwarded and 0 packets are dropped
    And the drop counter with reason "qer_mbr_exceeded" has increased by 0

  @error
  Scenario: Knob qos.mbr_enforcement=false still enforces Gate Status CLOSED
    # AmbrEnforcement.md: gating (TS 29.244 §5.4.3) is a different function from MBR policing
    Given a UPF PFCP server with QoS knob "qos.mbr_enforcement" false and "qos.burst_ms" 10
    And a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Modification Request with Update QER 2 Gate Status UL CLOSED DL OPEN
    And 4 packets of 1000 bytes are offered uplink at t=0 ms
    Then 0 packets are forwarded and 4 packets are dropped
    And the drop counter with reason "qer_gate_closed" has increased by 4

  # ---- Remove QER (TS 29.244 §7.5.4.9) ----

  @happy
  Scenario: Remove QER of the Session-AMBR QER removes its enforcement
    Given a PFCP session with Session-AMBR QER 1 (MBR 4000/4000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Modification Request with Remove QER 1 and Update PDR 1 QER list "2"
    And 100 packets of 1000 bytes are offered uplink at t=0 ms
    Then the PFCP Session Modification Response has Cause 1 "Request accepted"
    And the UPF session no longer stores QER 1
    And 100 packets are forwarded and 0 packets are dropped

  # ---- Session lifecycle ----

  @happy
  Scenario: Create QER inside a Session Modification adds a new QER that is enforced
    # TS 29.244 §7.5.4: Create QER is allowed in a Session Modification Request
    Given a PFCP session whose only QER 1 has QFI 1 and MBR "absent"
    When the SMF sends a PFCP Session Modification Request with Create QER 3 Gate OPEN/OPEN MBR 4000/4000 kbps and Update PDR 1 QER list "1,3"
    And 10 packets of 1000 bytes are offered uplink at t=0 ms
    Then the PFCP Session Modification Response has Cause 1 "Request accepted"
    And 5 packets are forwarded and 5 packets are dropped

  @happy
  Scenario: PFCP Session Deletion removes the session and its QoS state
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Deletion Request
    Then the PFCP Session Deletion Response has Cause 1 "Request accepted"
    And the UPF has no session for the SEID

  # ---- Spec-deviation rejections (TS 29.244 §8.2.1 cause values) ----

  @rejection
  Scenario: Update QER for an unknown QER ID is rejected with Cause 73 and a Failed Rule ID
    # Cause 73 = Rule creation/modification Failure; Failed Rule ID {Rule ID Type QER, 99}
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Modification Request with Update QER 99 MBR 1000 kbps UL and 1000 kbps DL
    Then the PFCP Session Modification Response has Cause 73 "Rule creation/modification Failure"
    And the response carries Failed Rule ID with Rule ID Type "QER" and Rule ID 99
    And the UPF session still stores QER 1 with MBR UL 8000 kbps and MBR DL 8000 kbps and no QFI

  @rejection
  Scenario: A Session Modification with one valid and one invalid Update QER applies nothing
    # AmbrEnforcement.md: no partial application; validate all rules first
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Modification Request with Update QER 1 MBR 4000 kbps UL and 4000 kbps DL and Update QER 99 MBR 1000 kbps UL and 1000 kbps DL
    Then the PFCP Session Modification Response has Cause 73 "Rule creation/modification Failure"
    And the UPF session still stores QER 1 with MBR UL 8000 kbps and MBR DL 8000 kbps and no QFI
    When 15 packets of 1000 bytes are offered uplink at t=0 ms
    Then 10 packets are forwarded and 5 packets are dropped

  @rejection
  Scenario: Remove QER for an unknown QER ID is rejected with Cause 73
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Modification Request with Remove QER 99
    Then the PFCP Session Modification Response has Cause 73 "Rule creation/modification Failure"
    And the response carries Failed Rule ID with Rule ID Type "QER" and Rule ID 99
    And the UPF session still stores QER 1 and QER 2

  @rejection
  Scenario: Remove QER still referenced by a PDR is rejected with Cause 73
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When the SMF sends a PFCP Session Modification Request with Remove QER 1 only
    Then the PFCP Session Modification Response has Cause 73 "Rule creation/modification Failure"
    And the response carries Failed Rule ID with Rule ID Type "QER" and Rule ID 1
    And PDR 1 references QER IDs 1 and 2 in that order

  @rejection
  Scenario: Create PDR referencing a missing QER rejects the Session Establishment with Cause 73
    # AmbrEnforcement.md: never install a PDR with a dangling QER reference
    When the SMF sends a PFCP Session Establishment Request with
      | rule       | id | gate_ul | gate_dl | mbr_ul_kbps | mbr_dl_kbps | qfi    | pdr_qer_ids |
      | Create PDR | 1  |         |         |             |             |        | 1,2         |
      | Create QER | 1  | OPEN    | OPEN    | 8000        | 8000        | absent |             |
    Then the PFCP Session Establishment Response has Cause 73 "Rule creation/modification Failure"
    And the UPF has no session for the requested CP F-SEID

  @rejection
  Scenario: Create QER without a QER ID rejects the Session Establishment with Cause 66
    # TS 29.244 §8.2.1 Cause 66 Mandatory IE missing, Offending IE = QER ID (type 109)
    When the SMF sends a PFCP Session Establishment Request with a Create QER that has Gate Status OPEN/OPEN and MBR 8000/8000 kbps but no QER ID
    Then the PFCP Session Establishment Response has Cause 66 "Mandatory IE missing"
    And the response carries Offending IE type 109
    And the UPF has no session for the requested CP F-SEID

  @rejection
  Scenario: Duplicate QER ID in one Session Establishment is rejected with Cause 73
    # TS 29.244 §7.5.2.5: QER ID is unique within the PFCP session
    When the SMF sends a PFCP Session Establishment Request with
      | rule       | id | gate_ul | gate_dl | mbr_ul_kbps | mbr_dl_kbps | qfi    | pdr_qer_ids |
      | Create PDR | 1  |         |         |             |             |        | 1           |
      | Create QER | 1  | OPEN    | OPEN    | 8000        | 8000        | absent |             |
      | Create QER | 1  | OPEN    | OPEN    | 4000        | 4000        | 1      |             |
    Then the PFCP Session Establishment Response has Cause 73 "Rule creation/modification Failure"
    And the response carries Failed Rule ID with Rule ID Type "QER" and Rule ID 1
    And the UPF has no session for the requested CP F-SEID

  @rejection
  Scenario: Session Modification for an unknown SEID is rejected with Cause 65
    # Existing behaviour, unchanged by UPF-005
    When the SMF sends a PFCP Session Modification Request with Update QER 1 MBR 1000 kbps UL and 1000 kbps DL for an unknown UP SEID
    Then the PFCP Session Modification Response has Cause 65 "Session context not found"

  @rejection
  Scenario: Create QER without Gate Status is accepted leniently with gates defaulting to OPEN
    # AmbrEnforcement.md edge case "Lenient MVP": WARN logged, gates default to OPEN
    When the SMF sends a PFCP Session Establishment Request with
      | rule       | id | gate_ul | gate_dl | mbr_ul_kbps | mbr_dl_kbps | qfi | pdr_qer_ids |
      | Create PDR | 1  |         |         |             |             |     | 1           |
      | Create QER | 1  | absent  | absent  | 8000        | 8000        | 1   |             |
    Then the PFCP Session Establishment Response has Cause 1 "Request accepted"
    And the UPF logged a WARN for QER 1 Gate Status
    When 3 packets of 1000 bytes are offered uplink at t=0 ms
    Then 3 packets are forwarded and 0 packets are dropped

  # ---- Observability ----

  @happy
  Scenario: QER provisioning is logged with the canonical AmbrEnforcement fields
    # CLAUDE.md logging contract; spec_ref per operation, never per packet
    When the SMF sends a PFCP Session Establishment Request with
      | rule       | id | gate_ul | gate_dl | mbr_ul_kbps | mbr_dl_kbps | qfi    | pdr_qer_ids |
      | Create PDR | 1  |         |         |             |             |        | 1,2         |
      | Create QER | 1  | OPEN    | OPEN    | 8000        | 8000        | absent |             |
      | Create QER | 2  | OPEN    | OPEN    | absent      | absent      | 1      |             |
    Then the UPF logs a line with nf "UPF", procedure "AmbrEnforcement", interface "N4", direction "IN" and spec_ref "TS 29.244 §7.5.2.5"
    And that log line carries seid, qer_id, mbr_ul_kbps and mbr_dl_kbps

  @error
  Scenario: Policed packets produce no per-packet INFO log
    # UPF CLAUDE.md §3d: never log per packet at INFO
    Given a PFCP session with Session-AMBR QER 1 (MBR 8000/8000 kbps, no QFI) and flow QER 2 (QFI 1, no MBR) on PDR 1
    When 1000 packets of 1000 bytes are offered uplink at t=0 ms
    Then the UPF emitted no INFO-level log line during the offered traffic

  # ---- Live acceptance criteria (manual; scripts/perf, docs/performance/user-plane-throughput.md) ----

  @e2e @manual
  Scenario: TCP throughput is capped near the lowered Session-AMBR in both directions
    # Acceptance criterion 2; Test plan live step 1-2: Session-AMBR 20 Mb/s UL / 30 Mb/s DL
    Given E2E_TEST is set to "1" and the UERANSIM stack is up with the subscriber Session-AMBR set to 20 Mbps UL and 30 Mbps DL
    When "make perf-dn" and "make ueransim-iperf" are run
    Then TCP UL throughput is between 0.85 and 1.0 times 20 Mbps
    And TCP DL throughput is between 0.85 and 1.0 times 30 Mbps
    And the UPF counter "fivegc_upf_packet_drops_total" with reason "qer_mbr_exceeded" has increased

  @e2e @manual
  Scenario: A QoS modification changing the Session-AMBR moves the cap
    # Test plan live step 3
    Given E2E_TEST is set to "1" and the UERANSIM stack is up with a PDU session capped at 20 Mbps UL
    When a QoS modification raises the Session-AMBR via POST /nsmf-management/v1/sessions/{psi}/qos
    Then the UPF logs procedure "AmbrEnforcement" with the new mbr_ul_kbps and mbr_dl_kbps
    And the measured throughput follows the new cap

  @e2e @manual
  Scenario: gtpu-bench knee does not regress with unlimited MBR sessions
    # Test plan live step 4: MBR 0xFFFFFFFF -> nil bucket, zero per-packet cost
    Given E2E_TEST is set to "1" and the perf profile is up
    When "make perf-bench" is run
    Then the knee matches the UPF-004 baseline within noise
    And no packets are dropped with reason "qer_mbr_exceeded"
