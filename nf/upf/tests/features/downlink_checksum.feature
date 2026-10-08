# UPF Downlink L4 Checksum Repair — N6 -> N3 (task UPF-003)
#
# DESIGN STATUS: APPROVED and IMPLEMENTED (2026-10-04, human design sign-off) — see
# docs/procedures/DownlinkChecksum.md. Step definitions live in downlink_checksum_steps_test.go
# (run with `make -C nf/upf test-functional`).
#
# Spec refs: TS 29.281 §5 (G-PDU carries the T-PDU), TS 29.281 §5.1 (GTP-U header Length),
#            TS 38.415 §5.5.2.1 (DL PDU Session Information / QFI),
#            TS 23.501 §6.2.3 (UPF packet routing and forwarding),
#            RFC 793 §3.1 (TCP checksum), RFC 768 (UDP checksum), RFC 1071 (Internet checksum),
#            RFC 8200 §8.1 (IPv6 upper-layer checksums), RFC 1122 §4.2.2.7.
#
# Harness contract for the godog suite (in-process, no real network):
#   - "fake TUN"      : the test injects an inner IP packet as if read from the DNN TUN (startTUNReader).
#   - "captured GTP-U": the test captures the UDP/2152 datagram that sendGTPU would emit toward the gNB.
#   - A session exists for the UE address with a DL TEID and gNB address (repair runs after those checks).
#   - The counter is fivegc_upf_l4_checksum_repaired_total{proto,ip}.
#   - Scenarios tagged @e2e @manual need the live UERANSIM stack on Docker Desktop for Mac and are
#     gated by E2E_TEST=1 (reported pending/skipped when unset).

Feature: UPF downlink L4 checksum verify-and-repair on N6 -> N3
  As the UPF forwarding downlink traffic from N6 to the gNB over N3
  I want to repair invalid TCP/UDP checksums before GTP-U encapsulation
  So that a UE behind Docker Desktop's userspace network proxy can complete TCP handshakes with external servers

  Background:
    Given a UPF with an established PDU session for UE address "10.60.0.3" with DL TEID 0x1001, QFI 1 and gNB address "172.30.3.10"
    And the UPF knob "n6.l4_checksum_repair" is true
    And the counter "fivegc_upf_l4_checksum_repaired_total" is read for all proto and ip labels

  # ---- Happy path (acceptance: unit-level repair; GTP-U unchanged) ----

  Scenario: IPv4 TCP SYN-ACK with an invalid checksum is repaired and GTP-U is unchanged
    # RFC 793 §3.1, RFC 1071; TS 29.281 §5; TS 38.415 §5.5.2.1
    Given a downlink IPv4 TCP SYN-ACK from "1.1.1.1" to "10.60.0.3" with TCP checksum 0x4f8b but correct value 0x310a
    When the packet is read from the TUN
    Then exactly one GTP-U datagram is sent to the gNB
    And the inner TCP checksum in the datagram is 0x310a
    And the GTP-U TEID is 0x1001 and the PDU Session Container carries QFI 1
    And the GTP-U Length equals the inner packet length plus the extension header octets
    And all inner bytes except the TCP checksum are identical to the TUN packet
    And the counter with proto "tcp" and ip "v4" has increased by 1

  Scenario: IPv4 TCP packet with checksum 0x0000 that does not verify is repaired
    # RFC 793 §3.1: zero has no special meaning for TCP; "unset" is simply invalid
    Given a downlink IPv4 TCP segment to "10.60.0.3" with TCP checksum 0x0000 that does not verify
    When the packet is read from the TUN
    Then the inner TCP checksum in the sent datagram verifies over the pseudo-header and segment
    And the counter with proto "tcp" and ip "v4" has increased by 1

  # ---- Valid / no-op paths ----

  Scenario: IPv4 TCP packet with a valid checksum is forwarded byte-identical
    # RFC 1071 §1: a segment is valid iff the folded sum is 0xFFFF
    Given a downlink IPv4 TCP segment to "10.60.0.3" with a valid TCP checksum
    When the packet is read from the TUN
    Then the inner packet in the sent GTP-U datagram is byte-identical to the TUN packet
    And no counter with name "fivegc_upf_l4_checksum_repaired_total" has changed

  Scenario: IPv4 UDP packet with checksum 0x0000 is forwarded unchanged
    # RFC 768: zero over IPv4 means "no checksum transmitted"
    Given a downlink IPv4 UDP datagram to "10.60.0.3" with UDP checksum 0x0000
    When the packet is read from the TUN
    Then the inner packet in the sent GTP-U datagram is byte-identical to the TUN packet
    And no counter with name "fivegc_upf_l4_checksum_repaired_total" has changed

  Scenario: IPv4 UDP packet with a valid checksum is forwarded byte-identical
    # RFC 768, RFC 1071
    Given a downlink IPv4 UDP datagram to "10.60.0.3" with a valid UDP checksum
    When the packet is read from the TUN
    Then the inner packet in the sent GTP-U datagram is byte-identical to the TUN packet
    And no counter with name "fivegc_upf_l4_checksum_repaired_total" has changed

  # ---- UDP repair ----

  Scenario: IPv4 UDP packet with an invalid checksum is repaired
    # RFC 768, RFC 1071
    Given a downlink IPv4 UDP datagram to "10.60.0.3" with a non-zero UDP checksum that does not verify
    When the packet is read from the TUN
    Then the inner UDP checksum in the sent datagram verifies over the pseudo-header and datagram
    And the counter with proto "udp" and ip "v4" has increased by 1

  Scenario: IPv4 UDP repair whose computed checksum is 0x0000 is transmitted as 0xFFFF
    # RFC 768: a computed zero MUST be transmitted as all ones
    Given a downlink IPv4 UDP datagram to "10.60.0.3" whose correct checksum computes to 0x0000 and whose stored checksum is 0x1234
    When the packet is read from the TUN
    Then the inner UDP checksum in the sent datagram is 0xFFFF
    And the counter with proto "udp" and ip "v4" has increased by 1

  # ---- IPv6 (design open question 3: in scope, unit-tested only) ----

  Scenario Outline: IPv6 <proto> packet with an invalid checksum is repaired
    # RFC 8200 §8.1 pseudo-header; RFC 1071
    Given a downlink IPv6 <proto> packet to UE IPv6 prefix address "2001:db8:60::3" with an invalid <proto> checksum
    When the packet is read from the TUN
    Then the inner <proto> checksum in the sent datagram verifies over the IPv6 pseudo-header and segment
    And the counter with proto "<label>" and ip "v6" has increased by 1

    Examples:
      | proto | label |
      | TCP   | tcp   |
      | UDP   | udp   |

  Scenario: IPv6 UDP packet with checksum 0x0000 gets a computed checksum
    # RFC 8200 §8.1: UDP checksum is mandatory over IPv6, zero is invalid
    Given a downlink IPv6 UDP packet to UE IPv6 prefix address "2001:db8:60::3" with UDP checksum 0x0000
    When the packet is read from the TUN
    Then the inner UDP checksum in the sent datagram is non-zero and verifies over the IPv6 pseudo-header
    And the counter with proto "udp" and ip "v6" has increased by 1

  # ---- Error / rejection edges: ineligible packets are forwarded unchanged ----

  Scenario Outline: Ineligible packet "<case>" with a bad checksum is forwarded unchanged and not counted
    # Design doc error/edge table; RFC 791 §3.1 (fragmentation, lengths), RFC 8200 §4 (extension headers)
    Given a downlink packet of kind "<case>" to "10.60.0.3" carrying an invalid L4 checksum
    When the packet is read from the TUN
    Then the inner packet in the sent GTP-U datagram is byte-identical to the TUN packet
    And the UPF does not panic
    And no counter with name "fivegc_upf_l4_checksum_repaired_total" has changed

    Examples:
      | case                                      |
      | IPv4 fragment with MF=1                   |
      | IPv4 fragment with non-zero offset        |
      | truncated TCP header (less than 20 octets)|
      | truncated UDP header (less than 8 octets) |
      | IPv4 Total Length greater than read size  |
      | IPv6 Payload Length beyond read size      |
      | UDP Length not equal to IP-derived length |
      | IPv6 with Hop-by-Hop extension header     |
      | IPv6 with Fragment extension header       |
      | ICMP echo reply                           |
      | ICMPv6 echo reply                         |

  Scenario: Bytes beyond IPv4 Total Length are ignored when verifying
    # RFC 791 §3.1: trailing padding is not part of the datagram
    Given a downlink IPv4 TCP segment to "10.60.0.3" with an invalid checksum followed by 4 trailing padding octets after Total Length
    When the packet is read from the TUN
    Then the inner TCP checksum is repaired using only the octets within Total Length
    And the counter with proto "tcp" and ip "v4" has increased by 1

  Scenario: Downlink packet for an unknown UE address is dropped before any repair is attempted
    # Existing behaviour: repair runs after session lookup and DL tunnel readiness checks
    Given a downlink IPv4 TCP segment to "10.60.0.99" with an invalid TCP checksum and no session for that address
    When the packet is read from the TUN
    Then no GTP-U datagram is sent
    And no counter with name "fivegc_upf_l4_checksum_repaired_total" has changed

  # ---- Config knob ----

  Scenario: Knob n6.l4_checksum_repair=false makes the path a no-op
    # Design decision 3
    Given the UPF knob "n6.l4_checksum_repair" is false
    And a downlink IPv4 TCP SYN-ACK from "1.1.1.1" to "10.60.0.3" with TCP checksum 0x4f8b but correct value 0x310a
    When the packet is read from the TUN
    Then the inner packet in the sent GTP-U datagram is byte-identical to the TUN packet
    And no counter with name "fivegc_upf_l4_checksum_repaired_total" has changed

  # ---- UPF-built packets are not subject to repair ----

  Scenario: ICMP echo reply built by the UPF is not subject to repair
    # Design decision 1: repair is in startTUNReader, not in sendGTPU
    Given the UPF answers an ICMP echo request from UE "10.60.0.3" to the gateway with its own echo reply via sendGTPU
    Then the echo reply in the sent GTP-U datagram is exactly the packet the UPF built
    And no counter with name "fivegc_upf_l4_checksum_repaired_total" has changed

  Scenario: Router Advertisement built by the UPF is not subject to repair
    # Design decision 1; RFC 4861 RA built by the UPF RA advertiser
    Given the UPF sends an ICMPv6 Router Advertisement to the UE via sendGTPU
    Then the Router Advertisement in the sent GTP-U datagram is exactly the packet the UPF built
    And no counter with name "fivegc_upf_l4_checksum_repaired_total" has changed

  # ---- Live acceptance criteria (manual, Docker Desktop for Mac) ----

  @e2e @manual
  Scenario: UE reaches a TCP server on the Mac LAN address through its PDU session
    # Acceptance criterion 1; recipe steps 2-3
    Given E2E_TEST is set to "1" and the UERANSIM stack is up on Docker Desktop for Mac
    And a TCP server is listening on the Mac LAN address
    When the UE runs curl bound to "uesimtun0" against that server
    Then the HTTP response is received before the timeout

  @e2e @manual
  Scenario: UE reaches an internet TCP server through its PDU session
    # Acceptance criterion 1; recipe step 2
    Given E2E_TEST is set to "1" and the UERANSIM stack is up on Docker Desktop for Mac
    When the UE runs "curl --interface uesimtun0 -m 10 http://1.1.1.1/"
    Then an HTTP response is received

  @e2e @manual
  Scenario: UE Tcp and Udp InCsumErrors stay flat during external transfers
    # Acceptance criterion 2; recipe steps 1 and 4
    Given E2E_TEST is set to "1" and the UERANSIM stack is up on Docker Desktop for Mac
    And the UE /proc/net/snmp Tcp and Udp InCsumErrors are recorded
    When the UE completes an external TCP transfer and an external UDP transfer through the PDU session
    Then the Tcp InCsumErrors and Udp InCsumErrors values are unchanged
    And the UPF counter "fivegc_upf_l4_checksum_repaired_total" has increased on Docker Desktop

  @e2e @manual
  Scenario: Throughput on N6-bridge traffic does not regress
    # Acceptance criterion 3; recipe step 5; baseline TCP UL 105.75, TCP DL 108.26, UDP UL 108.03, UDP DL 108.43 Mbps
    Given E2E_TEST is set to "1" and the UERANSIM stack is up
    When "make ueransim-iperf" is run with the repair enabled
    Then TCP UL, TCP DL, UDP UL and UDP DL throughput show no material regression against the baseline
    And the repair counter stays 0 for N6-bridge-only traffic

  @e2e @manual
  Scenario: Portal iperf3 with a custom LAN or Mac host server IP succeeds
    # Acceptance criterion 4; recipe step 3 via the mgmt-portal UERANSim page
    Given E2E_TEST is set to "1" and the UERANSIM stack and mgmt-portal are up
    And iperf3 is listening on a LAN or Mac host address
    When the portal iperf3 test is started with that custom server IP
    Then the test completes with a non-zero throughput result

  @e2e @manual
  Scenario: Disabling the knob reproduces the defect (negative control)
    # Recipe step 6
    Given E2E_TEST is set to "1" and the UPF is restarted with "n6.l4_checksum_repair" false on Docker Desktop for Mac
    When the UE runs "curl --interface uesimtun0 -m 10 http://1.1.1.1/"
    Then the request times out
    And the UE Tcp InCsumErrors value increases
