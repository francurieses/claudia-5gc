Feature: IPv6 / IPv4v6 PDU session prefix delegation
  As the SMF
  I want to grant the appropriate PDU session type and address material
  So that UEs can establish IPv6 and IPv4v6 sessions per TS 23.501 §5.8.2

  # The /64 prefix is delivered to the UE via Router Advertisement on the UPF
  # data plane (escalated, UPF-001). These scenarios cover the SMF control-plane
  # decision + the NAS PDU Address IE encoding (TS 24.501 §9.11.4.10).

  Scenario: IPv4 request on any DNN is granted IPv4 (no regression)
    Given a DNN "internet" with an IPv4 pool and no IPv6 prefix
    When a UE requests PDU session type "IPv4"
    Then the granted PDU session type is "IPv4"
    And the PDU Address IE has type octet "0x01" and 4 address octets

  Scenario: IPv6 request on an IPv6-capable DNN is granted IPv6
    Given a DNN "ims" with an IPv4 pool and an IPv6 prefix "2001:db8:61::/56"
    When a UE requests PDU session type "IPv6"
    Then the granted PDU session type is "IPv6"
    And the PDU Address IE has type octet "0x02" and 8 address octets
    And the PDU Address IE address octets carry the interface identifier, not the /64 prefix

  Scenario: IPv4v6 request on an IPv6-capable DNN is granted IPv4v6
    Given a DNN "ims" with an IPv4 pool and an IPv6 prefix "2001:db8:61::/56"
    When a UE requests PDU session type "IPv4v6"
    Then the granted PDU session type is "IPv4v6"
    And the PDU Address IE has type octet "0x03" and 12 address octets

  Scenario: IPv6 request on an IPv4-only DNN downgrades to IPv4
    Given a DNN "internet" with an IPv4 pool and no IPv6 prefix
    When a UE requests PDU session type "IPv6"
    Then the granted PDU session type is "IPv4"

  Scenario: IPv4v6 request on an IPv4-only DNN downgrades to IPv4
    Given a DNN "internet" with an IPv4 pool and no IPv6 prefix
    When a UE requests PDU session type "IPv4v6"
    Then the granted PDU session type is "IPv4"

  Scenario: An IPv6 /64 pool allocates distinct prefixes and reclaims them
    Given an IPv6 pool over "2001:db8:61::/56"
    When two /64 prefixes are allocated
    Then the two prefixes are distinct and inside the pool
    When the first prefix is released and a third is allocated
    Then the third prefix reuses the released /64
