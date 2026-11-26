@sepp @n32 @interop @SEPP-005
Feature: N32 roaming interface ready by default with per-PLMN trust and a documented interop profile (TS 33.501 §13.1.2; TS 29.573 §5.2.2, §6.1.5.2, §6.1.7; TS 23.003 §28.5)
  As an operator of the local core
  I want the SEPP to start N32-ready without any roaming partner and to add partners by configuration only
  So that a real partner SEPP can interconnect without code changes and every partner is trusted only through its own PLMN trust anchor

  # SPEC mode (SEPP-005, folds SEPP-004): scenarios only, step definitions follow in STEPS mode.
  # Design: docs/procedures/N32InteropReadiness.md (errors E1-E13, items S1-S5), .tmp/sepp005/DESIGN.md.
  # Steps of n32_handshake.feature are reused where they match (peer sends POST ... with SecNegotiateReqData,
  # the response status is N, the response body is SecNegotiateRspData ..., the response "k" is v).
  # The SBI CA is never part of any N32 trust pool. Metric: fivegc_sepp_n32_tls_reject_total{reason}.
  # Items marked [VERIFY] in the procedure doc (S1, S2 allowed set, S3 status, S4, S5) are project policy.

  Background:
    Given the local SEPP serves PLMN "001/01" with SEPP FQDN "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    And the local SEPP has an own N32 certificate issued by the N32 CA of the local core
    And the SEPP runs with the "rel19" release profile

  # ------------------------------------------------------------ default start (AC1)
  @happy @startup
  Scenario: Default start without any roaming partner leaves the N32 responder ready and quiet
    Given no roaming partners file exists
    And the SEPP config has no inline partners
    When the SEPP starts
    Then the SEPP is healthy
    And the N32 listener is started on port 8443
    And no N32-c initiator runs
    And the SEPP log has no WARN or ERROR line
    And the admin endpoint GET "/admin/v1/n32/partners" returns an empty "partners" list

  @startup
  Scenario: Default start without partners and without an own N32 certificate does not start the listener
    Given no roaming partners file exists
    And the SEPP config has no inline partners
    And the own N32 certificate files do not exist
    When the SEPP starts
    Then the SEPP is healthy
    And the N32 listener is not started
    And the SEPP log has exactly one INFO line stating that N32 is disabled
    And the SEPP log has no WARN or ERROR line

  @error @trust
  Scenario: A handshake is rejected when no partner is configured (E2)
    Given no roaming partners file exists
    And the SEPP config has no inline partners
    And the SEPP has started
    When a peer connects to the N32 listener with a certificate of PLMN "001/02" issued by the test peer CA
    Then the TLS handshake fails with alert "bad_certificate"
    And the metric "fivegc_sepp_n32_tls_reject_total" with reason "not_partner" increases by 1
    And the SEPP log has cause "n32_tls_not_partner"

  # ------------------------------------------------------------ partners (AC2)
  @happy @partners
  Scenario: Partner from the partners file is accepted and the N32-c initiator runs
    Given a roaming partners file with partner PLMN "001/02", n32 ca_file of the test peer CA and address "sepp.5gc.mnc002.mcc001.3gppnetwork.org:8443"
    When the SEPP starts
    Then the SEPP is healthy
    And an N32-c initiator runs towards PLMN "001/02"
    And the admin endpoint GET "/admin/v1/n32/partners" lists partner "001-02" with source "file"
    And a peer holding a certificate of PLMN "001/02" issued by the test peer CA completes the TLS handshake with the N32 listener

  @partners
  Scenario: Partners file entry overrides the inline config entry of the same PLMN
    Given the SEPP config has inline partner PLMN "001/02" with ca_file "/etc/5gc/pki/n32/peers/001-03/ca.crt"
    And a roaming partners file with partner PLMN "001/02", n32 ca_file "/etc/5gc/pki/n32/peers/001-02/ca.crt"
    When the SEPP starts
    Then the admin endpoint GET "/admin/v1/n32/partners" lists exactly one partner "001-02"
    And that partner has source "file" and caFile "/etc/5gc/pki/n32/peers/001-02/ca.crt"

  @partners
  Scenario: A missing partners file means no partners and is not an error
    Given the ROAMING_PARTNERS_FILE points to a file that does not exist
    When the SEPP starts
    Then the SEPP is healthy
    And the SEPP log has one INFO line stating that the partners file is absent
    And the admin endpoint GET "/admin/v1/n32/partners" returns an empty "partners" list

  @partners
  Scenario: The admin endpoint reports the effective partner list
    Given a roaming partners file with partner PLMN "001/02", n32 ca_file of the test peer CA, sepp_fqdn "sepp.5gc.mnc002.mcc001.3gppnetwork.org" and address "sepp.5gc.mnc002.mcc001.3gppnetwork.org:8443"
    And the SEPP config has inline partner PLMN "001/03" with a valid ca_file
    When the SEPP starts
    And a client sends GET "/admin/v1/n32/partners" on the metrics port
    Then the response status is 200
    And each entry of "partners" has the keys "plmn", "source", "caFile", "seppFqdn", "address", "anchorSubject", "anchorNotAfter"
    And the entry "001-02" has source "file" and the entry "001-03" has source "config"

  # ------------------------------------------------------------ fail closed (E12)
  @error @config
  Scenario Outline: SEPP refuses to start on an invalid roaming configuration (E12)
    Given <setup>
    When the SEPP starts
    Then the SEPP exits with status 1
    And the SEPP log has an ERROR line with cause "config_invalid" mentioning "<hint>"

    Examples:
      | setup                                                                                          | hint                       |
      | a roaming partners file that is not valid YAML                                                 | partners file              |
      | a roaming partners file with a partner whose n32 section has no ca_file                         | ca_file                    |
      | a roaming partners file with two entries for PLMN "001/02"                                      | duplicate                  |
      | the SEPP config contains the legacy key "n32.roaming_partners"                                  | n32.partners               |
      | the SEPP config contains the legacy key "n32.peers"                                             | n32.partners               |
      | the SEPP config contains the legacy key "n32.tls.ca_file"                                       | partners[].n32.ca_file     |
      | a valid partner exists and the own N32 certificate files do not exist                           | n32.tls.cert_file          |
      | a valid partner exists and the own N32 certificate SAN lacks the SEPP FQDN of PLMN "001/01"     | SAN                        |

  @error @config
  Scenario: Own N32 certificate is never taken from the SBI TLS configuration
    Given a valid partner exists
    And the own N32 certificate files do not exist
    And the SBI TLS certificate files exist
    When the SEPP starts
    Then the SEPP exits with status 1

  # ------------------------------------------------------------ per-PLMN trust (AC3, AC4)
  @trust @happy
  Scenario: Certificate of the partner PLMN signed by that partner's anchor is accepted
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    When a peer connects to the N32 listener with a certificate of PLMN "001/02" issued by "testpeer-ca"
    Then the TLS handshake succeeds

  @trust @rejection
  Scenario Outline: N32 TLS peer is rejected on trust grounds with a bounded metric reason
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the SEPP has partner PLMN "001/03" with anchor "other-ca"
    When a peer connects to the N32 listener with <certificate>
    Then the TLS handshake fails with alert "bad_certificate"
    And the metric "fivegc_sepp_n32_tls_reject_total" with reason "<reason>" increases by 1
    And the SEPP log has cause "<cause>"

    Examples:
      | certificate                                                                                  | reason          | cause                    |
      | a certificate of PLMN "001/03" signed by "testpeer-ca" (PLMN B cert on PLMN A anchor)        | chain           | n32_tls_chain            |
      | a certificate of PLMN "001/02" signed by the SBI CA                                          | chain           | n32_tls_chain            |
      | a certificate of PLMN "001/02" signed by an unknown CA                                       | chain           | n32_tls_chain            |
      | a certificate of PLMN "001/09" signed by "testpeer-ca" (non-partner PLMN)                    | not_partner     | n32_tls_not_partner      |
      | a certificate without any SAN of the form mncXXX.mccYYY.3gppnetwork.org                      | no_plmn         | n32_tls_no_plmn          |
      | a certificate with SAN PLMNs "001/02" and "001/03" that map to different anchors             | anchor_conflict | n32_tls_anchor_conflict  |

  @trust @rejection
  Scenario: The SBI CA is never accepted as an N32 trust anchor
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    When a peer connects to the N32 listener with a certificate of PLMN "001/02" signed by the SBI CA
    Then the TLS handshake fails
    And the N32 trust pool of PLMN "001/02" does not contain the SBI CA

  @trust @rejection
  Scenario: Peer without a client certificate is rejected before the trust check (E6)
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    When a peer connects to the N32 listener without a client certificate
    Then the TLS handshake fails
    And the SEPP log has cause "n32_tls_no_client_cert"

  @trust @rejection @initiator
  Scenario Outline: Client side rejects a server whose PLMN or FQDN is not the dialled partner (E5)
    Given the SEPP has partner PLMN "001/02" with sepp_fqdn "sepp.5gc.mnc002.mcc001.3gppnetwork.org" and anchor "testpeer-ca"
    And the dialled server presents <certificate>
    When the N32-c initiator dials partner "001/02"
    Then the initiator aborts the TLS handshake with alert "bad_certificate"
    And the metric "fivegc_sepp_n32_tls_reject_total" with reason "plmn_mismatch" increases by 1
    And the SEPP log has cause "n32_tls_plmn_mismatch"
    And the initiator does not retry

    Examples:
      | certificate                                                         |
      | a certificate of PLMN "001/03" signed by "testpeer-ca"              |
      | a certificate of PLMN "001/02" whose SAN is not the partner FQDN    |

  # ------------------------------------------------------------ N32-c (AC3, S1-S5)
  @n32c @happy
  Scenario Outline: SEPP offers the supportedFeatures of its release profile
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the SEPP runs with the "<profile>" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                     | sepp.5gc.mnc002.mcc001.3gppnetwork.org |
      | supportedSecCapabilityList | ["TLS"]                                |
      | targetPlmnId               | {"mcc":"001","mnc":"01"}               |
    Then the response status is 200
    And the response "supportedFeatures" is "<features>"

    Examples:
      | profile | features |
      | rel19   | 5        |
      | rel17   | 1        |

  @n32c @regression
  Scenario: Rel-17 handshake response without purposes is byte-identical to the golden file
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the SEPP runs with the "rel17" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                     | sepp.5gc.mnc002.mcc001.3gppnetwork.org |
      | supportedSecCapabilityList | ["TLS"]                                |
      | targetPlmnId               | {"mcc":"001","mnc":"01"}               |
    Then the response status is 200
    And the response body equals the golden file "n32c_exchange_capability_rel17.json"
    And the response has no "allowedUsagePurpose" and no "rejectedUsagePurpose"

  @n32c @purposes
  Scenario: Request without intendedUsagePurpose gets no purpose IEs (S2)
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                     | sepp.5gc.mnc002.mcc001.3gppnetwork.org |
      | supportedSecCapabilityList | ["TLS"]                                |
    Then the response status is 200
    And the response has no "allowedUsagePurpose" and no "rejectedUsagePurpose"

  @n32c @purposes
  Scenario Outline: intendedUsagePurpose is honoured per Table 6.1.5.2.3-1 (S2)
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the SEPP runs with the "<profile>" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                     | sepp.5gc.mnc002.mcc001.3gppnetwork.org |
      | supportedSecCapabilityList | ["TLS"]                                |
      | intendedUsagePurpose       | <requested>                            |
    Then the response status is <status>
    And the response "allowedUsagePurpose" is <allowed>
    And the response "rejectedUsagePurpose" is <rejected>

    Examples:
      | profile | requested                          | status | allowed                    | rejected                  |
      | rel19   | ["ROAMING","INTER_PLMN_MOBILITY"]  | 200    | ["ROAMING","INTER_PLMN_MOBILITY"] | absent             |
      | rel19   | ["ROAMING","SMS_ONLY"]             | 200    | ["ROAMING"]                | ["SMS_ONLY"]              |
      | rel17   | ["ROAMING","SMS_ONLY"]             | 200    | ["ROAMING"]                | ["SMS_ONLY"]              |
      | rel19   | ["SMS_ONLY"]                       | 403    | absent                     | absent                    |

  @n32c @rejection @purposes
  Scenario: All requested purposes rejected answers 403 REQUESTED_PURPOSE_NOT_ALLOWED (E10)
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                     | sepp.5gc.mnc002.mcc001.3gppnetwork.org |
      | supportedSecCapabilityList | ["TLS"]                                |
      | intendedUsagePurpose       | ["SMS_ONLY"]                           |
    Then the response status is 403
    And the response is ProblemDetails with cause "REQUESTED_PURPOSE_NOT_ALLOWED"
    And no N32 context exists for remote PLMN "001/02"
    And the SEPP log has cause "purpose_not_allowed" with result "REJECT"

  @n32c @rejection
  Scenario: targetPlmnId that is not the local PLMN is rejected (E8, S3)
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                     | sepp.5gc.mnc002.mcc001.3gppnetwork.org |
      | supportedSecCapabilityList | ["TLS"]                                |
      | targetPlmnId               | {"mcc":"001","mnc":"07"}               |
    Then the response status is 403
    And no N32 context exists for remote PLMN "001/02"
    And the SEPP log has cause "target_plmn_not_served" with result "REJECT"

  @n32c @sender
  Scenario Outline: sender is checked by home network domain suffix only (E9, S4)
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                     | <sender>                   |
      | supportedSecCapabilityList | ["TLS"]                    |
    Then the response status is <status>
    And the SEPP log has cause "<cause>"

    Examples:
      | sender                                          | status | cause                  |
      | sepp.5gc.mnc002.mcc001.3gppnetwork.org          | 200    | handshake_accepted     |
      | edge1.sepp.5gc.mnc002.mcc001.3gppnetwork.org    | 200    | handshake_accepted     |
      | sepp.5gc.mnc003.mcc001.3gppnetwork.org          | 403    | sender_domain_mismatch |
      | sepp.example.org                                | 403    | sender_domain_mismatch |

  @n32c @rejection
  Scenario: plmnIdList entry outside the certificate PLMN is rejected (E7, S5)
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                     | sepp.5gc.mnc002.mcc001.3gppnetwork.org            |
      | supportedSecCapabilityList | ["TLS"]                                           |
      | plmnIdList                 | [{"mcc":"001","mnc":"02"},{"mcc":"001","mnc":"05"}] |
    Then the response status is 403
    And no N32 context exists for remote PLMN "001/02"
    And the SEPP log has cause "plmn_mismatch" with result "REJECT"
    And the metric "fivegc_sepp_n32c_handshake_total" with result "REJECT" increases by 1

  @n32c @happy
  Scenario: plmnIdList equal to the certificate PLMN is accepted (S5)
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                     | sepp.5gc.mnc002.mcc001.3gppnetwork.org |
      | supportedSecCapabilityList | ["TLS"]                                |
      | plmnIdList                 | [{"mcc":"001","mnc":"02"}]             |
    Then the response status is 200
    And an N32 context exists for remote PLMN "001/02" with security capability "TLS"

  @n32c @rejection
  Scenario: No common security capability still answers 403 NEGOTIATION_NOT_ALLOWED (E11)
    Given the SEPP has partner PLMN "001/02" with anchor "testpeer-ca"
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                     | sepp.5gc.mnc002.mcc001.3gppnetwork.org |
      | supportedSecCapabilityList | ["PRINS"]                              |
    Then the response status is 403
    And the response is ProblemDetails with cause "NEGOTIATION_NOT_ALLOWED"
