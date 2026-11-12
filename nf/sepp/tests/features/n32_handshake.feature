@sepp @n32c @REL19-9.2
Feature: SEPP N32-c Security Capability Negotiation and N32-f TLS teardown (TS 29.573 §5.2.2, §6.1.4.2; TS 33.501 §13.1.2)
  As the responding SEPP (hSEPP) of a roaming agreement
  I want to negotiate the N32-f security capability with a peer SEPP over mutually authenticated TLS
  So that only authorised roaming partners obtain an N32-f context, in the Rel-17 or the Rel-19 wire profile

  # SPEC mode (REL19-9.2): scenarios only, no step definitions yet (implemented by REL19-9.4).
  # Design: docs/procedures/n32-roaming-interconnect.md.
  # Operation: POST {apiRoot}/n32c-handshake/v1/exchange-capability (TS 29.573 §6.1.4.2),
  #            SecNegotiateReqData / SecNegotiateRspData per TS29573_N32_Handshake.yaml.
  # This increment is TLS mode only: the SEPP never offers or selects PRINS.
  # ProblemDetails causes (verified against TS 29.573 V19.7.0 / TS 29.500 V17.16.0 + V19.7.1):
  #   - 403 NEGOTIATION_NOT_ALLOWED: no common security capability (TS 29.573 §6.1.4.2.2 Table -2, §6.1.6.3).
  #     Asserted for rel19; the Rel-17 TS 29.573 text is not available locally, so rel17 asserts 403 only.
  #   - 409 N32C_EXCHANGE_CAPABILITY_ONGOING: collision (§5.2.2 step 2b); CR 0150, V18.5.0, so rel19 only.
  #   - 400 MANDATORY_IE_MISSING / MANDATORY_IE_INCORRECT / INVALID_MSG_FORMAT: TS 29.500 Table 5.2.7.2-1.
  #   (There is no TS 29.573 §6.1.7.3; §6.1.7 is Feature Negotiation, application errors are §6.1.6.3.)
  # TLS-mode teardown (TS 29.573 §5.2.2): exchange-capability with supportedSecCapabilityList ["NONE"],
  #   only if the remote SEPP indicated feature NFTLST (supportedFeatures bit 1, §6.1.7 Table 6.1.7-1)
  #   at N32-c setup; response selectedSecCapability "NONE"; both SEPPs then terminate N32-c and N32-f TLS.
  # n32f-terminate (§5.2.4) is NOT applicable in TLS-only mode: n32fContextId is carried only by
  #   SecParamExchReqData/RspData (exchange-params), which runs only when PRINS is selected (§5.2.3.1).
  #   A TLS-only SEPP therefore never holds an n32fContextId; only the unknown-context answer is specified below.

  Background:
    Given the local SEPP serves PLMN "001/02" with SEPP FQDN "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    And the roaming-partner list of the local SEPP contains only PLMN "001/01"
    And the local SEPP supports security capabilities "TLS" only
    And the N32 listener requires and verifies a client certificate

  # ---------------------------------------------------------------- happy path
  @happy
  Scenario Outline: Successful exchange-capability selects TLS (<profile> profile)
    Given the SEPP runs with the "<profile>" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with SecNegotiateReqData:
      | sender                          | sepp.5gc.mnc001.mcc001.3gppnetwork.org |
      | supportedSecCapabilityList      | ["TLS"]                                |
      | 3GppSbiTargetApiRootSupported   | true                                   |
      | plmnIdList                      | [{"mcc":"001","mnc":"01"}]             |
      | targetPlmnId                    | {"mcc":"001","mnc":"02"}               |
    Then the response status is 200
    And the response body is SecNegotiateRspData with selectedSecCapability "TLS"
    And the response "plmnIdList" is [{"mcc":"001","mnc":"02"}]
    And the response "sender" is "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
    And an N32 context exists for remote PLMN "001/01" with security capability "TLS"
    And the SEPP log has procedure "N32cSecurityCapabilityNegotiation" interface "N32c" direction "IN" result "OK"

    Examples:
      | profile |
      | rel17   |
      | rel19   |

  @happy
  Scenario: Both SEPPs support 3gpp-Sbi-Target-apiRoot, the context records it (TS 29.573 §5.2.2 step 2a)
    Given the SEPP runs with the "rel17" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    And the local SEPP supports the 3gpp-Sbi-Target-apiRoot header
    When the peer sends exchange-capability with "3GppSbiTargetApiRootSupported" true and capabilities ["TLS"]
    Then the response status is 200
    And the response "3GppSbiTargetApiRootSupported" is true
    And the N32 context for remote PLMN "001/01" has targetApiRoot header mode enabled

  @happy
  Scenario: Peer without 3gpp-Sbi-Target-apiRoot support, the context records header mode disabled (default false)
    Given the SEPP runs with the "rel17" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability without the "3GppSbiTargetApiRootSupported" IE and capabilities ["TLS"]
    Then the response status is 200
    And the N32 context for remote PLMN "001/01" has targetApiRoot header mode disabled

  @happy
  Scenario: Extensible enums and unknown keys are tolerated, unknown capability values are ignored in selection
    Given the SEPP runs with the "rel17" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability with capabilities ["FUTURE_CAP","TLS"] and an unknown JSON key "x-future"
    Then the response status is 200
    And the response body is SecNegotiateRspData with selectedSecCapability "TLS"

  @happy
  Scenario: A new exchange-capability replaces the existing N32-f context (TS 29.573 §5.2.2 step 2a)
    Given an N32 context exists for remote PLMN "001/01" with security capability "TLS"
    And the SEPP runs with the "rel17" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends a valid exchange-capability with capabilities ["TLS"]
    Then the response status is 200
    And exactly one N32 context exists for remote PLMN "001/01"
    And the previous N32 context was deleted before the new one was created

  # ---------------------------------------------------- TLS-mode teardown via NONE
  @teardown
  Scenario Outline: Teardown of a TLS-mode N32-f connection with capability NONE (TS 29.573 §5.2.2, NFTLST) (<profile>)
    Given the SEPP runs with the "<profile>" release profile
    And the local SEPP supports feature "NFTLST"
    And an N32 context exists for remote PLMN "001/01" with security capability "TLS" and feature "NFTLST" negotiated
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability with supportedSecCapabilityList ["NONE"]
    Then the response status is 200
    And the response body is SecNegotiateRspData with selectedSecCapability "NONE"
    And no N32 context exists for remote PLMN "001/01"
    And the SEPP terminates the N32-c and N32-f TLS connections of that peer

    Examples:
      | profile |
      | rel17   |
      | rel19   |

  @teardown @error
  Scenario: NONE without negotiated NFTLST is not a teardown and is rejected as no common capability
    # TS 29.573 §5.2.2: teardown via NONE requires the remote SEPP to have indicated NFTLST.
    Given the SEPP runs with the "rel19" release profile
    And an N32 context exists for remote PLMN "001/01" with security capability "TLS" and feature "NFTLST" not negotiated
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability with supportedSecCapabilityList ["NONE"]
    Then the response status is 403
    And the response body is ProblemDetails with cause "NEGOTIATION_NOT_ALLOWED"

  @teardown
  Scenario: N32-f requests are rejected after teardown until a new handshake succeeds
    Given the N32 context for remote PLMN "001/01" was torn down with capability "NONE"
    When the peer sends an N32-f request for PLMN "001/02"
    Then the N32-f ingress rejects the request with status 403
    # rel19 cause "CONTEXT_NOT_FOUND": TS 29.573 §5.3.3.4 Table 5.3.3.4-1 (asserted in n32f_forwarding.feature E5).

  # ----------------------------------------------------------------- Rel-17 vs Rel-19 wire profile
  @rel17 @profile
  Scenario: Rel-17 profile never emits Rel-19-only IEs (byte-identical baseline)
    Given the SEPP runs with the "rel17" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability including Rel-19 IEs "n32HandshakeId","senderN32fFqdn","senderN32fPortList","n32KeepaliveTimer"
    Then the response status is 200
    And the response body contains none of "n32HandshakeId","senderN32fFqdn","senderN32fPort","n32KeepaliveTimer"
    And the response "supportedFeatures" is absent when the negotiated set is empty
    And the Rel-19-only IEs received are ignored and not stored in the N32 context

  @rel19 @profile
  Scenario: Rel-19 profile sends supportedFeatures "0" when the negotiated set is empty (SpecLiteral)
    Given the SEPP runs with the "rel19" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability with capabilities ["TLS"] and no supportedFeatures
    Then the response status is 200
    And the response "supportedFeatures" is "0"

  @rel19 @profile
  Scenario: Rel-19 profile echoes n32HandshakeId when received (TS 29.573 §5.2.2 step 2a)
    # TS 29.573 §5.2.2 step 2a: the response includes n32HandshakeId only "if the N32 handshake identifier
    # was received in the request and the responding SEPP supports the N32 handshake identifier"; support
    # is optional. Applies only if REL19-9.4 elects to support it (design doc: SEPP-001 ignores it). A SEPP
    # that supports it must also send "3gpp-Sbi-N32-Handshake-Id" on correlated N32-f requests (§5.3.3.3).
    Given the SEPP runs with the "rel19" release profile
    And the local SEPP supports the N32 handshake identifier
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability with n32HandshakeId "0123456789abcdef"
    Then the response status is 200
    And the response "n32HandshakeId" is "0123456789abcdef"

  @rel17 @profile
  Scenario Outline: Rel-17 profile never emits API-specific status codes added after Rel-17 (<trigger>)
    # 307 (redirection, CR 0126, V18.2.0) and 409 on exchange-capability (collision, CR 0150, V18.5.0)
    # are absent from the Rel-17 YAML. 401/403/404/502 are NOT Rel-19-only: they are "M" for POST in
    # TS 29.500 V17.16.0 Table 5.2.7.1-1. The project additionally keeps rel17 within the Rel-17 YAML list.
    Given the SEPP runs with the "rel17" release profile
    When <trigger>
    Then the response status is one of 400, 403, 411, 413, 415, 429, 500, 503
    And the response status is not one of 307, 409

    Examples:
      | trigger                                                      |
      | the peer sends an unknown-partner exchange-capability        |
      | the peer sends an exchange-capability with an empty body     |
      | the peer sends exchange-capability with only capability PRINS |

  # ---------------------------------------------------------------------- errors
  @error @E1
  Scenario Outline: E1 no common security capability is rejected with 403 (<offered>)
    Given the SEPP runs with the "<profile>" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability with supportedSecCapabilityList <offered>
    Then the response status is 403
    And the response body is ProblemDetails
    And no N32 context exists for remote PLMN "001/01"
    And the SEPP log has procedure "N32cSecurityCapabilityNegotiation" result "REJECT"
    # 403 confirmed: TS 29.573 §6.1.4.2.2 Table 6.1.4.2.2-2 and Rel-17 YAML both list 403.

    Examples:
      | profile | offered                 |
      | rel17   | ["PRINS"]               |
      | rel19   | ["PRINS"]               |
      | rel17   | ["FUTURE_CAP"]          |
      | rel19   | ["PRINS","FUTURE_CAP"]  |

  @error @E1
  Scenario Outline: E1 no common security capability carries cause NEGOTIATION_NOT_ALLOWED (<profile>)
    # Same rule in both releases: TS 29.573 §6.1.4.2.2 Table 6.1.4.2.2-2 ("When the receiving SEPP
    # fails to negotiate the security capability, the cause attribute shall be set to
    # NEGOTIATION_NOT_ALLOWED") and §6.1.6.3 Table 6.1.6.3-1 (403). Verified in V17.7.0 and V19.7.0.
    Given the SEPP runs with the "<profile>" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability with supportedSecCapabilityList ["PRINS"]
    Then the response status is 403
    And the response body is ProblemDetails with cause "NEGOTIATION_NOT_ALLOWED"

    Examples:
      | profile |
      | rel17   |
      | rel19   |

  @error @rel19
  Scenario Outline: Rel-19 exchange-capability collision resolved by FQDN order (TS 29.573 §5.2.2 step 2b) (<peer>)
    # The SEPP whose FQDN lexicographically precedes rejects the incoming request with 409
    # N32C_EXCHANGE_CAPABILITY_ONGOING (Table 6.1.6.3-1) and continues its own; otherwise it yields.
    # Rel-17 has no 409 on exchange-capability (CR 0150, V18.5.0), so the collision rule is rel19 only.
    Given the SEPP runs with the "rel19" release profile
    And the roaming-partner list of the local SEPP contains PLMNs "001/01" and "001/03"
    And the local SEPP has an outgoing exchange-capability towards "<peer>" awaiting its response
    And the peer presents a certificate whose SAN is "<peer>"
    When the peer sends a valid exchange-capability with sender "<peer>" and capabilities ["TLS"]
    Then the response status is <status>
    And the local SEPP <outcome>

    Examples:
      | peer                                   | status | outcome                                                                          |
      | sepp.5gc.mnc003.mcc001.3gppnetwork.org | 409    | answers ProblemDetails cause "N32C_EXCHANGE_CAPABILITY_ONGOING" and keeps its own request |
      | sepp.5gc.mnc001.mcc001.3gppnetwork.org | 200    | abandons its own outgoing request                                                |

  @error @E2
  Scenario Outline: E2 PLMN not in the roaming-partner list is rejected with 403 (<profile>)
    Given the SEPP runs with the "<profile>" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc099.mcc999.3gppnetwork.org"
    When the peer sends exchange-capability with plmnIdList [{"mcc":"999","mnc":"99"}] and capabilities ["TLS"]
    Then the response status is 403
    And the response body is ProblemDetails
    And no N32 context exists for remote PLMN "999/99"
    And the SEPP log has procedure "N32cSecurityCapabilityNegotiation" result "REJECT" cause "plmn_not_allowed"
    # No TS 29.573 application error is defined for a non-partner PLMN; the ProblemDetails cause is not asserted.

    Examples:
      | profile |
      | rel17   |
      | rel19   |

  @error @E3
  Scenario Outline: E3 certificate PLMN differs from the handshake PLMN is rejected with 403 (<profile>)
    Given the SEPP runs with the "<profile>" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability with sender "sepp.5gc.mnc005.mcc001.3gppnetwork.org" and plmnIdList [{"mcc":"001","mnc":"05"}]
    Then the response status is 403
    And no N32 context exists for remote PLMN "001/05"
    And the SEPP log has procedure "N32cSecurityCapabilityNegotiation" result "REJECT"

    Examples:
      | profile |
      | rel17   |
      | rel19   |

  @error @E3
  Scenario: E3 plmnIdList PLMN differs from the certificate PLMN although both are allowed partners
    Given the roaming-partner list of the local SEPP contains PLMNs "001/01" and "001/03"
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability with plmnIdList [{"mcc":"001","mnc":"03"}] and capabilities ["TLS"]
    Then the response status is 403
    And no N32 context exists for remote PLMN "001/03"

  @error @E3
  Scenario: Peer without a client certificate cannot reach exchange-capability
    When a client connects to the N32 listener without presenting a client certificate
    Then the TLS handshake fails
    And no HTTP request is processed

  @error @E4
  Scenario Outline: E4 malformed or incomplete body is rejected with 400 (<case>)
    Given the SEPP runs with the "rel17" release profile
    And the peer presents a certificate whose SAN is "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
    When the peer sends exchange-capability with <case>
    Then the response status is 400
    And the response body is ProblemDetails with cause "<cause>"
    And no N32 context exists for remote PLMN "001/01"

    Examples:
      | case                                          | cause                    |
      | no "sender" IE                                | MANDATORY_IE_MISSING     |
      | no "supportedSecCapabilityList" IE            | MANDATORY_IE_MISSING     |
      | an empty supportedSecCapabilityList           | MANDATORY_IE_INCORRECT   |
      | a body that is not valid JSON                 | INVALID_MSG_FORMAT       |

  @error
  Scenario: Wrong Content-Type is rejected with 415
    Given the SEPP runs with the "rel17" release profile
    When the peer sends POST "/n32c-handshake/v1/exchange-capability" with Content-Type "text/plain"
    Then the response status is 415

  # ----------------------------------------------- n32f-terminate in TLS-only mode (no n32fContextId exists)
  # The 200 OK + N32fContextInfo success path (TS 29.573 §5.2.4, §6.1.4.4.2) needs an n32fContextId
  # from exchange-params (PRINS). It cannot occur in this TLS-only increment and is not specified here.
  @terminate @E6 @rel17
  Scenario: E6 Rel-17 n32f-terminate for an unknown context answers 400 (project choice)
    # Project choice, not a TS rule: TS 29.500 V17.16.0 Table 5.2.7.1-1 marks 403/404 "M" for POST and
    # the TS 29.573 operation tables apply them (NOTE under Table 6.1.4.4.2-2), so 404 would also conform.
    # rel17 stays inside the Rel-17 YAML list (400,411,413,415,429,500,503). No specific cause is defined.
    Given the SEPP runs with the "rel17" release profile
    When the peer sends n32f-terminate for unknown n32fContextId "ffffffffffffffff"
    Then the response status is 400
    And the response body is ProblemDetails with cause "MANDATORY_IE_INCORRECT"

  @terminate @E6 @rel19
  Scenario: E6 Rel-19 n32f-terminate for an unknown context answers 404
    Given the SEPP runs with the "rel19" release profile
    When the peer sends n32f-terminate for unknown n32fContextId "ffffffffffffffff"
    Then the response status is 404

  @terminate @error
  Scenario Outline: n32f-terminate with an invalid n32fContextId pattern is rejected with 400 (<id>)
    Given the SEPP runs with the "rel17" release profile
    When the peer sends n32f-terminate for n32fContextId "<id>"
    Then the response status is 400

    Examples:
      | id                  |
      | xyz                 |
      | 0011223344556677aa  |
      |                     |
