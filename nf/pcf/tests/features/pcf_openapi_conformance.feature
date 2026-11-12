Feature: PCF Rel-17 OpenAPI conformance — Location, delete semantics, body schemas, routing, logging (PCF-003)
  As an SBI consumer (SMF, AMF, AF)
  I want the PCF Npcf producers to follow the Rel-17 OpenAPI wire behaviour
  So that Location headers, status codes, bodies and logs are interoperable and traceable
  Spec: TS 29.501 §4.4.1, TS 29.525 §4.2.2/§4.2.5/§5.7.3, TS 29.507 §4.2.2/§4.2.5/§5.6.2.2/§5.6.2.3,
        TS 29.512 §4.2.5.2, TS 29.514 §4.2.4.2, TS 29.500 §5.2.7.1/§6.6.2 (programme decision D1)

  Background:
    Given a PCF instance with default configuration
    And the PCF SBI FQDN is "pcf.5gc.mnc001.mcc001.3gppnetwork.org" and it listens on a free local port

  # ---------------------------------------------------------------------------
  # AC 1 — absolute Location on every 201 (TS 29.501 §4.4.1)
  # ---------------------------------------------------------------------------
  Scenario Outline: <service> create returns 201 with an absolute Location header
    When a consumer sends POST "<path>" with a valid <service> create body
    Then the PCF responds with status 201
    And the Location header starts with "https://pcf.5gc.mnc001.mcc001.3gppnetwork.org:{port}<path>/"
    And the Location header ends with the identifier of the created resource

    Examples:
      | service                      | path                                 |
      | SM policy                    | /npcf-smpolicycontrol/v1/sm-policies |
      | AM policy association        | /npcf-am-policy-control/v1/policies  |
      | UE policy association        | /npcf-ue-policy-control/v1/policies  |
      | Policy authorization session | /npcf-policyauthorization/v1/app-sessions |

  Scenario: Location falls back to the request Host when no SBI FQDN is configured
    Given the PCF has no SBI FQDN configured
    When a consumer sends POST "/npcf-am-policy-control/v1/policies" with a valid AM policy create body and Host "pcf-test:9443"
    Then the PCF responds with status 201
    And the Location header starts with "https://pcf-test:9443/npcf-am-policy-control/v1/policies/"

  # ---------------------------------------------------------------------------
  # AC 2 — UE and AM policy association delete (TS 29.525 §4.2.5, TS 29.507 §4.2.5)
  # ---------------------------------------------------------------------------
  Scenario: Deleting a known UE policy association returns 204 No Content
    Given an existing UE policy association
    When a consumer sends DELETE on that UE policy association
    Then the PCF responds with status 204
    And the response body is empty

  Scenario: Deleting an unknown UE policy association returns 404 POLICY_ASSOCIATION_NOT_FOUND
    When a consumer sends DELETE "/npcf-ue-policy-control/v1/policies/unknown-id"
    Then the PCF responds with status 404
    And the response is a ProblemDetails with cause "POLICY_ASSOCIATION_NOT_FOUND"

  Scenario: Deleting an unknown AM policy association returns 404 POLICY_ASSOCIATION_NOT_FOUND
    When a consumer sends DELETE "/npcf-am-policy-control/v1/policies/unknown-id"
    Then the PCF responds with status 404
    And the response is a ProblemDetails with cause "POLICY_ASSOCIATION_NOT_FOUND"

  # ---------------------------------------------------------------------------
  # AC 4 — 201 body schemas (TS 29.525 §5.7.3, TS 29.507 §5.6.2.2/§5.6.2.3)
  # ---------------------------------------------------------------------------
  Scenario: UE policy association 201 body carries uePolicy and omits polAssoId and uePolicySections
    Given a URSP policy is configured for the UE
    When a consumer sends POST "/npcf-ue-policy-control/v1/policies" with a valid UE policy create body
    Then the PCF responds with status 201
    And the response body has a base64 "uePolicy" attribute carrying the URSP container
    And the response body has no "polAssoId" attribute
    And the response body has no "uePolicySections" attribute

  Scenario: AM policy association 201 body omits polAssoId
    When a consumer sends POST "/npcf-am-policy-control/v1/policies" with a valid AM policy create body
    Then the PCF responds with status 201
    And the response body has no "polAssoId" attribute

  Scenario Outline: supportedFeatures is negotiated per profile and request (D1, TS 29.500 §6.6.2) — <service>, <profile>
    Given the PCF runs with profile "<profile>"
    When a consumer sends POST "<path>" with a valid <service> create body that <request_suppfeat>
    Then the PCF responds with status 201
    And the response body <expectation>

    Examples:
      | service               | path                                | profile | request_suppfeat       | expectation                              |
      | AM policy association | /npcf-am-policy-control/v1/policies | rel17   | omits suppFeat         | has no "suppFeat" attribute              |
      | AM policy association | /npcf-am-policy-control/v1/policies | rel19   | omits suppFeat         | has "suppFeat" equal to "0"              |
      | UE policy association | /npcf-ue-policy-control/v1/policies | rel17   | omits suppFeat         | has no "suppFeat" attribute              |
      | UE policy association | /npcf-ue-policy-control/v1/policies | rel19   | omits suppFeat         | has "suppFeat" equal to "0"              |

  # ---------------------------------------------------------------------------
  # AC 5 — 413 is counted and logged under the DELETE procedure (TS 29.500 §5.2.7.1)
  # ---------------------------------------------------------------------------
  Scenario Outline: Oversized body (> 1 MiB) on <resource> delete returns 413 under the delete procedure
    Given an existing <resource>
    When a consumer sends POST "<delete_path>" with a body larger than 1 MiB
    Then the PCF responds with status 413
    And the procedure counter "<delete_procedure>" is incremented with result "REJECT"
    And the procedure counter "<create_procedure>" is not incremented
    And a log line with procedure "<delete_procedure>" and result "REJECT" is emitted

    Examples:
      | resource           | delete_path                          | delete_procedure            | create_procedure        |
      | SM policy          | /npcf-smpolicycontrol/v1/sm-policies/{id}/delete | SmPolicyDelete | SmPolicyCreate |
      | app session        | /npcf-policyauthorization/v1/app-sessions/{id}/delete | PolicyAuthorizationDelete | PolicyAuthorizationCreate |

  # ---------------------------------------------------------------------------
  # AC 6 — legacy aliases are not routed
  # ---------------------------------------------------------------------------
  Scenario Outline: Legacy alias <method> <path> is not routed
    When a consumer sends <method> "<path>"
    Then the PCF responds with status 404 or 405

    Examples:
      | method | path                                          |
      | POST   | /npcf-ampolicycontrol/v1/policies             |
      | POST   | /npcf-ue-policy-control/v1/ue-policies        |
      | DELETE | /npcf-smpolicycontrol/v1/sm-policies/some-id  |
      | DELETE | /npcf-policyauthorization/v1/app-sessions/some-id |

  # ---------------------------------------------------------------------------
  # AC 3 — mandatory log fields on delete outcome lines
  # ---------------------------------------------------------------------------
  Scenario Outline: <resource> delete emits canonical structured log fields exactly once
    Given an existing <resource>
    When a consumer sends the delete request for that <resource>
    Then every PCF log line has field "nf" equal to "PCF" exactly once
    And the received log line has procedure "<procedure>", interface "<interface>", direction "IN"
    And the outcome log line has procedure "<procedure>", interface "<interface>", direction "OUT", result "OK"
    And the outcome log line has a non-empty "correlation_id" and a "spec_ref" starting with "TS 29."

    Examples:
      | resource              | procedure      | interface |
      | AM policy association | AMPolicyDelete | Npcf      |
      | UE policy association | UEPolicyDelete | N15       |

  # ---------------------------------------------------------------------------
  # AC 7 — YAML TLS config honoured
  # ---------------------------------------------------------------------------
  Scenario: PCF YAML sbi.tls cert_file, key_file and ca_file are honoured
    Given a PCF YAML config with sbi.tls.cert_file, sbi.tls.key_file and sbi.tls.ca_file set to test PKI files
    When the PCF SBI server is built from that configuration
    Then the server TLS configuration uses that certificate and key

  # SBA is always mTLS: ca_file is the client CA pool and a client certificate is required.
  Scenario: PCF SBI listener requires client certificates signed by the configured ca_file
    Given a PCF YAML config with sbi.tls.cert_file, sbi.tls.key_file and sbi.tls.ca_file set to test PKI files
    When the PCF SBI server is built from that configuration
    Then the client CA pool contains the configured ca_file and client certificates are required
