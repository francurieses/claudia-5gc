# SBI HTTP 307/308 redirection (ES3XX) — SMF as Namf_Communication consumer
# (TS 29.518 §6.1.8 Table 6.1.8-1 feature 7 ES3XX "M" for the NF Service Consumer, §6.1.10;
#  TS 29.500 §6.10.9.1 HTTP redirection, §5.2.7.3 c) retry with the same method,
#  §6.4.2.4 redirect-loop detection, §5.2.3.2.13 3gpp-Sbi-Target-Nf-Id;
#  TS 29.571 RedirectResponse; TS 23.502 §4.2.3.3 N1N2MessageTransfer for CN paging)
#
# Design contract: docs/procedures/feature-negotiation.md, "ES3XX — consumer redirect handling"
# and "ES3XX implementation notes". Task SBI-FEAT-001: only ES3XX is implemented in this
# session; HOFAIL, AASN and SCID are deferred (no scenario).
#
# Behaviour under test: the SMF N1N2MessageTransfer clients (internal/server/paging.go DL-data
# notification and secondary_auth.go) follow 307/308 with the same method, body and headers to
# the Location (relative references resolved against the request URI), honour a RedirectResponse
# SCP_REDIRECTION/SEPP_REDIRECTION (Location ignored, original path sent to the target apiRoot),
# never follow other 3xx, bound the chain (TS 29.500 §6.4.2.4), and do not follow 307/308
# lacking a usable Location. Not profile-gated; only the offer is: rel19 offers
# supportedFeatures "40" (feature 7 = bit 6) in N1N2MessageTransferReqData, rel17 sends none.

@rel19 @feature-negotiation @es3xx
Feature: SMF handling of HTTP 307/308 redirection (ES3XX) as Namf_Communication consumer
  As the SMF acting as NF Service Consumer of Namf_Communication
  I want to follow 307 Temporary Redirect and 308 Permanent Redirect from an AMF on N1N2MessageTransfer
  So that CN paging reaches the redirect target while other 3xx responses are never followed

  Background:
    Given a mock AMF-A and a mock AMF-B are running
    And the SMF Namf client is configured with the address of mock AMF-A
    And an established PDU session 1 for SUPI "imsi-001010000000001" exists in the SMF

  # ---- supportedFeatures offer (gated by release profile) ----

  Scenario: Rel-19 SMF offers ES3XX bit "40" in N1N2MessageTransfer
    Given the SMF runs with release profile "rel19"
    And mock AMF-A answers N1N2MessageTransfer with 202 "ATTEMPTING_TO_REACH_UE"
    When the SMF triggers a DL-data notification for PDU session 1
    Then mock AMF-A received supportedFeatures "40" in N1N2MessageTransferReqData

  Scenario: Rel-17 SMF sends no supportedFeatures in N1N2MessageTransfer
    Given the SMF runs with release profile "rel17"
    And mock AMF-A answers N1N2MessageTransfer with 202 "ATTEMPTING_TO_REACH_UE"
    When the SMF triggers a DL-data notification for PDU session 1
    Then mock AMF-A received N1N2MessageTransferReqData without a supportedFeatures attribute
    And mock AMF-A received a request body byte-identical to the pre-negotiation baseline

  # ---- 307 / 308 followed ----

  Scenario Outline: N1N2MessageTransfer redirected with <status> is retransmitted to the Location with same method, body and headers
    Given the SMF runs with release profile "<profile>"
    And mock AMF-A answers N1N2MessageTransfer with <status> and Location "mock AMF-B /namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    And mock AMF-B answers N1N2MessageTransfer with 202 "ATTEMPTING_TO_REACH_UE"
    When the SMF triggers a DL-data notification for PDU session 1
    Then mock AMF-A received 1 request
    And mock AMF-B received 1 request
    And mock AMF-B received method "POST" and path "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    And the request body received by mock AMF-B equals the request body received by mock AMF-A
    And the headers "Content-Type", "X-Correlation-Id" and "3gpp-Sbi-Message-Priority" received by mock AMF-B equal those received by mock AMF-A
    And the DL-data notification result is 202 with cause "ATTEMPTING_TO_REACH_UE"

    Examples:
      | status | profile |
      | 307    | rel19   |
      | 308    | rel19   |
      | 307    | rel17   |
      | 308    | rel17   |

  Scenario: 307 with 3gpp-Sbi-Target-Nf-Id is followed and the target NF instance id is logged
    Given the SMF runs with release profile "rel19"
    And mock AMF-A answers N1N2MessageTransfer with 307, Location "mock AMF-B /namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages" and header "3gpp-Sbi-Target-Nf-Id" "nfinst=0f3a4d2e-6a1b-4c5d-8e9f-0123456789ab"
    And mock AMF-B answers N1N2MessageTransfer with 202 "ATTEMPTING_TO_REACH_UE"
    When the SMF triggers a DL-data notification for PDU session 1
    Then mock AMF-B received 1 request
    And a redirect log has interface "Namf", direction "OUT", spec_ref "TS 29.500 §6.10.9.1", http_status 307, target_nf_id "nfinst=0f3a4d2e-6a1b-4c5d-8e9f-0123456789ab" and result "OK"

  Scenario: 307 with a relative Location is resolved against the request URI
    Given the SMF runs with release profile "rel19"
    And mock AMF-A answers N1N2MessageTransfer with 307 and the relative Location "/alt/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    And mock AMF-A answers a request to path "/alt/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages" with 202 "ATTEMPTING_TO_REACH_UE"
    When the SMF triggers a DL-data notification for PDU session 1
    Then mock AMF-A received 2 requests
    And mock AMF-A received the second request with method "POST" and path "/alt/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    And mock AMF-B received 0 requests
    And the DL-data notification result is 202 with cause "ATTEMPTING_TO_REACH_UE"

  Scenario: Secondary-authentication N1N2MessageTransfer redirected with 307 is followed
    Given the SMF runs with release profile "rel19"
    And mock AMF-A answers N1N2MessageTransfer with 307 and Location "mock AMF-B /namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    And mock AMF-B answers N1N2MessageTransfer with 200 "N1_N2_TRANSFER_INITIATED"
    When the SMF sends a secondary authentication N1N2MessageTransfer for PDU session 1
    Then mock AMF-B received method "POST" and path "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    And the request body received by mock AMF-B equals the request body received by mock AMF-A
    And the secondary authentication N1N2MessageTransfer succeeds

  # ---- SCP / SEPP redirection (RedirectResponse) ----

  Scenario: 307 with RedirectResponse SCP_REDIRECTION sends the original path to targetScp and ignores Location
    Given the SMF runs with release profile "rel19"
    And mock AMF-A answers N1N2MessageTransfer with 307, Location "mock AMF-A /ignored-location" and RedirectResponse cause "SCP_REDIRECTION" with targetScp "mock AMF-B apiRoot"
    And mock AMF-B answers N1N2MessageTransfer with 202 "ATTEMPTING_TO_REACH_UE"
    When the SMF triggers a DL-data notification for PDU session 1
    Then mock AMF-A received 1 request
    And mock AMF-B received 1 request
    And mock AMF-B received method "POST" and path "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    And the DL-data notification result is 202 with cause "ATTEMPTING_TO_REACH_UE"

  Scenario: 308 with RedirectResponse SEPP_REDIRECTION sends the original path to targetSepp and ignores Location
    Given the SMF runs with release profile "rel19"
    And mock AMF-A answers N1N2MessageTransfer with 308, Location "mock AMF-A /ignored-location" and RedirectResponse cause "SEPP_REDIRECTION" with targetSepp "mock AMF-B apiRoot"
    And mock AMF-B answers N1N2MessageTransfer with 202 "ATTEMPTING_TO_REACH_UE"
    When the SMF triggers a DL-data notification for PDU session 1
    Then mock AMF-B received 1 request
    And mock AMF-B received method "POST" and path "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    And the DL-data notification result is 202 with cause "ATTEMPTING_TO_REACH_UE"

  # ---- error path: bounded chain, missing Location ----

  Scenario: Redirect loop between two AMFs fails after the maximum number of redirects
    Given the SMF runs with release profile "rel19"
    And mock AMF-A always answers N1N2MessageTransfer with 307 and Location "mock AMF-B /namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    And mock AMF-B always answers N1N2MessageTransfer with 307 and Location "mock AMF-A /namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    When the SMF triggers a DL-data notification for PDU session 1
    Then the DL-data notification fails with an error containing "too many redirects"
    And the total number of requests received by mock AMF-A and mock AMF-B is the maximum redirects plus 1
    And a redirect log has http_status 307 and result "FAILURE"

  Scenario Outline: <status> without Location and without a RedirectResponse body is not followed
    Given the SMF runs with release profile "rel19"
    And mock AMF-A answers N1N2MessageTransfer with <status>, no Location header and an empty body
    When the SMF triggers a DL-data notification for PDU session 1
    Then mock AMF-A received 1 request
    And mock AMF-B received 0 requests
    And the DL-data notification fails exactly as for an unexpected status <status>

    Examples:
      | status |
      | 307    |
      | 308    |

  # ---- spec-deviation / non-follow: 3xx other than 307/308 ----

  Scenario Outline: N1N2MessageTransfer answered with <status> is not followed and the operation fails
    Given the SMF runs with release profile "rel19"
    And mock AMF-A answers N1N2MessageTransfer with <status> and Location "mock AMF-B /namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    When the SMF triggers a DL-data notification for PDU session 1
    Then mock AMF-A received 1 request
    And mock AMF-B received 0 requests
    And the DL-data notification fails exactly as for an unexpected status <status>

    Examples:
      | status |
      | 301    |
      | 302    |
      | 303    |
