# SBI HTTP 307/308 redirection (ES3XX) — AMF as Nsmf_PDUSession consumer
# (TS 29.502 §6.1.8 Table 6.1.8-1 feature 8 ES3XX "M" for the NF Service Consumer, §6.1.10;
#  TS 29.500 §6.10.9.1 HTTP redirection, §5.2.7.3 c) retry with the same method,
#  §6.4.2.4 redirect-loop detection, §5.2.3.2.13 3gpp-Sbi-Target-Nf-Id;
#  TS 29.571 RedirectResponse (cause SCP_REDIRECTION / SEPP_REDIRECTION, targetScp, targetSepp))
#
# Design contract: docs/procedures/feature-negotiation.md, sections "Mandatory features
# (SBI-FEAT-001)" -> "ES3XX — consumer redirect handling" and "ES3XX implementation notes".
# Task SBI-FEAT-001: only ES3XX is implemented in this session; HOFAIL, AASN and SCID are
# deferred and have no scenario here.
#
# Behaviour under test (shared helper in shared/sbi, wired into HTTPSMFClient):
#  - 307/308: retransmit with the SAME method, SAME body and SAME headers to Location
#    (a relative reference is resolved against the request URI); 3gpp-Sbi-Target-Nf-Id logged.
#  - 307/308 whose body is a RedirectResponse with SCP_REDIRECTION/targetScp (or
#    SEPP_REDIRECTION/targetSepp): Location is ignored, the original path is sent to that apiRoot.
#  - Any other 3xx (301/302/303): NOT followed, returned to the caller (operation fails as today).
#  - 307/308 without a usable Location and without a valid RedirectResponse: not followed, fails.
#  - Bounded redirect chain (TS 29.500 §6.4.2.4): exceeding the maximum fails the operation.
#  - Redirect handling is NOT profile-gated (works under rel17 and rel19). Only the offer is gated:
#    rel19 CreateSMContext offers supportedFeatures "80" (feature 8 = bit 7); rel17 sends no
#    supportedFeatures (byte-identical baseline). Producers answer "0".
# Limitation (stated, not tested): a 308 does not re-link the stored SMF address / smContextRef.

@rel19 @feature-negotiation @es3xx
Feature: AMF handling of HTTP 307/308 redirection (ES3XX) as Nsmf_PDUSession consumer
  As the AMF acting as NF Service Consumer of Nsmf_PDUSession
  I want to follow 307 Temporary Redirect and 308 Permanent Redirect from an SMF
  So that SM-context operations reach the redirect target while other 3xx responses are never followed

  Background:
    Given a mock SMF-A and a mock SMF-B are running
    And the AMF Nsmf client is configured with the address of mock SMF-A

  # ---- supportedFeatures offer (gated by release profile) ----

  Scenario: Rel-19 AMF offers ES3XX bit "80" in CreateSMContext
    Given the AMF runs with release profile "rel19"
    And mock SMF-A answers CreateSMContext with 201 and supportedFeatures "0"
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-A received supportedFeatures "80" in SmContextCreateData
    And the AMF stores the negotiated feature set "0" on PDU session 1

  Scenario: Rel-17 AMF sends no supportedFeatures in CreateSMContext
    Given the AMF runs with release profile "rel17"
    And mock SMF-A answers CreateSMContext with 201 and supportedFeatures "0"
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-A received SmContextCreateData without a supportedFeatures attribute
    And mock SMF-A received a request body byte-identical to the pre-negotiation baseline

  # ---- 307 / 308 followed ----

  Scenario Outline: CreateSMContext redirected with <status> is retransmitted to the Location with same method, body and headers
    Given the AMF runs with release profile "<profile>"
    And mock SMF-A answers CreateSMContext with <status> and Location "mock SMF-B /nsmf-pdusession/v1/sm-contexts"
    And mock SMF-B answers CreateSMContext with 201 and smContextRef "ctx-b-1"
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-A received 1 request
    And mock SMF-B received 1 request
    And mock SMF-B received method "POST" and path "/nsmf-pdusession/v1/sm-contexts"
    And the request body received by mock SMF-B equals the request body received by mock SMF-A
    And the headers "Content-Type", "X-Correlation-Id" and "3gpp-Sbi-Message-Priority" received by mock SMF-B equal those received by mock SMF-A
    And the CreateSMContext call returns success
    And the AMF stores smContextRef "ctx-b-1" for PDU session 1

    Examples:
      | status | profile |
      | 307    | rel19   |
      | 308    | rel19   |
      | 307    | rel17   |
      | 308    | rel17   |

  Scenario: 307 with 3gpp-Sbi-Target-Nf-Id is followed and the target NF instance id is logged
    Given the AMF runs with release profile "rel19"
    And mock SMF-A answers CreateSMContext with 307, Location "mock SMF-B /nsmf-pdusession/v1/sm-contexts" and header "3gpp-Sbi-Target-Nf-Id" "nfinst=4947a69a-f61b-4bc1-b9da-47c9c5d12345"
    And mock SMF-B answers CreateSMContext with 201 and smContextRef "ctx-b-2"
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-B received 1 request
    And the CreateSMContext call returns success
    And a redirect log has interface "Nsmf", direction "OUT", spec_ref "TS 29.500 §6.10.9.1", http_status 307, target_nf_id "nfinst=4947a69a-f61b-4bc1-b9da-47c9c5d12345" and result "OK"

  Scenario: 307 with a relative Location is resolved against the request URI
    Given the AMF runs with release profile "rel19"
    And mock SMF-A answers CreateSMContext with 307 and the relative Location "/alt/nsmf-pdusession/v1/sm-contexts"
    And mock SMF-A answers a request to path "/alt/nsmf-pdusession/v1/sm-contexts" with 201 and smContextRef "ctx-a-rel"
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-A received 2 requests
    And mock SMF-A received the second request with method "POST" and path "/alt/nsmf-pdusession/v1/sm-contexts"
    And mock SMF-B received 0 requests
    And the CreateSMContext call returns success

  Scenario: Redirect handling does not send Go-default rewritten requests (POST is never turned into GET)
    Given the AMF runs with release profile "rel19"
    And mock SMF-A answers CreateSMContext with 308 and Location "mock SMF-B /nsmf-pdusession/v1/sm-contexts"
    And mock SMF-B answers CreateSMContext with 201 and smContextRef "ctx-b-3"
    When the AMF creates an SM context for PDU session 1
    Then every request received by mock SMF-B has method "POST" and a non-empty body

  # ---- SCP / SEPP redirection (RedirectResponse) ----

  Scenario: 307 with RedirectResponse SCP_REDIRECTION sends the original path to targetScp and ignores Location
    Given the AMF runs with release profile "rel19"
    And mock SMF-A answers CreateSMContext with 307, Location "mock SMF-A /ignored-location" and RedirectResponse cause "SCP_REDIRECTION" with targetScp "mock SMF-B apiRoot"
    And mock SMF-B answers CreateSMContext with 201 and smContextRef "ctx-scp"
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-A received 1 request
    And mock SMF-B received 1 request
    And mock SMF-B received method "POST" and path "/nsmf-pdusession/v1/sm-contexts"
    And the request body received by mock SMF-B equals the request body received by mock SMF-A
    And the CreateSMContext call returns success

  Scenario: 308 with RedirectResponse SEPP_REDIRECTION sends the original path to targetSepp and ignores Location
    Given the AMF runs with release profile "rel19"
    And mock SMF-A answers CreateSMContext with 308, Location "mock SMF-A /ignored-location" and RedirectResponse cause "SEPP_REDIRECTION" with targetSepp "mock SMF-B apiRoot"
    And mock SMF-B answers CreateSMContext with 201 and smContextRef "ctx-sepp"
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-B received 1 request
    And mock SMF-B received method "POST" and path "/nsmf-pdusession/v1/sm-contexts"
    And the CreateSMContext call returns success

  Scenario: Malformed RedirectResponse falls back to the Location header
    Given the AMF runs with release profile "rel19"
    And mock SMF-A answers CreateSMContext with 307, Location "mock SMF-B /nsmf-pdusession/v1/sm-contexts" and RedirectResponse cause "SCP_REDIRECTION" without targetScp
    And mock SMF-B answers CreateSMContext with 201 and smContextRef "ctx-fallback"
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-B received 1 request
    And the CreateSMContext call returns success

  # ---- other SM-context operations follow 307/308 as well ----

  Scenario Outline: UpdateSMContext (modify) redirected with <status> is followed
    Given the AMF runs with release profile "rel19"
    And an SM context "ctx-1" exists for PDU session 1 on mock SMF-A
    And mock SMF-A answers UpdateSMContext on "ctx-1" with <status> and Location "mock SMF-B /nsmf-pdusession/v1/sm-contexts/ctx-1/modify"
    And mock SMF-B answers UpdateSMContext on "ctx-1" with 200
    When the AMF sends an UpdateSMContext for PDU session 1
    Then mock SMF-B received method "POST" and path "/nsmf-pdusession/v1/sm-contexts/ctx-1/modify"
    And the request body received by mock SMF-B equals the request body received by mock SMF-A
    And the UpdateSMContext call returns success

    Examples:
      | status |
      | 307    |
      | 308    |

  Scenario: Deletion of the SM context redirected with 307 is followed with the same method
    Given the AMF runs with release profile "rel19"
    And an SM context "ctx-1" exists for PDU session 1 on mock SMF-A
    And mock SMF-A answers the SM context deletion on "ctx-1" with 307 and Location "mock SMF-B /nsmf-pdusession/v1/sm-contexts/ctx-1"
    And mock SMF-B answers the SM context deletion on "ctx-1" with 204
    When the AMF deletes the SM context for PDU session 1
    Then mock SMF-B received the same method and path as mock SMF-A received for the deletion
    And the SM context deletion returns success

  # ---- error path: bounded chain, missing Location ----

  Scenario: Redirect loop between two SMFs fails after the maximum number of redirects
    Given the AMF runs with release profile "rel19"
    And mock SMF-A always answers CreateSMContext with 307 and Location "mock SMF-B /nsmf-pdusession/v1/sm-contexts"
    And mock SMF-B always answers CreateSMContext with 307 and Location "mock SMF-A /nsmf-pdusession/v1/sm-contexts"
    When the AMF creates an SM context for PDU session 1
    Then the CreateSMContext call fails with an error containing "too many redirects"
    And the total number of requests received by mock SMF-A and mock SMF-B is the maximum redirects plus 1
    And a redirect log has http_status 307 and result "FAILURE"
    And the AMF does not retry the redirect chain beyond the maximum

  Scenario Outline: <status> without Location and without a RedirectResponse body is not followed
    Given the AMF runs with release profile "rel19"
    And mock SMF-A answers CreateSMContext with <status>, no Location header and an empty body
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-A received 1 request
    And mock SMF-B received 0 requests
    And the CreateSMContext call fails with an error containing "status <status>"

    Examples:
      | status |
      | 307    |
      | 308    |

  Scenario: 307 with an unparsable Location is not followed
    Given the AMF runs with release profile "rel19"
    And mock SMF-A answers CreateSMContext with 307 and the raw Location "http://[::1"
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-A received 1 request
    And mock SMF-B received 0 requests
    # net/http rejects an unparsable Location before the redirect policy runs,
    # so the call fails with a transport error naming the Location header
    # (not with "status 307"). Orchestrator edit, SBI-FEAT-001.
    And the CreateSMContext call fails with an error containing "failed to parse Location header"

  # ---- spec-deviation / non-follow: 3xx other than 307/308 ----

  Scenario Outline: CreateSMContext answered with <status> is not followed and the operation fails
    Given the AMF runs with release profile "rel19"
    And mock SMF-A answers CreateSMContext with <status> and Location "mock SMF-B /nsmf-pdusession/v1/sm-contexts"
    When the AMF creates an SM context for PDU session 1
    Then mock SMF-A received 1 request
    And mock SMF-B received 0 requests
    And the CreateSMContext call fails with an error containing "status <status>"

    Examples:
      | status |
      | 301    |
      | 302    |
      | 303    |
