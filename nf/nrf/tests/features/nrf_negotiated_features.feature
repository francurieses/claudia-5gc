@nrf-negotiated-features
Feature: NRF applies the negotiated Nnrf features (TS 29.510 §5.2.2.5, §5.2.2.6, §5.2.2.9, §5.3.2.2, §6.1.9)
  As an NF consumer of the NRF
  I want responses and notifications to follow the features I negotiated
  So that I receive nfServiceList / nfServices, interPlmnFqdn, SubscriptionData and ProblemDetails as TS 29.510 prescribes

  Background:
    Given a clean NRF instance is running with release profile "rel19"

  # ---- Service-Map (Nnrf_NFDiscovery bit 6, Nnrf_NFManagement bit 1) ----

  Scenario: Discovery with Service-Map in requester-features returns nfServiceList keyed by serviceInstanceId
    Given an NF profile for AMF with instance id "00000000-0000-4000-8000-000000000101" registered with nfServices "namf-comm" and "namf-evts"
    When an SMF queries NFDiscover for AMFs with requester-features "20"
    Then the NRF responds with status 200 OK
    And the SearchResult nfInstance has nfServiceList keyed by serviceInstanceId "namf-comm-1" and "namf-evts-1"
    And the SearchResult nfInstance has no nfServices
    And the SearchResult nrfSupportedFeatures is present

  Scenario: Discovery without requester-features returns nfServices array sorted by key and preserves unknown attributes
    Given an NF profile for AMF with instance id "00000000-0000-4000-8000-000000000102" registered with nfServiceList keys "svc-b" and "svc-a" and unknown nested service attribute "vendorExt"
    When an SMF queries NFDiscover for AMFs without requester-features
    Then the NRF responds with status 200 OK
    And the SearchResult nfInstance has nfServices ordered "svc-a", "svc-b"
    And the SearchResult nfInstance has no nfServiceList
    And every returned NFService still carries the unknown attribute "vendorExt"

  Scenario: NFProfileRetrieve returns nfServiceList only when Service-Map is requested
    Given an NF profile for AMF with instance id "00000000-0000-4000-8000-000000000103" registered with nfServices "namf-comm" and "namf-evts"
    When the consumer retrieves NF profile "00000000-0000-4000-8000-000000000103" with requester-features "1"
    Then the retrieved profile has nfServiceList and no nfServices
    When the consumer retrieves NF profile "00000000-0000-4000-8000-000000000103" without requester-features
    Then the retrieved profile has nfServices and no nfServiceList

  Scenario: NFStatusNotify body follows the subscriber's negotiated Service-Map
    Given a subscriber "sub-map" with nfStatusNotificationUri and requesterFeatures "1" for NF type "AMF"
    And a subscriber "sub-nomap" with nfStatusNotificationUri and no requesterFeatures for NF type "AMF"
    When an NF profile for AMF with instance id "00000000-0000-4000-8000-000000000104" registered with nfServices "namf-comm" is sent to the NRF
    Then subscriber "sub-map" is notified with an nfProfile carrying nfServiceList and no nfServices
    And subscriber "sub-nomap" is notified with an nfProfile carrying nfServices and no nfServiceList

  # ---- Inter-Plmn-Fqdn (Nnrf_NFManagement bit 3) ----

  Scenario: Intra-PLMN subscriber without Inter-Plmn-Fqdn gets no interPlmnFqdn, subscriber with bit 3 keeps it
    Given a subscriber "sub-no-ipf" with nfStatusNotificationUri and no requesterFeatures for NF type "AMF"
    And a subscriber "sub-ipf" with nfStatusNotificationUri and requesterFeatures "5" for NF type "AMF"
    When an NF profile for AMF with instance id "00000000-0000-4000-8000-000000000105" with interPlmnFqdn at profile and service level is sent to the NRF
    Then subscriber "sub-no-ipf" is notified with an nfProfile without interPlmnFqdn at profile or service level
    And subscriber "sub-ipf" is notified with an nfProfile that keeps interPlmnFqdn at profile and service level

  # ---- NFStatusSubscribe 201 SubscriptionData ----

  Scenario: NFStatusSubscribe 201 returns SubscriptionData echoing the request with subscriptionId, validityTime and nrfSupportedFeatures
    When a consumer sends NFStatusSubscribe with nfStatusNotificationUri "https://amf.example:8443/notify", reqNfType "AMF", validityTime "2030-01-01T00:00:00Z" and requesterFeatures "1"
    Then the NRF responds with status 201 Created
    And the response content type is "application/json"
    And the SubscriptionData body echoes nfStatusNotificationUri "https://amf.example:8443/notify" and reqNfType "AMF"
    And the SubscriptionData body has a subscriptionId
    And the SubscriptionData body has validityTime "2030-01-01T00:00:00Z"
    And the SubscriptionData body has nrfSupportedFeatures "5"
    And the SubscriptionData body does not echo requesterFeatures
    And the Location header ends with "/nnrf-nfm/v1/subscriptions/" followed by the subscriptionId

  Scenario: NFStatusSubscribe without validityTime gets the NRF default validityTime
    When a consumer sends NFStatusSubscribe with nfStatusNotificationUri "https://amf.example:8443/notify" and no validityTime
    Then the NRF responds with status 201 Created
    And the SubscriptionData body has a validityTime in the future

  # ---- ProblemDetails 400 ----

  Scenario Outline: NFStatusSubscribe with an invalid body is rejected with application/problem+json
    When a consumer sends NFStatusSubscribe with <body>
    Then the NRF responds with status 400 Bad Request
    And the response content type is "application/problem+json"
    And the cause is "<cause>"

    Examples:
      | body                                  | cause                |
      | a body without nfStatusNotificationUri | MANDATORY_IE_MISSING |
      | a malformed JSON body                  | INVALID_MSG_FORMAT   |

  Scenario: Non-hex requester-features on discovery is rejected with ProblemDetails
    When an SMF queries NFDiscover for AMFs with requester-features "zz"
    Then the NRF responds with status 400 Bad Request
    And the response content type is "application/problem+json"
    And the cause is "OPTIONAL_QUERY_PARAM_INCORRECT"
    And the invalidParams contains param "query requester-features"

  # ---- Legacy rel17 profile: byte-identical ----

  Scenario: Release profile rel17 keeps legacy NRF wire shapes
    Given a clean NRF instance is running with release profile "rel17"
    And an NF profile for AMF with instance id "00000000-0000-4000-8000-000000000106" registered with nfServices "namf-comm"
    When an SMF queries NFDiscover for AMFs with requester-features "20"
    Then the SearchResult nfInstance is returned exactly as registered with nfServices and no nfServiceList
    When a consumer sends NFStatusSubscribe with nfStatusNotificationUri "https://amf.example:8443/notify" and no requesterFeatures
    Then the NRF responds with status 201 Created
    And the subscribe response body contains only the attribute "subscriptionId"
    When a consumer sends NFStatusSubscribe with a body without nfStatusNotificationUri
    Then the NRF responds with status 400 Bad Request
    And the response content type is "text/plain; charset=utf-8"
