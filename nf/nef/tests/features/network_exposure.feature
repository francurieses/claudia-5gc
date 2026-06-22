Feature: Nnef_AFsessionWithQoS — AsSessionWithQoS Create / Get / Delete (TS 29.522 §4.4.13)
  As an Application Function requesting guaranteed QoS for an application flow
  I want to create an AsSessionWithQoS subscription with the NEF by supplying a UE IPv4 address and a qosReference
  So that the NEF discovers the serving PCF via BSF and maps the request onto a PCF policy-authorization, returning a subscriptionId

  Background:
    Given a clean NEF instance is running
    And the NRF is available and accepts NF registrations
    And the NEF has registered with nfType "NEF" in the NRF
    And a mock BSF is available for Nbsf_Management_Discovery
    And a mock PCF is available for Npcf_PolicyAuthorization

  # ---------------------------------------------------------------------------
  # Scenario 1 — Happy path: AF creates an AsSessionWithQoS subscription (AC 1)
  # TS 29.522 §4.4.13.2.5 — POST subscriptions → BSF discovery → PCF create → 201
  # ---------------------------------------------------------------------------
  Scenario: AF creates an AsSessionWithQoS subscription for a UE with a registered PCF binding
    Given a valid OAuth2 bearer token with scope "nnef-afsessionwithqos" for scsAsId "af-001"
    And the mock BSF returns a PcfBinding with pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org" and pcfId "pcf-instance-001" for ipv4Addr "10.60.0.1"
    And the mock PCF returns 201 Created with appSessionId "appsess-001" for a Npcf_PolicyAuthorization_Create request
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.1" qosReference "GBR-VIDEO-LOW" and notificationDestination "https://af.example.com/notify"
    Then the NEF responds with status 201 Created
    And the response Location header contains "/3gpp-as-session-with-qos/v1/af-001/subscriptions/"
    And the response body contains an AsSessionWithQoSSubscription with ueIpv4Addr "10.60.0.1" and qosReference "GBR-VIDEO-LOW"
    And the response body contains a subscriptionId
    And the mock BSF received a GET to "/nbsf-management/v1/pcfBindings" with query parameter ipv4Addr "10.60.0.1"
    And the mock PCF received a POST to "/npcf-policyauthorization/v1/app-sessions" with ueIpv4 "10.60.0.1" and qosReference "GBR-VIDEO-LOW"

  # ---------------------------------------------------------------------------
  # Scenario 2 — OAuth2: missing bearer token is rejected with 401 (AC 3)
  # TS 29.500 §5.2.7.2, TS 29.522 §6 — absent Authorization header → 401 UNAUTHORIZED
  # ---------------------------------------------------------------------------
  Scenario: Request without a bearer token is rejected with 401 Unauthorized
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.1" qosReference "GBR-VIDEO-LOW" and no Authorization header
    Then the NEF responds with status 401
    And the cause is "UNAUTHORIZED"

  # ---------------------------------------------------------------------------
  # Scenario 3 — OAuth2: bearer token with wrong scope is rejected with 403 (AC 3)
  # TS 29.522 §6 — valid token but wrong scope → 403 UNAUTHORIZED_AF
  # ---------------------------------------------------------------------------
  Scenario: Request with a bearer token that has an incorrect scope is rejected with 403 Forbidden
    Given a valid OAuth2 bearer token with scope "nnrf-disc" for scsAsId "af-001"
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.1" qosReference "GBR-VIDEO-LOW" and notificationDestination "https://af.example.com/notify"
    Then the NEF responds with status 403
    And the cause is "UNAUTHORIZED_AF"

  # ---------------------------------------------------------------------------
  # Scenario 4 — Spec deviation: missing UE address → 400 MANDATORY_IE_MISSING (AC 4)
  # TS 29.522 §5.14.2.1.2 + TS 29.500 §5.2.7.2 — at least one UE address key is required
  # ---------------------------------------------------------------------------
  Scenario: Create subscription without any UE address is rejected with 400 MANDATORY_IE_MISSING
    Given a valid OAuth2 bearer token with scope "nnef-afsessionwithqos" for scsAsId "af-001"
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with qosReference "GBR-VIDEO-LOW" and notificationDestination "https://af.example.com/notify" but no ueIpv4Addr
    Then the NEF responds with status 400
    And the cause is "MANDATORY_IE_MISSING"

  # ---------------------------------------------------------------------------
  # Scenario 5 — Spec deviation: missing qosReference → 400 MANDATORY_IE_MISSING (AC 4)
  # TS 29.522 §5.14.2.1.2 — qosReference is a mandatory IE
  # ---------------------------------------------------------------------------
  Scenario: Create subscription without qosReference is rejected with 400 MANDATORY_IE_MISSING
    Given a valid OAuth2 bearer token with scope "nnef-afsessionwithqos" for scsAsId "af-001"
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.1" and notificationDestination "https://af.example.com/notify" but no qosReference
    Then the NEF responds with status 400
    And the cause is "MANDATORY_IE_MISSING"

  # ---------------------------------------------------------------------------
  # Scenario 6 — BSF discovery miss: no PCF binding for the UE IP → 404 (AC 5)
  # TS 29.521 §5.2.2.4.4 — BSF 404 → NEF maps to northbound 404 PCF_BINDING_NOT_FOUND
  # [VERIFY: confirm exact Rel-17 cause string against TS29522 OpenAPI — see B-1 in procedure doc]
  # ---------------------------------------------------------------------------
  Scenario: Create subscription when no PCF binding exists for the UE IP returns 404
    Given a valid OAuth2 bearer token with scope "nnef-afsessionwithqos" for scsAsId "af-001"
    And the mock BSF returns 404 for ipv4Addr "10.60.0.99"
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.99" qosReference "GBR-VIDEO-LOW" and notificationDestination "https://af.example.com/notify"
    Then the NEF responds with status 404
    And the cause is "PCF_BINDING_NOT_FOUND"

  # ---------------------------------------------------------------------------
  # Scenario 7 — PCF rejects the authorization → 403 propagated to AF (AC 6)
  # TS 29.514 §5.2.2.2.4 — PCF 403 (e.g. unauthorized qosReference) → NEF propagates 403
  # ---------------------------------------------------------------------------
  Scenario: Create subscription when PCF rejects authorization propagates 403 to the AF
    Given a valid OAuth2 bearer token with scope "nnef-afsessionwithqos" for scsAsId "af-001"
    And the mock BSF returns a PcfBinding with pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org" and pcfId "pcf-instance-001" for ipv4Addr "10.60.0.2"
    And the mock PCF returns 403 for a Npcf_PolicyAuthorization_Create request
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.2" qosReference "UNAUTHORIZED-QOS-REF" and notificationDestination "https://af.example.com/notify"
    Then the NEF responds with status 403

  # ---------------------------------------------------------------------------
  # Scenario 8 — GET an existing subscription by subscriptionId → 200 (AC 7)
  # TS 29.522 §4.4.13.2.5 — GET …/{subscriptionId} → 200 AsSessionWithQoSSubscription
  # ---------------------------------------------------------------------------
  Scenario: AF retrieves an existing AsSessionWithQoS subscription by subscriptionId
    Given a valid OAuth2 bearer token with scope "nnef-afsessionwithqos" for scsAsId "af-002"
    And the mock BSF returns a PcfBinding with pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org" and pcfId "pcf-instance-001" for ipv4Addr "10.60.0.3"
    And the mock PCF returns 201 Created with appSessionId "appsess-002" for a Npcf_PolicyAuthorization_Create request
    And an AsSessionWithQoS subscription has been created for scsAsId "af-002" with ueIpv4Addr "10.60.0.3" qosReference "GBR-AUDIO" and the subscriptionId has been stored
    When the AF sends a GET to "/3gpp-as-session-with-qos/v1/af-002/subscriptions/{subscriptionId}" using the stored subscriptionId
    Then the NEF responds with status 200 OK
    And the response body contains an AsSessionWithQoSSubscription with ueIpv4Addr "10.60.0.3" and qosReference "GBR-AUDIO"

  # ---------------------------------------------------------------------------
  # Scenario 9 — GET an unknown subscriptionId → 404 (AC 8)
  # TS 29.522 §4.4.13.2.5 — unknown subscriptionId → 404 ProblemDetails
  # ---------------------------------------------------------------------------
  Scenario: AF retrieves a non-existent subscriptionId returns 404
    Given a valid OAuth2 bearer token with scope "nnef-afsessionwithqos" for scsAsId "af-001"
    When the AF sends a GET to "/3gpp-as-session-with-qos/v1/af-001/subscriptions/00000000-0000-0000-0000-000000000000"
    Then the NEF responds with status 404

  # ---------------------------------------------------------------------------
  # Scenario 10 — DELETE an existing subscription → 204 + PCF app-session deleted (AC 8)
  # TS 29.522 §4.4.13.2.5 + TS 29.514 §5.2.2.4 — DELETE → PCF DELETE → 204
  # ---------------------------------------------------------------------------
  Scenario: AF deletes an AsSessionWithQoS subscription and the NEF relays deletion to the PCF
    Given a valid OAuth2 bearer token with scope "nnef-afsessionwithqos" for scsAsId "af-003"
    And the mock BSF returns a PcfBinding with pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org" and pcfId "pcf-instance-001" for ipv4Addr "10.60.0.4"
    And the mock PCF returns 201 Created with appSessionId "appsess-003" for a Npcf_PolicyAuthorization_Create request
    And the mock PCF returns 204 No Content for a Npcf_PolicyAuthorization_Delete request
    And an AsSessionWithQoS subscription has been created for scsAsId "af-003" with ueIpv4Addr "10.60.0.4" qosReference "GBR-VIDEO-LOW" and the subscriptionId has been stored
    When the AF sends a DELETE to "/3gpp-as-session-with-qos/v1/af-003/subscriptions/{subscriptionId}" using the stored subscriptionId
    Then the NEF responds with status 204 No Content
    And the mock PCF received a DELETE to "/npcf-policyauthorization/v1/app-sessions/appsess-003"

  # ---------------------------------------------------------------------------
  # Scenario 11 — DELETE then GET the same subscriptionId → 404 (AC 8)
  # TS 29.522 §4.4.13.2.5 — subscription no longer exists after deletion
  # ---------------------------------------------------------------------------
  Scenario: GET after DELETE on the same subscriptionId returns 404
    Given a valid OAuth2 bearer token with scope "nnef-afsessionwithqos" for scsAsId "af-004"
    And the mock BSF returns a PcfBinding with pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org" and pcfId "pcf-instance-001" for ipv4Addr "10.60.0.5"
    And the mock PCF returns 201 Created with appSessionId "appsess-004" for a Npcf_PolicyAuthorization_Create request
    And the mock PCF returns 204 No Content for a Npcf_PolicyAuthorization_Delete request
    And an AsSessionWithQoS subscription has been created for scsAsId "af-004" with ueIpv4Addr "10.60.0.5" qosReference "GBR-VIDEO-LOW" and the subscriptionId has been stored
    And the AF has deleted the subscription at "/3gpp-as-session-with-qos/v1/af-004/subscriptions/{subscriptionId}" using the stored subscriptionId
    When the AF sends a GET to "/3gpp-as-session-with-qos/v1/af-004/subscriptions/{subscriptionId}" using the stored subscriptionId
    Then the NEF responds with status 404

  # ---------------------------------------------------------------------------
  # Scenario 12 — DELETE an unknown subscriptionId → 404 (AC 8)
  # TS 29.522 §4.4.13.2.5 — unknown subscriptionId on DELETE → 404 ProblemDetails
  # ---------------------------------------------------------------------------
  Scenario: DELETE a non-existent subscriptionId returns 404
    Given a valid OAuth2 bearer token with scope "nnef-afsessionwithqos" for scsAsId "af-001"
    When the AF sends a DELETE to "/3gpp-as-session-with-qos/v1/af-001/subscriptions/00000000-0000-0000-0000-000000000000"
    Then the NEF responds with status 404
