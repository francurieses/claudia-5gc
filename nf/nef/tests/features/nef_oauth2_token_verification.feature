@NEF-002
Feature: NEF verifies NRF-issued OAuth2 access tokens with the shared default secret (TS 29.522 §6)
  As an Application Function holding an access token issued by the NRF
  I want the NEF to verify the HS256 signature with the same secret the NRF signs with
  So that valid NRF-issued tokens are accepted and forged or expired tokens are rejected

  # Secret precedence (shared/oauth2.ResolveSecret): env OAUTH2_SECRET > YAML value > DefaultDevSecret.

  Background:
    Given a clean NEF instance is running
    And the NRF is available and accepts NF registrations
    And the NEF has registered with nfType "NEF" in the NRF
    And a mock BSF is available for Nbsf_Management_Discovery
    And a mock PCF is available for Npcf_PolicyAuthorization

  # ---------------------------------------------------------------------------
  # Scenario 1 — Happy path: default config accepts NRF default-secret token
  # TS 29.522 §6; TS 33.501 §13.4.1; TS 29.510 §6.3.5.2.2
  # ---------------------------------------------------------------------------
  @NEF-002
  Scenario: NEF with default config accepts a token signed with the NRF default dev secret
    Given the NEF is configured with no OAuth2 secret and OAUTH2_SECRET is unset
    And the mock BSF returns a PcfBinding with pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org" and pcfId "pcf-instance-001" for ipv4Addr "10.60.0.1"
    And the mock PCF returns 201 Created with appSessionId "appsess-001" for a Npcf_PolicyAuthorization_Create request
    And an OAuth2 bearer token signed with the shared/oauth2 DefaultDevSecret with scope "3gpp-as-session-with-qos" for scsAsId "af-001"
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.1" qosReference "GBR-VIDEO-LOW" and notificationDestination "https://af.example.com/notify"
    Then the NEF responds with status 201 Created
    And the response body contains a subscriptionId

  # ---------------------------------------------------------------------------
  # Scenario 2 — Error: token signed with a different secret
  # TS 33.501 §13.4.1 — signature verification failure -> 401 UNAUTHORIZED
  # ---------------------------------------------------------------------------
  @NEF-002
  Scenario: Token signed with a different secret is rejected with 401 UNAUTHORIZED
    Given the NEF is configured with no OAuth2 secret and OAUTH2_SECRET is unset
    And an OAuth2 bearer token signed with secret "some-other-secret" with scope "3gpp-as-session-with-qos" for scsAsId "af-001"
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.1" qosReference "GBR-VIDEO-LOW" and notificationDestination "https://af.example.com/notify"
    Then the NEF responds with status 401
    And the cause is "UNAUTHORIZED"

  # ---------------------------------------------------------------------------
  # Scenario 3 — Env override: OAUTH2_SECRET takes precedence over the default
  # TS 33.501 §13.4.1; ResolveSecret precedence env > YAML > DefaultDevSecret
  # ---------------------------------------------------------------------------
  @NEF-002
  Scenario: OAUTH2_SECRET override accepts its own token and rejects the default dev secret token
    Given the NEF is configured with no OAuth2 secret and OAUTH2_SECRET is set to "operator-secret-123"
    And the mock BSF returns a PcfBinding with pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org" and pcfId "pcf-instance-001" for ipv4Addr "10.60.0.1"
    And the mock PCF returns 201 Created with appSessionId "appsess-001" for a Npcf_PolicyAuthorization_Create request
    And an OAuth2 bearer token signed with secret "operator-secret-123" with scope "3gpp-as-session-with-qos" for scsAsId "af-001"
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.1" qosReference "GBR-VIDEO-LOW" and notificationDestination "https://af.example.com/notify"
    Then the NEF responds with status 201 Created
    Given an OAuth2 bearer token signed with the shared/oauth2 DefaultDevSecret with scope "3gpp-as-session-with-qos" for scsAsId "af-001"
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.1" qosReference "GBR-VIDEO-LOW" and notificationDestination "https://af.example.com/notify"
    Then the NEF responds with status 401
    And the cause is "UNAUTHORIZED"

  # ---------------------------------------------------------------------------
  # Scenario 4 — Rejection: expired token with the correct secret
  # TS 29.510 §6.3.5.2.2 (expiration) ; TS 33.501 §13.4.1 — exp check -> 401
  # ---------------------------------------------------------------------------
  @NEF-002
  Scenario: Expired token signed with the correct secret is rejected with 401
    Given the NEF is configured with no OAuth2 secret and OAUTH2_SECRET is unset
    And an expired OAuth2 bearer token signed with the shared/oauth2 DefaultDevSecret with scope "3gpp-as-session-with-qos" for scsAsId "af-001"
    When the AF sends a POST to "/3gpp-as-session-with-qos/v1/af-001/subscriptions" with ueIpv4Addr "10.60.0.1" qosReference "GBR-VIDEO-LOW" and notificationDestination "https://af.example.com/notify"
    Then the NEF responds with status 401
    And the cause is "UNAUTHORIZED"
