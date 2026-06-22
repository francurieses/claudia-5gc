Feature: Nbsf_Management — PCF Binding Register / Deregister / Discovery (TS 29.521 §5 / TS 23.501 §6.2.16)
  As a PCF creating and deleting SM policy associations
  I want to register and deregister PCF bindings with the BSF
  So that consumers can discover the serving PCF for a UE by its IP address

  Background:
    Given a clean BSF instance is running
    And the NRF is available and accepts NF registrations
    And the BSF has registered with nfType "BSF" in the NRF

  # ---------------------------------------------------------------------------
  # Scenario 1 — Register a PCF binding (AC 1, happy path)
  # TS 29.521 §5.2.2.2 — POST /nbsf-management/v1/pcfBindings → 201 + Location
  # ---------------------------------------------------------------------------
  Scenario: PCF registers a binding and receives 201 Created with Location header and echoed PcfBinding
    When the PCF sends a PcfBinding Register request with supi "imsi-001010000000001" dnn "internet" snssai sst 1 sd "000001" ipv4Addr "10.60.0.1" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org"
    Then the BSF responds with status 201 Created
    And the response Location header contains "/nbsf-management/v1/pcfBindings/"
    And the response body contains a PcfBinding with ipv4Addr "10.60.0.1" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org"

  # ---------------------------------------------------------------------------
  # Scenario 2 — Discovery by UE IPv4 address (AC 3, happy path)
  # TS 29.521 §5.2.2.4 — GET /nbsf-management/v1/pcfBindings?ipv4Addr=… → 200
  # ---------------------------------------------------------------------------
  Scenario: Consumer discovers the serving PCF by UE IPv4 address
    Given a PcfBinding is registered for supi "imsi-001010000000001" dnn "internet" snssai sst 1 sd "000001" ipv4Addr "10.60.0.2" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org"
    When the consumer sends a Discovery request with query ipv4Addr "10.60.0.2"
    Then the BSF responds with status 200 OK
    And the response body contains a PcfBinding with ipv4Addr "10.60.0.2" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org"

  # ---------------------------------------------------------------------------
  # Scenario 3 — Discovery with no matching binding (AC 3, error path)
  # TS 29.521 §5.2.2.4.4 — no match → 404
  # ---------------------------------------------------------------------------
  Scenario: Discovery for an IP with no registered binding returns 404
    Given no PcfBinding is registered for ipv4Addr "10.60.0.99"
    When the consumer sends a Discovery request with query ipv4Addr "10.60.0.99"
    Then the BSF responds with status 404

  # ---------------------------------------------------------------------------
  # Scenario 4 — Deregister removes the binding; subsequent discovery returns 404 (AC 2)
  # TS 29.521 §5.2.2.3 — DELETE /nbsf-management/v1/pcfBindings/{bindingId} → 204
  # ---------------------------------------------------------------------------
  Scenario: PCF deregisters a binding and subsequent discovery for that IP returns 404
    Given a PcfBinding is registered for supi "imsi-001010000000001" dnn "internet" snssai sst 1 sd "000001" ipv4Addr "10.60.0.3" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org"
    And the binding ID for ipv4Addr "10.60.0.3" has been stored
    When the PCF sends a Deregister request for the stored binding ID
    Then the BSF responds with status 204 No Content
    When the consumer sends a Discovery request with query ipv4Addr "10.60.0.3"
    Then the BSF responds with status 404

  # ---------------------------------------------------------------------------
  # Scenario 5 — Register with missing mandatory IE → 400 MANDATORY_IE_MISSING (AC 1 spec deviation)
  # TS 29.521 §5.2.2.2.4 + TS 29.500 §5.2.7.2
  # ---------------------------------------------------------------------------
  Scenario: Register with missing mandatory dnn is rejected with 400 MANDATORY_IE_MISSING
    When the PCF sends a PcfBinding Register request with supi "imsi-001010000000001" snssai sst 1 sd "000001" ipv4Addr "10.60.0.4" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org" but no dnn
    Then the BSF responds with status 400
    And the cause is "MANDATORY_IE_MISSING"

  Scenario: Register with missing mandatory snssai is rejected with 400 MANDATORY_IE_MISSING
    When the PCF sends a PcfBinding Register request with supi "imsi-001010000000001" dnn "internet" ipv4Addr "10.60.0.5" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org" but no snssai
    Then the BSF responds with status 400
    And the cause is "MANDATORY_IE_MISSING"

  # ---------------------------------------------------------------------------
  # Scenario 6 — Duplicate Register → 403 EXISTING_BINDING_INFO_FOUND (AC 1 spec deviation)
  # TS 29.521 §5.2.2.2.4 — same (ipv4Addr, dnn, snssai) key already bound
  # ---------------------------------------------------------------------------
  Scenario: Registering a binding for an already-bound UE IP returns 403 EXISTING_BINDING_INFO_FOUND
    Given a PcfBinding is registered for supi "imsi-001010000000001" dnn "internet" snssai sst 1 sd "000001" ipv4Addr "10.60.0.6" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org"
    When the PCF sends a PcfBinding Register request with supi "imsi-001010000000001" dnn "internet" snssai sst 1 sd "000001" ipv4Addr "10.60.0.6" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org"
    Then the BSF responds with status 403
    And the cause is "EXISTING_BINDING_INFO_FOUND"

  # ---------------------------------------------------------------------------
  # Scenario 7 — Discovery by SUPI returns the binding
  # TS 29.521 §5.2.2.4.3.1 — supi is a valid query parameter for discovery
  # ---------------------------------------------------------------------------
  Scenario: Consumer discovers the serving PCF by SUPI
    Given a PcfBinding is registered for supi "imsi-001010000000002" dnn "internet" snssai sst 1 sd "000001" ipv4Addr "10.60.0.7" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org"
    When the consumer sends a Discovery request with query supi "imsi-001010000000002"
    Then the BSF responds with status 200 OK
    And the response body contains a PcfBinding with ipv4Addr "10.60.0.7" and pcfFqdn "pcf.5gc.mnc001.mcc001.3gppnetwork.org"

  # ---------------------------------------------------------------------------
  # Scenario 8 — Discovery with no query parameter → 400 MANDATORY_IE_MISSING
  # TS 29.521 §5.2.2.4.4 — at least one binding-identifying parameter is required
  # ---------------------------------------------------------------------------
  Scenario: Discovery with no query parameter returns 400 MANDATORY_IE_MISSING
    When the consumer sends a Discovery request with no query parameters
    Then the BSF responds with status 400
    And the cause is "MANDATORY_IE_MISSING"

  # ---------------------------------------------------------------------------
  # Scenario 9 — Deregister an unknown bindingId → 404
  # TS 29.521 §5.2.2.3.4 — unknown bindingId has no specific cause; ProblemDetails only
  # ---------------------------------------------------------------------------
  Scenario: Deregister with an unknown bindingId returns 404
    When the PCF sends a Deregister request for bindingId "00000000-0000-0000-0000-000000000000"
    Then the BSF responds with status 404

  # ---------------------------------------------------------------------------
  # Scenario 10 — PCF SM policy lifecycle drives Register then Deregister (AC 2)
  # TS 29.521 §5.2.2.2 (register) + §5.2.2.3 (deregister) via PCF client integration
  # ---------------------------------------------------------------------------
  Scenario: PCF registers a binding on SmPolicyCreate and deregisters it on SmPolicyDelete
    Given a mock BSF is listening on the nbsf-management endpoint
    When the SMF sends a SmPolicyControl_Create request for supi "imsi-001010000000001" dnn "internet" snssai sst 1 sd "000001" and ipv4Addr "10.60.0.8"
    Then the mock BSF receives a POST to "/nbsf-management/v1/pcfBindings" with ipv4Addr "10.60.0.8" and dnn "internet"
    When the SMF sends a SmPolicyControl_Delete request for that sm-policy association
    Then the mock BSF receives a DELETE to "/nbsf-management/v1/pcfBindings/{bindingId}"
