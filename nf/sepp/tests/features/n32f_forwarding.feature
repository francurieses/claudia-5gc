@sepp @n32f @REL19-9.2
Feature: SEPP N32-f forwarding in TLS mode (TS 29.500 §6.1.4.3; TS 29.573 §5.3.3; TS 33.501 §13.1)
  As the consumer-side SEPP (cSEPP) and producer-side SEPP (pSEPP)
  I want to forward HTTP/2 SBI messages unmodified over the N32-f TLS connection
  So that an NF in one PLMN reaches an NF in the other PLMN only through the SEPPs, without topology leakage

  # SPEC mode (REL19-9.2): scenarios only, no step definitions yet (implemented by REL19-9.5).
  # Design: docs/procedures/n32-roaming-interconnect.md.
  # Routing rule between SEPPs: TS 29.500 §6.1.4.3.4. NF<->SEPP inside a PLMN: §6.1.4.3.2 (telescopic
  # FQDN) and §6.1.4.3.3 (3gpp-Sbi-Target-apiRoot header). Telescopic FQDN format: TS 23.003 §28.5.2.
  # Rules (TS 29.500 §6.1.4.3.4, identical in V17.16.0 and V19.7.1; TS 33.501 §13.1.1):
  #   - Telescopic FQDNs are used between an NF and its own SEPP inside a PLMN, never on N32-f. The SEPP
  #     facing its NFs forms them: the cSEPP for target-NF FQDNs in discovery responses, the pSEPP for
  #     callback URIs in requests (TS 33.501 §13.1.1.1 a-c; TS 29.500 §6.1.4.3.2).
  #   - Both SEPPs signalled 3GppSbiTargetApiRootSupported = true -> request URI apiRoot := receiving SEPP's
  #     apiRoot; the header is forwarded unmodified, or inserted if the NF used a telescopic FQDN.
  #   - Otherwise the sending SEPP removes the header and sets the request URI apiRoot to the target NF's
  #     apiRoot (from the header or derived from the telescopic FQDN), forwarding "as is without reformatting".
  #   - A request carrying both a telescopic FQDN and the header: the SEPP ignores the header (§6.1.4.3.3).
  # ProblemDetails causes: rel19 CONTEXT_NOT_FOUND 403 (TS 29.573 §5.3.3.4, CR 0158 V18.5.0) and
  # TARGET_PLMN_NOT_REACHABLE 504 (TS 29.500 V19.7.1 Table 5.2.7.4-1); rel17 has neither (see E5/E7).

  Background:
    Given the vPLMN SEPP "sepp.5gc.mnc001.mcc001.3gppnetwork.org" serves PLMN "001/01" (cSEPP)
    And the hPLMN SEPP "sepp.5gc.mnc002.mcc001.3gppnetwork.org" serves PLMN "001/02" (pSEPP)
    And the hPLMN NRF "nrf.5gc.mnc002.mcc001.3gppnetwork.org" is reachable only from the pSEPP
    And a producer mock for Nnrf_NFDiscovery on the hPLMN NRF returns a SearchResult with one UDM profile
    And the N32 mutual TLS trust bundle contains the roaming-partner CA

  # ---------------------------------------------------------------- happy path
  @happy
  Scenario Outline: Forwarding with 3gpp-Sbi-Target-apiRoot negotiated by both SEPPs (<profile> profile)
    # TS 29.500 §6.1.4.3.4: request URI apiRoot := receiving SEPP apiRoot; header forwarded unmodified.
    Given both SEPPs run the "<profile>" release profile
    And an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS and "3GppSbiTargetApiRootSupported" true on both sides
    When the vAMF sends GET "/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF" to the cSEPP with header "3gpp-Sbi-Target-apiRoot: https://nrf.5gc.mnc002.mcc001.3gppnetwork.org"
    Then the cSEPP sends the request over the N32-f TLS connection with the request URI apiRoot of the pSEPP
    And the forwarded request carries "3gpp-Sbi-Target-apiRoot: https://nrf.5gc.mnc002.mcc001.3gppnetwork.org" unmodified
    And the path, query and body are unchanged
    And the pSEPP routes the request to the hPLMN NRF without the "3gpp-Sbi-Target-apiRoot" header
    # pSEPP acts as the SCP towards its NFs (TS 29.500 §6.1.4.3.3, §6.10.2: header removed when forwarding).
    And the vAMF receives status 200 with the SearchResult
    And the cSEPP and pSEPP logs have procedure "N32fForwarding" interface "N32f" with the same correlation_id

    Examples:
      | profile |
      | rel17   |
      | rel19   |

  @happy
  Scenario: Forwarding when at least one SEPP does not support the header (TS 29.500 §6.1.4.3.4)
    Given both SEPPs run the "rel17" release profile
    And an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS and "3GppSbiTargetApiRootSupported" true on the cSEPP and false on the pSEPP
    When the vAMF sends GET "/nnrf-disc/v1/nf-instances?target-nf-type=UDM" to the cSEPP with header "3gpp-Sbi-Target-apiRoot: https://nrf.5gc.mnc002.mcc001.3gppnetwork.org"
    Then the cSEPP removes the "3gpp-Sbi-Target-apiRoot" header
    And the cSEPP sets the request URI apiRoot on N32-f to "https://nrf.5gc.mnc002.mcc001.3gppnetwork.org"
    And the pSEPP routes the request to the hPLMN NRF
    And the vAMF receives status 200

  @happy
  Scenario: NF uses a telescopic FQDN towards its own SEPP (TS 29.500 §6.1.4.3.2)
    Given both SEPPs run the "rel17" release profile
    And an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS and "3GppSbiTargetApiRootSupported" false on both sides
    When the vAMF sends GET "/nnrf-disc/v1/nf-instances?target-nf-type=UDM" to the cSEPP with :authority set to the telescopic FQDN of "nrf.5gc.mnc002.mcc001.3gppnetwork.org" under the cSEPP domain
    Then the cSEPP derives the target apiRoot "https://nrf.5gc.mnc002.mcc001.3gppnetwork.org" from the telescopic FQDN
    And the cSEPP sets the N32-f request URI apiRoot to that target apiRoot
    And the pSEPP routes the request to the hPLMN NRF
    And the vAMF receives status 200
    # TS 23.003 §28.5.2: <label>.<FQDN of the SEPP>; the label is a single DNS label and its construction is
    # implementation specific (NOTE 1). The project encoding is therefore an implementation choice.

  @happy
  Scenario: Telescopic FQDN from the NF with header support on both SEPPs, the cSEPP inserts the header (TS 29.500 §6.1.4.3.4)
    Given both SEPPs run the "rel17" release profile
    And an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS and "3GppSbiTargetApiRootSupported" true on both sides
    When the vAMF sends GET "/nnrf-disc/v1/nf-instances?target-nf-type=UDM" to the cSEPP with :authority set to the telescopic FQDN of "nrf.5gc.mnc002.mcc001.3gppnetwork.org" under the cSEPP domain
    Then the cSEPP sends the request over the N32-f TLS connection with the request URI apiRoot of the pSEPP
    And the forwarded request carries "3gpp-Sbi-Target-apiRoot: https://nrf.5gc.mnc002.mcc001.3gppnetwork.org"
    And the pSEPP routes the request to the hPLMN NRF

  @security
  Scenario: Telescopic FQDN plus 3gpp-Sbi-Target-apiRoot header, the header is ignored (TS 29.500 §6.1.4.3.3 NOTE 1)
    Given an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS
    When the vAMF sends a request to the cSEPP with a telescopic FQDN for "nrf.5gc.mnc002.mcc001.3gppnetwork.org" and header "3gpp-Sbi-Target-apiRoot: https://udm.5gc.mnc002.mcc001.3gppnetwork.org"
    Then the cSEPP routes the request using the telescopic FQDN only
    And the request never reaches "udm.5gc.mnc002.mcc001.3gppnetwork.org"

  @happy
  Scenario Outline: Discovery response FQDNs are made telescopic by the cSEPP (<profile> profile)
    # TS 33.501 §13.1.1.1 a: the cSEPP rewrites each target NF FQDN in the Discovery response to a telescopic
    # FQDN under its own domain. Applies only when the vAMF uses telescopic FQDNs: the SEPP should skip the
    # conversion if the request carried 3gpp-Sbi-Target-apiRoot (TS 29.500 §6.1.4.3.1).
    # Topology hiding on the pSEPP (removing internal IPs) is operator policy (TS 23.003 §28.5.2 "may be
    # rewritten by the other PLMN SEPP for topology hiding"), not a TS mandate.
    Given both SEPPs run the "<profile>" release profile
    And an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS
    And topology hiding is enabled on the pSEPP
    When the vAMF discovers UDM through the cSEPP without a "3gpp-Sbi-Target-apiRoot" header and the hPLMN NRF returns a profile with fqdn "udm.5gc.mnc002.mcc001.3gppnetwork.org" and ipv4Addresses ["10.20.0.5"]
    Then the SearchResult on N32-f contains no internal IPv4 address of the hPLMN
    And every NF FQDN in the SearchResult seen by the vAMF is a telescopic FQDN under the cSEPP domain
    And no SearchResult on N32-f contains a telescopic FQDN
    And no "Via" or "X-Forwarded-For" header reaches the vAMF

    Examples:
      | profile |
      | rel17   |
      | rel19   |

  @happy
  Scenario: Callback URI in a request is rewritten to a telescopic FQDN by the pSEPP (TS 29.500 §6.1.4.3.2; TS 33.501 §13.1.1.1 b)
    Given an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS and "3GppSbiTargetApiRootSupported" false on both sides
    And the pSEPP uses telescopic FQDNs towards the hPLMN NFs
    When the vAMF sends a subscription request to the hUDM with callback URI "https://amf.5gc.mnc001.mcc001.3gppnetwork.org/namf-callback/v1/x"
    Then the callback URI on N32-f is still "https://amf.5gc.mnc001.mcc001.3gppnetwork.org/namf-callback/v1/x"
    And the callback URI seen by the hUDM has the telescopic FQDN of the vAMF under the pSEPP domain

  @happy
  Scenario: Request and response bodies pass through unmodified in TLS mode
    Given an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS
    When the vAMF sends a POST with a JSON body of 20 KiB through the cSEPP
    Then the pSEPP forwards the identical body bytes to the producer
    And no JOSE (JWE/JWS) protection is applied on N32-f

  # ----------------------------------------------------------------------- errors
  @error @E5
  Scenario Outline: E5 N32-f request without an active context is rejected with 403 (<profile>)
    Given both SEPPs run the "<profile>" release profile
    And no N32 context exists for the PLMN pair 001/01 - 001/02 on the pSEPP
    When the cSEPP forwards an N32-f request for PLMN "001/02"
    Then the pSEPP responds with status 403 and a ProblemDetails body
    And the request is not forwarded to any internal NF
    And the pSEPP log has procedure "N32fForwarding" result "REJECT"
    # 403 confirmed for rel19 by TS 29.573 §5.3.3.4 Table 5.3.3.4-1; rel17 has no such rule (CR 0158,
    # V18.5.0), so 403 there is a project choice. Rel-17 also has no CONTEXT_NOT_FOUND cause.

    Examples:
      | profile |
      | rel17   |
      | rel19   |

  @error @E5 @rel19
  Scenario: E5 Rel-19 N32-f request with no related N32-c context carries cause CONTEXT_NOT_FOUND
    # TS 29.573 V19.7.0 §5.3.3.4 Table 5.3.3.4-1; correlation per §5.3.3.2.1 (peer FQDN in the TLS
    # certificate vs "sender"/"senderN32fFqdn" of the N32-c context).
    Given both SEPPs run the "rel19" release profile
    And no N32 context exists for the PLMN pair 001/01 - 001/02 on the pSEPP
    When the cSEPP forwards an N32-f request for PLMN "001/02"
    Then the pSEPP responds with status 403 and a ProblemDetails body with cause "CONTEXT_NOT_FOUND"

  @error @E5
  Scenario: cSEPP triggers a handshake and retries once when it has no context
    Given no N32 context exists for the PLMN pair 001/01 - 001/02 on the cSEPP
    When the vAMF sends a request for the hPLMN NRF to the cSEPP
    Then the cSEPP first sends exchange-capability to the pSEPP
    And after a 200 response the cSEPP forwards the original request exactly once
    And the vAMF receives status 200

  @error @E5
  Scenario: Handshake failure during lazy establishment fails the request without a retry loop
    Given no N32 context exists for the PLMN pair 001/01 - 001/02 on the cSEPP
    And the pSEPP rejects exchange-capability with status 403
    When the vAMF sends a request for the hPLMN NRF to the cSEPP
    Then the cSEPP sends exactly one exchange-capability
    And the vAMF receives a 4xx or 5xx ProblemDetails response
    And the cSEPP does not forward the original request

  @error @E3 @security
  Scenario: N32-f ingress rejects a peer whose certificate PLMN differs from the context PLMN
    Given an N32 context exists for the PLMN pair 001/01 - 001/02
    And a peer connects to the pSEPP N32 listener presenting a certificate with SAN "sepp.5gc.mnc005.mcc001.3gppnetwork.org"
    When the peer sends an N32-f request claiming PLMN "001/01"
    Then the pSEPP rejects it with status 403 or closes the TLS connection
    # TS 33.501 §13.1.2: an N32-f certificate with PLMN-IDs not in the correlated N32-c certificate shall be rejected.
    And the request is not forwarded to any internal NF
    And the pSEPP log has procedure "N32fForwarding" result "REJECT"

  @error @E7
  Scenario Outline: E7 peer SEPP unreachable (<profile>, <failure>)
    # TS 29.500 Table 5.2.7.4-1 (errors generated by the SCP/SEPP). Rel-19 V19.7.1 defines
    # TARGET_PLMN_NOT_REACHABLE 504 for "issues on N32 connection"; Rel-17 V17.16.0 lacks it, so rel17 uses
    # the closest code, TARGET_NF_NOT_REACHABLE 504 (§5.2.7.4: map to the most similar code).
    Given both SEPPs run the "<profile>" release profile
    And an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS
    And the pSEPP N32 endpoint <failure>
    When the vAMF sends a request for the hPLMN NRF to the cSEPP
    Then the cSEPP responds to the vAMF with status 504 and a ProblemDetails body with cause "<cause>"
    And the cSEPP log has procedure "N32fForwarding" result "FAILURE"

    Examples:
      | profile | failure                         | cause                     |
      | rel17   | refuses TCP connections         | TARGET_NF_NOT_REACHABLE   |
      | rel17   | fails the TLS handshake         | TARGET_NF_NOT_REACHABLE   |
      | rel17   | does not answer within timeout  | TARGET_NF_NOT_REACHABLE   |
      | rel19   | refuses TCP connections         | TARGET_PLMN_NOT_REACHABLE |
      | rel19   | fails the TLS handshake         | TARGET_PLMN_NOT_REACHABLE |
      | rel19   | does not answer within timeout  | TARGET_PLMN_NOT_REACHABLE |

  @error @E8
  Scenario Outline: E8 target apiRoot cannot be resolved to an internal NF on the pSEPP (<case>)
    Given an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS
    When the cSEPP forwards a request whose target apiRoot is <case>
    Then the pSEPP responds with status 404 or 502 and a ProblemDetails body
    And the request is not forwarded to any host outside the hPLMN

    Examples:
      | case                                                       |
      | "https://unknown.5gc.mnc002.mcc001.3gppnetwork.org"        |
      | "https://nrf.5gc.mnc099.mcc999.3gppnetwork.org" (foreign)  |
      | an unparsable telescopic label                             |

  # ----------------------------------------------------------------------- security
  @security
  Scenario: Internal NF identities never appear on N32-f
    Given an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS
    When the vAMF sends a request with headers "Via: 1.1 amf-internal" and "X-Forwarded-For: 10.10.0.7" through the cSEPP
    Then the request on N32-f carries neither "Via" nor "X-Forwarded-For" nor any internal IP address
    And the "X-Correlation-Id" header is propagated unchanged

  @security
  Scenario: The SEPP logs never contain bearer tokens
    Given an N32 context exists for the PLMN pair 001/01 - 001/02 with TLS
    When the vAMF sends a request with header "Authorization: Bearer secret-token-123" through the cSEPP
    Then no SEPP log line contains "secret-token-123"

  @security
  Scenario: Internal SBI listener and N32 listener use separate trust stores
    When a client presents a certificate issued by the internal core CA to the N32 listener
    Then the TLS handshake fails
    And when a client presents a certificate issued by the roaming-partner CA to the internal SBI listener the TLS handshake fails

  # ------------------------------------------------------------------- Rel-17 / Rel-19
  @rel19 @profile
  Scenario: Mixed-release peers negotiate the intersection of supportedFeatures
    Given the cSEPP runs the "rel19" release profile and the pSEPP runs the "rel17" release profile
    When the cSEPP performs exchange-capability towards the pSEPP offering Rel-19 supportedFeatures bits
    Then the pSEPP returns supportedFeatures that are a subset of both sides' supported features
    And forwarding over N32-f works as in the Rel-17 profile
