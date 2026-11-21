@SEC-006
Feature: NAS ciphering algorithm negotiation and use - 128-NEA1 (SNOW 3G) / 128-NEA3 (ZUC) (TS 33.501 §6.7.1.1, §6.7.2, Annex D.2/D.4; TS 24.501 §4.4.4, §4.4.6, §5.4.2, §9.11.3.34)
  As the AMF serving a UE that supports a subset of the 5G encryption algorithms
  I want to select the highest-priority allowed NEA the UE supports and signal it in the SECURITY MODE COMMAND
  So that every later N1 message is ciphered and deciphered with the negotiated algorithm

  # Design: docs/procedures/nas-security-algorithms.md (§4 IEs, §5 error cases, §7 dispatch and config).
  # Config: nas_security.ciphering_order (env AMF_NAS_CIPHERING_ORDER), default "NEA2, NEA1, NEA3, NEA0".
  # Selected NAS security algorithms IE (TS 24.501 §9.11.3.34): octet = (ciphering << 4) | integrity; EA 0 NEA0, 1 NEA1, 2 NEA2, 3 NEA3.
  # BEARER = 0x01 (3GPP access), DIRECTION 0 UL / 1 DL (TS 33.501 §6.4.3.1, §6.4.4).

  Background:
    Given the AMF NAS handler is running with an AUSF mock returning a KAMF
    And a UE "imsi-001010000000001" starts an initial registration over 3GPP access

  # TS 33.501 §6.7.1.1; legacy byte-identity (docs §7 Selection)
  Scenario: Default ordered list with a UE supporting NEA0-NEA3 selects NEA2 and the SECURITY MODE COMMAND bytes are unchanged
    Given the AMF ciphering order is the default "NEA2, NEA1, NEA3, NEA0"
    And the UE security capability advertises EA0, EA1, EA2, EA3 and IA0, IA1, IA2, IA3
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE ciphering field is 2
    And the SECURITY MODE COMMAND bytes are identical to the legacy golden SECURITY MODE COMMAND

  # TS 33.501 §6.7.1.1, §6.7.2; TS 24.501 §4.4.4; Annex D.2.1.2
  Scenario: UE without NEA2 but with NEA1 gets NEA1 and the Registration Accept is ciphered with NEA1
    Given the AMF ciphering order is the default "NEA2, NEA1, NEA3, NEA0"
    And the UE security capability advertises EA0, EA1 and IA0, IA1, IA2
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE ciphering field is 1
    And the UE completes the security mode procedure
    When the AMF sends the REGISTRATION ACCEPT downlink
    Then the REGISTRATION ACCEPT security header type is 2 (integrity protected and ciphered)
    And the UE-side deciphering with NEA1, KNASenc, the DL NAS COUNT, BEARER 0x01 and DIRECTION 1 yields the plain 5GMM REGISTRATION ACCEPT
    And the NAS MAC is computed over the ciphertext

  # TS 33.501 §6.7.1.1, Annex D.2.1.4
  Scenario: Operator list NEA3 first with a UE supporting NEA3 selects NEA3 and ciphers DL and deciphers UL with NEA3
    Given the AMF ciphering order is "NEA3, NEA2, NEA1, NEA0"
    And the UE security capability advertises EA0, EA1, EA2, EA3 and IA0, IA1, IA2, IA3
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE ciphering field is 3
    When the UE sends a SECURITY MODE COMPLETE ciphered with NEA3, DIRECTION 0 and integrity protected over the ciphertext
    Then the AMF deciphers the SECURITY MODE COMPLETE with NEA3 and accepts it
    When the AMF sends the REGISTRATION ACCEPT downlink
    Then the UE-side deciphering with NEA3, KNASenc, the DL NAS COUNT, BEARER 0x01 and DIRECTION 1 yields the plain 5GMM REGISTRATION ACCEPT
    When the UE sends a ciphered UL NAS TRANSPORT with NEA3
    Then the AMF deciphers it with NEA3 to the plain 5GMM message

  # TS 24.501 §4.4.6; TS 33.501 Annex D.2
  Scenario Outline: NAS message container in the SECURITY MODE COMPLETE is deciphered with the negotiated NEA
    Given the AMF ciphering order is "<order>"
    And the UE security capability advertises EA0, EA1, EA2, EA3 and IA0, IA1, IA2, IA3
    And the SECURITY MODE COMMAND selected ciphering algorithm <nea>
    When the UE sends a mobility REGISTRATION REQUEST, integrity protected, whose NAS message container carries the full REGISTRATION REQUEST ciphered with <nea_name>
    Then the AMF deciphers the NAS message container with <nea_name>
    And the AMF continues the registration with the REGISTRATION REQUEST from the container
    And no fresh authentication is started

    Examples:
      | order                   | nea | nea_name |
      | NEA1, NEA2, NEA3, NEA0  | 1   | NEA1     |
      | NEA3, NEA2, NEA1, NEA0  | 3   | NEA3     |

  # TS 33.501 §6.7.1.1: NEA0 allowed only if in the list and supported by the UE
  Scenario: UE supporting only NEA0 among the configured list gets NEA0
    Given the AMF ciphering order is the default "NEA2, NEA1, NEA3, NEA0"
    And the UE security capability advertises EA0 only and IA0, IA2
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE ciphering field is 0

  # TS 24.501 §5.5.1.2.8 i) NOTE 2; docs §5 first row
  Scenario: UE with no EA in common with the configured ordered list is rejected with 5GMM cause 23
    Given the AMF ciphering order is "NEA3, NEA2"
    And the UE security capability advertises EA0, EA1 and IA0, IA2
    When the AMF evaluates the UE security capability
    Then the AMF sends a REGISTRATION REJECT with 5GMM cause 23 "UE security capabilities mismatch"
    And no SECURITY MODE COMMAND is sent

  # docs §5 last-but-one config row: startup error
  Scenario Outline: Invalid nas_security.ciphering_order fails the AMF configuration load
    When the AMF configuration is loaded with nas_security.ciphering_order "<order>"
    Then the configuration load returns an error naming "nas_security.ciphering_order"
    And the AMF does not start

    Examples:
      | order              | reason         |
      | NEA2, NEA7, NEA0   | unknown name   |
      | NEA2, NEA2, NEA0   | duplicate      |
      | ,                  | empty list     |
      | NEA4, NEA2         | NEA4 reserved  |

  Scenario: Valid ordered list from the environment override is accepted and logged
    When the AMF configuration is loaded with env AMF_NAS_CIPHERING_ORDER "NEA3, NEA2, NEA1, NEA0"
    Then the effective ciphering order is NEA3, NEA2, NEA1, NEA0
    And the AMF logs the effective NAS ciphering order at startup

  # docs §5 CipheringAlgID row: never fall back to NEA2 or plaintext
  Scenario: Unknown ciphering algorithm id on a downlink context returns an error and sends nothing
    Given a registered UE whose NAS security context has CipheringAlgID 5
    When the AMF tries to send a ciphered downlink NAS message
    Then the AMF returns an error "unknown NEA5"
    And no NAS PDU is sent to the gNB
    And the AMF logs result "FAILURE"
    And the message is not ciphered with NEA2 and not sent in plaintext

  Scenario: Unknown ciphering algorithm id on an uplink context discards the message with an error
    Given a registered UE whose NAS security context has CipheringAlgID 5
    When the UE sends a ciphered UL NAS message with SHT 2
    Then the AMF returns an error "unknown NEA5" and does not process the message
    And the AMF does not decipher it with NEA2

  # ---------------------------------------------------------------------------
  # SEC-007: NAS integrity - 128-NIA1 (SNOW 3G) / 128-NIA3 (ZUC)
  # TS 33.501 §6.7.2, §6.7.1.1, Annex D.3; TS 24.501 §5.5.1.2.8 i), §4.4.3.1, §4.4.4.3
  # Config: nas_security.integrity_order (env AMF_NAS_INTEGRITY_ORDER), default "NIA2, NIA1, NIA3" (NIA0 never allowed).
  # Selected NAS security algorithms IE low nibble = integrity algorithm. UE-side MACs come from shared/crypto/nas/nia.
  # ---------------------------------------------------------------------------

  # TS 33.501 §6.7.2, Annex D.3.1.2
  Scenario: UE with IA1 but no IA2 gets NIA1 and the SECURITY MODE COMMAND and SECURITY MODE COMPLETE are MAC-ed with NIA1
    Given the AMF integrity order is the default "NIA2, NIA1, NIA3"
    And the UE security capability advertises EA0, EA1, EA2, EA3 and IA0, IA1
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE integrity field is 1
    And the SECURITY MODE COMMAND NAS-MAC verifies with NIA1 and not with any other NIA
    And the AMF accepts the SECURITY MODE COMPLETE integrity protected with NIA1

  # TS 33.501 §6.7.1.1, Annex D.3.1.4
  Scenario: Operator integrity list NIA3 first selects NIA3 and the REGISTRATION ACCEPT is MAC-ed with NIA3
    Given the AMF integrity order is "NIA3, NIA2"
    And the UE security capability advertises EA0, EA1, EA2, EA3 and IA0, IA1, IA2, IA3
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE integrity field is 3
    And the SECURITY MODE COMMAND NAS-MAC verifies with NIA3 and not with any other NIA
    And the AMF accepts the SECURITY MODE COMPLETE integrity protected with NIA3
    And the REGISTRATION ACCEPT NAS-MAC verifies with NIA3 and not with NIA2

  # TS 24.501 §5.5.1.2.8 i); docs §5: no NIA0 fallback
  Scenario Outline: UE with no IA in common with the configured integrity order is rejected with 5GMM cause 23
    Given the AMF integrity order is "<order>"
    And the UE security capability advertises EA0, EA1, EA2, EA3 and <ia>
    When the AMF evaluates the UE security capability
    Then the AMF sends a REGISTRATION REJECT with 5GMM cause 23 "UE security capabilities mismatch"
    And no SECURITY MODE COMMAND is sent

    Examples:
      | order      | ia          |
      | NIA2, NIA1 | IA0 only    |
      | NIA3       | IA2 only    |

  # docs §5 config row: startup error naming the key
  Scenario Outline: Invalid nas_security.integrity_order fails the AMF configuration load
    When the AMF configuration is loaded with nas_security.integrity_order "<order>"
    Then the configuration load returns an error naming "nas_security.integrity_order"
    And the AMF does not start

    Examples:
      | order            | reason          |
      | NIA2, NIA0       | NIA0 forbidden  |
      | NIA4, NIA2       | NIA4 reserved   |
      | NIA2, NIA2       | duplicate       |
      | ,                | empty list      |

  Scenario: Valid integrity order from the environment override is accepted
    When the AMF configuration is loaded with env AMF_NAS_INTEGRITY_ORDER "NIA3, NIA1"
    Then the effective integrity order is NIA3, NIA1

  # TS 24.501 §4.4.4.3; TS 33.501 §6.7.2: MAC with a NIA other than the selected one fails
  Scenario: UL message MAC-ed with NIA2 while NIA1 is selected is discarded as an integrity failure
    Given the AMF integrity order is the default "NIA2, NIA1, NIA3"
    And the UE security capability advertises EA0, EA1, EA2, EA3 and IA0, IA1
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE integrity field is 1
    And the AMF accepts the SECURITY MODE COMPLETE integrity protected with NIA1
    When the UE sends a UL NAS TRANSPORT whose NAS-MAC is computed with NIA2
    Then the AMF discards the message as an integrity failure and does not process it
    And the UL NAS COUNT is not advanced

  # TS 33.501 §6.7.1.1; legacy byte-identity
  Scenario: Default integrity order with a UE supporting IA0-IA3 still selects NIA2 and the SECURITY MODE COMMAND bytes are unchanged
    Given the AMF integrity order is the default "NIA2, NIA1, NIA3"
    And the UE security capability advertises EA0, EA1, EA2, EA3 and IA0, IA1, IA2, IA3
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE integrity field is 2
    And the SECURITY MODE COMMAND NAS-MAC verifies with NIA2 and not with any other NIA
    And the SECURITY MODE COMMAND bytes are identical to the legacy golden SECURITY MODE COMMAND

  # ---------------------------------------------------------------------------
  # AMF-009: debug security.null_ciphering never selects an NEA absent from the UE security capability
  # TS 33.501 §6.7.2, §5.11.1.1; TS 24.501 §9.11.3.54, §9.11.3.34, §5.5.1.2.8 i); design: docs/procedures/nas-security-algorithms.md §7.2
  # ---------------------------------------------------------------------------

  # TS 33.501 §6.7.2; UE advertises EA0: NEA0 allowed
  @AMF-009
  Scenario: null_ciphering with a UE advertising EA0 selects NEA0 and NIA2
    Given the AMF debug flag security.null_ciphering is enabled
    And the AMF ciphering order is the default "NEA2, NEA1, NEA3, NEA0"
    And the UE security capability advertises EA0, EA1, EA2, EA3 and IA0, IA1, IA2, IA3
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE ciphering field is 0
    And the Selected NAS security algorithms IE integrity field is 2
    And the Selected NAS security algorithms IE octet is 0x02

  # TS 33.501 §6.7.2, §5.11.1.1: never an algorithm absent from the UE security capability
  @AMF-009
  Scenario: null_ciphering with a UE not advertising EA0 falls back to NEA2 from ciphering_order and logs a WARN
    Given the AMF debug flag security.null_ciphering is enabled
    And the AMF ciphering order is the default "NEA2, NEA1, NEA3, NEA0"
    And the UE security capability advertises EA1, EA2, EA3 and IA1, IA2
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE ciphering field is 2
    And the Selected NAS security algorithms IE integrity field is 2
    And the AMF logs a WARN that null_ciphering was requested but the UE does not support 5G-EA0
    And NEA0 is not selected

  # TS 24.501 §5.5.1.2.8 i) NOTE 2; docs §5 null_ciphering row: no common EA -> #23
  @AMF-009
  Scenario: null_ciphering with a UE advertising only EA1 and ciphering order "NEA2, NEA0" is rejected with 5GMM cause 23
    Given the AMF debug flag security.null_ciphering is enabled
    And the AMF ciphering order is "NEA2, NEA0"
    And the UE security capability advertises EA1 and IA1, IA2
    When the AMF evaluates the UE security capability
    Then the AMF sends a REGISTRATION REJECT with 5GMM cause 23 "UE security capabilities mismatch"
    And no SECURITY MODE COMMAND is sent
    And NEA0 is not selected

  # Regression: flag off keeps the ordered-list selection, no WARN
  @AMF-009
  Scenario Outline: null_ciphering disabled leaves the ordered-list selection unchanged
    Given the AMF debug flag security.null_ciphering is disabled
    And the AMF ciphering order is the default "NEA2, NEA1, NEA3, NEA0"
    And the UE security capability advertises <ea> and IA1, IA2
    When the AMF sends the SECURITY MODE COMMAND
    Then the Selected NAS security algorithms IE ciphering field is <nea>
    And the AMF logs no null_ciphering WARN

    Examples:
      | ea              | nea |
      | EA0, EA1, EA2   | 2   |
      | EA0 only        | 0   |
