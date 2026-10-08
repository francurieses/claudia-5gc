Feature: Per slice/DNN subscribed Session-AMBR (UDR-003, TS 23.501 §5.7.2.6 / §5.7.1.8, TS 29.503 §6.1.6.2.8-§6.1.6.2.9, TS 29.571 §5.5.2)
  As a network operator
  I want the subscribed Session-AMBR stored per (S-NSSAI, DNN) in the UDR and editable through /nudr-internal/v1/slice-dnn-qos
  So that sm-data served over Nudr_DR reflects the configured value instead of a hard-coded default

  # The /nudr-internal/v1/slice-dnn-qos endpoints are NON-3GPP management interfaces.
  # The only 3GPP-visible effect is dnnConfigurations{dnn}.sessionAmbr in sm-data (TS 29.503 §6.1.6.2.9).
  # Error causes follow docs/procedures/SliceSessionAmbrConfig.md "Error cases".

  Background:
    Given a clean UDR instance is running
    And the slice/DNN QoS table is seeded with defaults for slices "1/000001" and "2/000001" on dnn "internet"
    And the seeded default Session-AMBR for slice "1/000001" dnn "internet" is "100 Mbps" uplink and "100 Mbps" downlink

  # ---- Acceptance: persisted per (slice, DNN), seed default only -------------------------------

  Scenario: List returns the seeded slice/DNN rows with source default
    When the operator GETs the slice-dnn-qos list
    Then the slice-qos response status is 200
    And the slice-qos list contains slice "1/000001" dnn "internet" with Session-AMBR "100 Mbps" / "100 Mbps" and source "default"
    And the slice-qos list contains slice "2/000001" dnn "internet" with source "default"
    And the slice-qos list is sorted by sst, sd, dnn

  # ---- Acceptance: editing changes sm-data for that slice/DNN ----------------------------------

  Scenario: Edit Session-AMBR re-derives sm-data of the subscriber on that slice and DNN
    Given subscriber "imsi-001010000000001" is provisioned on slice "1/000001" dnn "internet"
    When the operator PUTs slice-dnn-qos "1/000001/internet" with Session-AMBR uplink "20 Mbps" downlink "30 Mbps"
    Then the slice-qos response status is 200
    And the slice-qos item has source "edited" and Session-AMBR "20 Mbps" / "30 Mbps"
    And the slice-qos item keeps default Session-AMBR "100 Mbps" / "100 Mbps"
    And the slice-qos resync reports affectedSubscribers 1 and synced 1 and no failures
    When the UDM GETs sm-data of "imsi-001010000000001" for PLMN "00101"
    Then the slice-qos response status is 200
    And the sm-data for slice "1/000001" has dnnConfigurations "internet" sessionAmbr "20 Mbps" / "30 Mbps"

  Scenario: Editing one slice does not touch subscribers on another slice
    Given subscriber "imsi-001010000000001" is provisioned on slice "1/000001" dnn "internet"
    And subscriber "imsi-001010000000002" is provisioned on slice "2/000001" dnn "internet"
    When the operator PUTs slice-dnn-qos "1/000001/internet" with Session-AMBR uplink "20 Mbps" downlink "30 Mbps"
    Then the slice-qos response status is 200
    And the slice-qos resync reports affectedSubscribers 1 and synced 1 and no failures
    When the UDM GETs sm-data of "imsi-001010000000002" for PLMN "00101"
    Then the sm-data for slice "2/000001" has dnnConfigurations "internet" sessionAmbr "100 Mbps" / "200 Mbps"
    And the slice-dnn-qos "2/000001/internet" still has source "default"

  Scenario: PUT on an unseeded key creates the row as edited
    When the operator PUTs slice-dnn-qos "3/00000a/ims" with Session-AMBR uplink "5 Mbps" downlink "8 Mbps"
    Then the slice-qos response status is 201
    And the slice-qos item has source "edited" and Session-AMBR "5 Mbps" / "8 Mbps"
    And the slice-qos resync reports affectedSubscribers 0 and synced 0 and no failures
    When the operator GETs slice-dnn-qos "3/00000a/ims"
    Then the slice-qos response status is 200
    And the slice-qos item has source "edited" and Session-AMBR "5 Mbps" / "8 Mbps"

  Scenario: SD hyphen means the slice has no SD
    When the operator PUTs slice-dnn-qos "1/-/internet" with Session-AMBR uplink "10 Mbps" downlink "10 Mbps"
    Then the slice-qos response status is 201
    And the slice-qos item has sst 1 and no sd
    And the slice-qos item has source "edited" and Session-AMBR "10 Mbps" / "10 Mbps"
    And the slice-dnn-qos "1/000001/internet" still has source "default"

  # ---- Acceptance: invalid BitRate strings rejected with HTTP 400 ------------------------------

  Scenario Outline: Invalid BitRate string is rejected and the stored value is unchanged
    When the operator PUTs slice-dnn-qos "1/000001/internet" with Session-AMBR uplink "<uplink>" downlink "<downlink>"
    Then the slice-qos response status is 400
    And the slice-qos problem cause is "MANDATORY_IE_INCORRECT"
    And the slice-qos problem names invalid parameter "<param>"
    And the slice-dnn-qos "1/000001/internet" still has source "default" and Session-AMBR "100 Mbps" / "100 Mbps"

    Examples: TS 29.571 §5.5.2 pattern violations and non-positive values
      | uplink   | downlink | param                    |
      | 20Mbps   | 30 Mbps  | sessionAmbr.uplink       |
      | 20 mbps  | 30 Mbps  | sessionAmbr.uplink       |
      | 20 MB    | 30 Mbps  | sessionAmbr.uplink       |
      | -5 Mbps  | 30 Mbps  | sessionAmbr.uplink       |
      | 0 Mbps   | 30 Mbps  | sessionAmbr.uplink       |
      | 20 Mbps  | 30Mbps   | sessionAmbr.downlink     |
      | 20 Mbps  | 0 Kbps   | sessionAmbr.downlink     |
      | 20 Mbps  | 30 mbps  | sessionAmbr.downlink     |

  Scenario Outline: Missing or empty BitRate is rejected as a missing mandatory IE
    When the operator PUTs slice-dnn-qos "1/000001/internet" with raw body '<body>'
    Then the slice-qos response status is 400
    And the slice-qos problem cause is "MANDATORY_IE_MISSING"
    And the slice-qos problem names invalid parameter "<param>"
    And the slice-dnn-qos "1/000001/internet" still has source "default" and Session-AMBR "100 Mbps" / "100 Mbps"

    Examples: empty or absent members of sessionAmbr
      | body                                                          | param                |
      | {"sessionAmbr":{"uplink":"","downlink":"30 Mbps"}}            | sessionAmbr.uplink   |
      | {"sessionAmbr":{"uplink":"20 Mbps","downlink":""}}            | sessionAmbr.downlink |
      | {"sessionAmbr":{"downlink":"30 Mbps"}}                        | sessionAmbr.uplink   |
      | {"sessionAmbr":{"uplink":"20 Mbps"}}                          | sessionAmbr.downlink |
      | {}                                                            | sessionAmbr          |

  Scenario: Malformed JSON body is rejected as INVALID_MSG_FORMAT
    When the operator PUTs slice-dnn-qos "1/000001/internet" with raw body '{"sessionAmbr": not-json'
    Then the slice-qos response status is 400
    And the slice-qos problem cause is "INVALID_MSG_FORMAT"
    And the slice-dnn-qos "1/000001/internet" still has source "default" and Session-AMBR "100 Mbps" / "100 Mbps"

  Scenario Outline: Invalid path parameters are rejected
    When the operator PUTs slice-dnn-qos "<key>" with Session-AMBR uplink "20 Mbps" downlink "30 Mbps"
    Then the slice-qos response status is 400
    And the slice-qos problem cause is "MANDATORY_IE_INCORRECT"

    Examples: sst outside 0-255 and sd that is neither "-" nor six hex digits
      | key                  |
      | 300/000001/internet  |
      | 1/zz/internet        |
      | 1/00001/internet     |
      | 1/0000011/internet   |

  # ---- Revert (DELETE) -------------------------------------------------------------------------

  Scenario: DELETE reverts an edited row to the seed value and re-derives sm-data
    Given subscriber "imsi-001010000000001" is provisioned on slice "1/000001" dnn "internet"
    And slice-dnn-qos "1/000001/internet" was edited to Session-AMBR uplink "20 Mbps" downlink "30 Mbps"
    When the operator DELETEs slice-dnn-qos "1/000001/internet"
    Then the slice-qos response status is 200
    And the slice-qos item has source "default" and Session-AMBR "100 Mbps" / "100 Mbps"
    And the slice-qos response reports changed true
    And the slice-qos resync reports affectedSubscribers 1 and synced 1 and no failures
    When the UDM GETs sm-data of "imsi-001010000000001" for PLMN "00101"
    Then the sm-data for slice "1/000001" has dnnConfigurations "internet" sessionAmbr "100 Mbps" / "100 Mbps"
    When the operator GETs slice-dnn-qos "1/000001/internet"
    Then the slice-qos response status is 200
    And the slice-qos item has source "default" and Session-AMBR "100 Mbps" / "100 Mbps"

  Scenario: DELETE on a non-edited row is an idempotent no-op
    When the operator DELETEs slice-dnn-qos "1/000001/internet"
    Then the slice-qos response status is 200
    And the slice-qos response reports changed false
    And the slice-qos resync reports affectedSubscribers 0 and synced 0 and no failures
    And the slice-qos item has source "default" and Session-AMBR "100 Mbps" / "100 Mbps"

  Scenario Outline: Operations on a key with no row return DATA_NOT_FOUND
    When the operator <operation> slice-dnn-qos "9/ffffff/nonexistent"
    Then the slice-qos response status is 404
    And the slice-qos problem cause is "DATA_NOT_FOUND"

    Examples:
      | operation |
      | GETs      |
      | DELETEs   |

  # ---- Acceptance: survives UDR restart and make up reseed -------------------------------------

  Scenario: Re-seeding after a UDR restart does not overwrite an edited row
    Given slice-dnn-qos "1/000001/internet" was edited to Session-AMBR uplink "20 Mbps" downlink "30 Mbps"
    When the UDR is restarted and re-seeded with the default slice set
    Then the slice-dnn-qos "1/000001/internet" has source "edited" and Session-AMBR "20 Mbps" / "30 Mbps"
    And no sm-data resync is triggered for slice "1/000001" dnn "internet"

  Scenario: Re-seeding refreshes a non-edited row from an operator.yaml seed entry
    When the UDR is restarted and re-seeded with operator entry slice "1/000001" dnn "internet" Session-AMBR "50 Mbps" / "60 Mbps"
    Then the slice-dnn-qos "1/000001/internet" has source "operator" and Session-AMBR "50 Mbps" / "60 Mbps"
    And the slice-dnn-qos "1/000001/internet" has default Session-AMBR "50 Mbps" / "60 Mbps" with default source "operator"
    And a sm-data resync is triggered for slice "1/000001" dnn "internet"

  Scenario: Operator seed entry does not overwrite an edited row but updates the revert target
    Given slice-dnn-qos "1/000001/internet" was edited to Session-AMBR uplink "20 Mbps" downlink "30 Mbps"
    When the UDR is restarted and re-seeded with operator entry slice "1/000001" dnn "internet" Session-AMBR "50 Mbps" / "60 Mbps"
    Then the slice-dnn-qos "1/000001/internet" has source "edited" and Session-AMBR "20 Mbps" / "30 Mbps"
    And the slice-dnn-qos "1/000001/internet" has default Session-AMBR "50 Mbps" / "60 Mbps" with default source "operator"
    When the operator DELETEs slice-dnn-qos "1/000001/internet"
    Then the slice-qos response status is 200
    And the slice-qos item has source "operator" and Session-AMBR "50 Mbps" / "60 Mbps"
