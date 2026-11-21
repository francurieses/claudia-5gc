Feature: Dev subscriber seed keys sm-data per slice on the operator.yaml slice DNN (UDR-002, TS 29.503 §6.1.6.2.8 / §6.1.6.2.9, TS 23.502 §4.3.2.2.1 step 4)
  As a network operator
  I want the UDR dev seed to key each slice's DnnConfiguration on the DNN configured for that slice in operator.yaml
  So that a UE requesting gaming/ims/bronze finds a subscribed DnnConfiguration in sm-data

  # Design: docs/procedures/SubscriberSeed.md. Slice "internet" stays keyed "internet" and its am-data bytes are unchanged.

  Background:
    Given a clean UDR instance is running
    And the operator config defines slices "internet" 1/000001 dnn "internet", "gold" 1/000002 dnn "gaming", "silver" 2/000001 dnn "ims", "bronze" 3/000001 dnn "bronze"
    And the operator config defines dnns "internet, ims, gaming, bronze"

  Scenario: Gold subscriber seed keys sm-data of slice 1/000002 on gaming and 1/000001 on internet
    When the dev subscriber "imsi-001010000000201" is seeded with the "gold" slice profile
    And the UDM GETs seeded sm-data of "imsi-001010000000201" for PLMN "00101"
    Then the seeded sm-data status is 200
    And the seeded sm-data for slice "1/000002" has dnnConfigurations key "gaming" with 5QI 7
    And the seeded sm-data for slice "1/000001" has dnnConfigurations key "internet"

  Scenario Outline: Each slice profile is keyed on its own DNN with the slice 5QI
    When the dev subscriber "<supi>" is seeded with the "<profile>" slice profile
    And the UDM GETs seeded sm-data of "<supi>" for PLMN "00101"
    Then the seeded sm-data status is 200
    And the seeded sm-data for slice "<slice>" has dnnConfigurations key "<dnn>" with 5QI <5qi>

    Examples:
      | profile | supi                 | slice    | dnn    | 5qi |
      | gold    | imsi-001010000000201 | 1/000002 | gaming | 7   |
      | silver  | imsi-001010000000202 | 2/000001 | ims    | 8   |
      | bronze  | imsi-001010000000203 | 3/000001 | bronze | 9   |

  Scenario: am-data of the internet-only seed subscriber carries no dnn attribute
    When the dev subscriber "imsi-001010000000001" is seeded with the "internet" slice profile
    And the UDM GETs seeded am-data of "imsi-001010000000001" for PLMN "00101"
    Then the seeded am-data status is 200
    And the seeded am-data nssai entries carry no "dnn" attribute

  Scenario: Slice DNN missing from the configured dnns list falls back to internet and logs a WARN
    Given the operator config defines slice "odd" 1/000009 dnn "unlisted"
    When the dev subscriber "imsi-001010000000204" is seeded with the "odd" slice profile
    And the UDM GETs seeded sm-data of "imsi-001010000000204" for PLMN "00101"
    Then the seeded sm-data status is 200
    And the seeded sm-data for slice "1/000009" has dnnConfigurations key "internet"
    And the UDR logged a WARN about unknown seed DNN "unlisted"

  Scenario Outline: Without operator config the built-in fallback slices still map to their DNNs
    Given the operator config is absent
    When the dev subscriber "<supi>" is seeded with the "<profile>" slice profile
    And the UDM GETs seeded sm-data of "<supi>" for PLMN "00101"
    Then the seeded sm-data for slice "<slice>" has dnnConfigurations key "<dnn>"

    Examples:
      | profile | supi                 | slice    | dnn    |
      | gold    | imsi-001010000000201 | 1/000002 | gaming |
      | silver  | imsi-001010000000202 | 2/000001 | ims    |
      | bronze  | imsi-001010000000203 | 3/000001 | bronze |

  Scenario: An existing subscriber is not overwritten by the seed
    Given subscriber "imsi-001010000000201" is pre-provisioned with sm-data for slice "1/000002" keyed "internet"
    When the dev subscriber "imsi-001010000000201" is seeded with the "gold" slice profile
    And the UDM GETs seeded sm-data of "imsi-001010000000201" for PLMN "00101"
    Then the seeded sm-data for slice "1/000002" has dnnConfigurations key "internet"
    And the seeded sm-data for slice "1/000002" has no dnnConfigurations key "gaming"

  Scenario: Resync of sm-data keeps the per-slice DNN
    Given the dev subscriber "imsi-001010000000201" is seeded with the "gold" slice profile
    When the operator POSTs sync-sm-data for "imsi-001010000000201"
    And the UDM GETs seeded sm-data of "imsi-001010000000201" for PLMN "00101"
    Then the seeded sm-data for slice "1/000002" has dnnConfigurations key "gaming" with 5QI 7

  Scenario: slice_dnn_qos seed creates a row for slice 1/000002 and dnn gaming
    When the slice_dnn_qos table is seeded from the operator config
    And the operator GETs the slice-dnn-qos list
    Then the slice-qos list contains slice "1/000002" dnn "gaming" with source "default"
