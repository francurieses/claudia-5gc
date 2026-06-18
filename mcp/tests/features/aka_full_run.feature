Feature: 5G-AKA full run tool

  Scenario: run aka_full_run with TS 35.207 Set 1 K and OPc
    Given the MCP server is running
    When I call tool "aka_full_run" with input
      """
      {
        "supi": "imsi-001010000000001",
        "k": "465b5ce8b199b49faa5f0a2ee238a6bc",
        "opc": "cd63cb71954a9f4e48a5994e37a02baf",
        "serving_network_name": "5G:mnc001.mcc001.3gppnetwork.org",
        "sqn": "ff9bb4d0b607"
      }
      """
    Then the response contains field "rand" of length 32
    And the response contains field "autn" of length 32
    And the response contains field "xres_star" of length 32
    And the response contains field "hxres_star" of length 32
    And the response contains field "kausf" of length 64
    And the response contains field "kseaf" of length 64
    And the response contains field "kamf" of length 64
    And the response has no error

  Scenario: run aka_full_run with wrong OPc returns structured error
    Given the MCP server is running
    When I call tool "aka_full_run" with input
      """
      {
        "supi": "imsi-001010000000001",
        "k": "465b5ce8b199b49faa5f0a2ee238a6bc",
        "opc": "zz",
        "serving_network_name": "5G:mnc001.mcc001.3gppnetwork.org",
        "sqn": "ff9bb4d0b607"
      }
      """
    Then the response contains an MCP error
    And the server did not panic
