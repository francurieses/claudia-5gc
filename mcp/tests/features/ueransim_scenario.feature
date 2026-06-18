Feature: UERANSIM orchestration tools

  @e2e
  Scenario: full smoke test scenario for a registered UE
    Given the MCP server is running
    And the UERANSIM stack is up with UE "imsi-001010000000001"
    When I call tool "ueransim_run_scenario" with input
      """
      {
        "supi": "imsi-001010000000001",
        "dnn": "internet"
      }
      """
    Then the response field "all_passed" is true
    And the response field "steps" is a non-empty array
    And the response has no error

  Scenario: ueransim_ue_register for missing SUPI returns structured error
    Given the MCP server is running
    When I call tool "ueransim_ue_register" with input
      """
      {}
      """
    Then the response contains an MCP error
    And the server did not panic

  Scenario: ueransim_status returns container info
    Given the MCP server is running
    When I call tool "ueransim_status" with input "{}"
    Then the response contains field "container_running"
    And the response has no error
