Feature: MCP guardrails over the SSE transport
  As an operator of the 5G core
  I want every tool call checked against access mode, role and confirmation
  So that an LLM cannot change core state by accident

  Scenario: Read-only mode hides mutating and disruptive tools
    Given the MCP server runs with access mode "read-only"
    When I list the tools
    Then the tool list contains "probe_read"
    And the tool list does not contain "probe_mutate"
    And the tool list does not contain "probe_disrupt"

  Scenario: Operator mode lists disruptive tools but not admin tools
    Given the MCP server runs with access mode "operator"
    When I list the tools
    Then the tool list contains "probe_disrupt"
    And the tool list does not contain "probe_admin"

  Scenario: A disruptive call without confirm returns a dry run and changes nothing
    Given the MCP server runs with access mode "operator"
    When I call "probe_disrupt" with arguments {"supi":"imsi-001010000000001"}
    Then the result is a dry run
    And the upstream was called 0 times
    And the audit log has an entry for "probe_disrupt" with outcome "dry_run"

  Scenario: A disruptive call with confirm true executes once
    Given the MCP server runs with access mode "operator"
    When I call "probe_disrupt" with arguments {"supi":"imsi-001010000000001","confirm":true}
    Then the call succeeds
    And the upstream was called 1 time
    And the audit log has an entry for "probe_disrupt" with outcome "executed"

  Scenario: A viewer token cannot call a disruptive tool
    Given the MCP server runs with access mode "operator" and bearer authentication
    And I send the viewer token
    When I call "probe_disrupt" with arguments {"confirm":true}
    Then the call is refused with code -32000 and message "role viewer may not call DISRUPTIVE tool probe_disrupt"
    And the upstream was called 0 times

  Scenario: A viewer token can still run read-only tools
    Given the MCP server runs with access mode "operator" and bearer authentication
    And I send the viewer token
    When I call "probe_read" with arguments {}
    Then the call succeeds

  Scenario: A second disruptive call within the interval is refused
    Given the MCP server runs with access mode "operator"
    When I call "probe_disrupt" with arguments {"confirm":true}
    And I call "probe_disrupt" with arguments {"confirm":true}
    Then the call is refused with code -32000 and message "rate limited"
    And the upstream was called 1 time

  Scenario: Admin tools need the lab access mode
    Given the MCP server runs with access mode "operator"
    When I call "probe_admin" with arguments {"confirm":true}
    Then the call is refused with code -32000 and message "access_mode operator does not allow it"
    And the upstream was called 0 times

  Scenario: Mutating tools run without confirm
    Given the MCP server runs with access mode "operator"
    When I call "probe_mutate" with arguments {}
    Then the call succeeds
    And the upstream was called 1 time
