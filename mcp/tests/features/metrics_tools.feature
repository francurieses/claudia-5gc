Feature: Prometheus metrics tools

  @e2e
  Scenario: kpi_snapshot for all NFs returns all numeric fields
    Given the MCP server is running
    And the observability stack is up
    When I call tool "kpi_snapshot" with input
      """
      {"nf": "all"}
      """
    Then the response contains field "registration_success_rate"
    And the response contains field "auth_success_rate"
    And the response contains field "avg_registration_latency_ms"
    And the response contains field "active_ue_contexts"
    And the response contains field "sbi_error_rate"
    And the response contains field "snapshot_time"
    And the response has no error

  @e2e
  Scenario: metric_query with valid PromQL returns results
    Given the MCP server is running
    And the observability stack is up
    When I call tool "metric_query" with input
      """
      {"promql": "up"}
      """
    Then the response contains field "results"
    And the response has no error

  @e2e
  Scenario: alert_list returns without error
    Given the MCP server is running
    And the observability stack is up
    When I call tool "alert_list" with input
      """
      {"state": "all"}
      """
    Then the response contains field "alerts"
    And the response has no error
