Feature: NAS decode over MCP
  As an LLM client debugging the 5G core
  I want to decode and validate NAS messages through the MCP server
  So that I can inspect 5GS signalling without bespoke tooling

  Background:
    Given the MCP server is running

  Scenario: Decode a valid RegistrationRequest
    When I call "nas_decode" with hex "7e004111000100"
    Then the call succeeds
    And the decoded message type name is "RegistrationRequest"

  Scenario: Malformed TLV reports the offending offset
    When I call "ie_validate" with hex "6d05aabb"
    Then the call succeeds
    And the result is reported invalid with first error offset 0

  Scenario: Round-trip encode then decode reproduces the message
    When I encode message type "0x41" with body "11000100"
    And I decode the encoded hex
    Then the decoded message type name is "RegistrationRequest"

  Scenario: Two concurrent SSE clients receive independent responses
    Given two SSE clients are connected
    When both clients call "nas_decode" concurrently with distinct inputs
    Then each client receives only its own response
    And the live session count returns to zero after both disconnect
