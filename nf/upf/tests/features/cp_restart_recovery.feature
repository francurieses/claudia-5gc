# UPF deletes the PFCP sessions of a restarted CP function (SMF) - orphan cleanup
#
# Spec refs: TS 29.244 §6.2.6 (Heartbeat Procedure, restart detection), §7.4.4.1 (Association Setup),
#            §8.2.65 (Recovery Time Stamp), TS 23.007 §19A (restoration procedures).
# Step definitions: cp_restart_recovery_steps_test.go (build tag `functional`).

Feature: UPF CP-function restart detection via Recovery Time Stamp
  As a UPF
  I want to compare the Recovery Time Stamp a CP function advertises with the one I stored
  So that sessions orphaned by an SMF restart are deleted, while a mere re-association keeps them

  Scenario: SMF restarts with a new Recovery Time Stamp, the UPF drops its old sessions
    Given a UPF PFCP server with an SMF associated with Recovery Time Stamp "T0"
    And the SMF has 2 established PFCP sessions
    When the SMF sends a PFCP Association Setup Request with Recovery Time Stamp "T1"
    Then the UPF holds 0 PFCP sessions

  Scenario: SMF re-associates with the same Recovery Time Stamp, the UPF keeps its sessions
    Given a UPF PFCP server with an SMF associated with Recovery Time Stamp "T0"
    And the SMF has 2 established PFCP sessions
    When the SMF sends a PFCP Association Setup Request with Recovery Time Stamp "T0"
    Then the UPF holds 2 PFCP sessions

  Scenario: A Heartbeat Request with a later Recovery Time Stamp reveals the SMF restart
    Given a UPF PFCP server with an SMF associated with Recovery Time Stamp "T0"
    And the SMF has 2 established PFCP sessions
    When the SMF sends a PFCP Heartbeat Request with Recovery Time Stamp "T1"
    Then the UPF holds 0 PFCP sessions
