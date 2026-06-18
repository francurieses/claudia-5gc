package ueransim_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	ueclient "github.com/francurieses/claudia-5gc/mcp/internal/ueransim"
	uetools "github.com/francurieses/claudia-5gc/mcp/internal/tools/ueransim"
)

func allTools(mock ueclient.Client) []interface{ Name() string; Invoke(context.Context, json.RawMessage) (any, error) } {
	tools := uetools.All(mock)
	out := make([]interface{ Name() string; Invoke(context.Context, json.RawMessage) (any, error) }, len(tools))
	for i, t := range tools {
		out[i] = t
	}
	return out
}

func invoke(t *testing.T, mock ueclient.Client, toolName, input string) map[string]any {
	t.Helper()
	for _, tool := range allTools(mock) {
		if tool.Name() != toolName {
			continue
		}
		res, err := tool.Invoke(context.Background(), json.RawMessage(input))
		if err != nil {
			t.Fatalf("%s.Invoke error: %v", toolName, err)
		}
		b, _ := json.Marshal(res)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	t.Fatalf("tool %q not found", toolName)
	return nil
}

func invokeErr(t *testing.T, mock ueclient.Client, toolName, input string) error {
	t.Helper()
	for _, tool := range allTools(mock) {
		if tool.Name() != toolName {
			continue
		}
		_, err := tool.Invoke(context.Background(), json.RawMessage(input))
		if err == nil {
			t.Fatalf("%s.Invoke: expected error but got nil", toolName)
		}
		return err
	}
	t.Fatalf("tool %q not found", toolName)
	return nil
}

func TestUERegisterSuccess(t *testing.T) {
	mock := &ueclient.MockClient{}
	m := invoke(t, mock, "ueransim_ue_register", `{"supi":"imsi-001010000000001"}`)
	if m["success"] != true {
		t.Errorf("expected success=true, got %v", m["success"])
	}
}

func TestUERegisterMissingSUPI(t *testing.T) {
	mock := &ueclient.MockClient{}
	invokeErr(t, mock, "ueransim_ue_register", `{}`)
}

func TestUERegisterContainerError(t *testing.T) {
	mock := &ueclient.MockClient{
		StatusFn: func(_ context.Context, supi string) (*ueclient.UEStatus, error) {
			return nil, fmt.Errorf("container not running")
		},
	}
	m := invoke(t, mock, "ueransim_ue_register", `{"supi":"imsi-001010000000001"}`)
	if m["success"] != false {
		t.Errorf("expected success=false on error")
	}
}

func TestPDUEstablishSuccess(t *testing.T) {
	mock := &ueclient.MockClient{}
	m := invoke(t, mock, "ueransim_pdu_session_establish", `{"supi":"imsi-001010000000001","dnn":"internet"}`)
	if m["success"] != true {
		t.Errorf("expected success=true, got %v", m["success"])
	}
	if m["pdu_session_id"] == nil {
		t.Error("pdu_session_id should not be nil")
	}
}

func TestPDUEstablishDefaultDNN(t *testing.T) {
	var capturedDNN string
	mock := &ueclient.MockClient{
		EstablishFn: func(_ context.Context, supi, dnn string) (*ueclient.PDUSession, error) {
			capturedDNN = dnn
			return &ueclient.PDUSession{SessionID: 1, UEAddr: "10.0.0.1"}, nil
		},
	}
	invoke(t, mock, "ueransim_pdu_session_establish", `{"supi":"imsi-001010000000001"}`)
	if capturedDNN != "internet" {
		t.Errorf("default DNN: want 'internet', got %q", capturedDNN)
	}
}

func TestDeregisterSuccess(t *testing.T) {
	mock := &ueclient.MockClient{}
	m := invoke(t, mock, "ueransim_ue_deregister", `{"supi":"imsi-001010000000001"}`)
	if m["success"] != true {
		t.Errorf("expected success=true")
	}
}

func TestRunScenarioAllPassed(t *testing.T) {
	mock := &ueclient.MockClient{} // all defaults succeed
	m := invoke(t, mock, "ueransim_run_scenario", `{"supi":"imsi-001010000000001","dnn":"internet"}`)
	if m["all_passed"] != true {
		t.Errorf("expected all_passed=true, got %v", m["all_passed"])
	}
	steps, _ := m["steps"].([]any)
	if len(steps) == 0 {
		t.Error("steps should not be empty")
	}
}

func TestRunScenarioRegistrationFailure(t *testing.T) {
	mock := &ueclient.MockClient{
		StatusFn: func(_ context.Context, supi string) (*ueclient.UEStatus, error) {
			return &ueclient.UEStatus{SUPI: supi, MMState: "MM-DEREGISTERED", Registered: false}, nil
		},
	}
	m := invoke(t, mock, "ueransim_run_scenario", `{"supi":"imsi-999990000000001","dnn":"internet"}`)
	if m["all_passed"] != false {
		t.Errorf("expected all_passed=false when UE not registered")
	}
}

func TestUERANSIMStatus(t *testing.T) {
	mock := &ueclient.MockClient{}
	m := invoke(t, mock, "ueransim_status", `{}`)
	if m["container_running"] != true {
		t.Errorf("expected container_running=true")
	}
}
