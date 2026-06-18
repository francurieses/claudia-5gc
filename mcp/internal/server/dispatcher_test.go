package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/jsonrpc"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	nastools "github.com/francurieses/claudia-5gc/mcp/internal/tools/nas"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

func testDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	reg := registry.New()
	if err := reg.RegisterAll(nastools.All()...); err != nil {
		t.Fatalf("register: %v", err)
	}
	return NewDispatcher(reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func req(t *testing.T, method string, params any) *jsonrpc.Request {
	t.Helper()
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			t.Fatalf("marshal params: %v", err)
		}
		raw = b
	}
	return &jsonrpc.Request{JSONRPC: "2.0", Method: method, Params: raw, ID: json.RawMessage(`1`)}
}

func TestInitialize(t *testing.T) {
	d := testDispatcher(t)
	resp := d.Dispatch(context.Background(), req(t, "initialize", nil))
	if resp.Error != nil {
		t.Fatalf("initialize error: %v", resp.Error)
	}
	var r struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.ProtocolVersion != protocolVersion {
		t.Errorf("protocolVersion: got %q", r.ProtocolVersion)
	}
	if r.ServerInfo.Name != serverName {
		t.Errorf("serverInfo.name: got %q", r.ServerInfo.Name)
	}
}

func TestToolsList(t *testing.T) {
	d := testDispatcher(t)
	resp := d.Dispatch(context.Background(), req(t, "tools/list", nil))
	if resp.Error != nil {
		t.Fatalf("tools/list error: %v", resp.Error)
	}
	var r struct {
		Tools []registry.ManifestEntry `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(r.Tools) != 4 { // nas_decode, nas_encode, ie_validate, tlv_inspect
		t.Fatalf("tools count: got %d, want 4", len(r.Tools))
	}
}

func TestToolsCallSuccess(t *testing.T) {
	d := testDispatcher(t)
	resp := d.Dispatch(context.Background(), req(t, "tools/call", map[string]any{
		"name":      "nas_decode",
		"arguments": map[string]any{"hex": "7e004111000100"},
	}))
	if resp.Error != nil {
		t.Fatalf("tools/call error: %v", resp.Error)
	}
	var r struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.IsError {
		t.Fatalf("unexpected isError; content: %s", r.Content[0].Text)
	}
	if len(r.Content) == 0 || r.Content[0].Type != "text" {
		t.Fatal("missing text content")
	}
}

func TestToolsCallUnknownTool(t *testing.T) {
	d := testDispatcher(t)
	resp := d.Dispatch(context.Background(), req(t, "tools/call", map[string]any{"name": "nope"}))
	if resp.Error == nil || resp.Error.Code != mcperr.CodeMethodNotFound {
		t.Fatalf("expected method-not-found, got %+v", resp.Error)
	}
}

func TestToolsCallToolErrorIsContent(t *testing.T) {
	// A malformed NAS PDU is a tool error, surfaced as a result with isError=true
	// (not a JSON-RPC error), per MCP convention.
	d := testDispatcher(t)
	resp := d.Dispatch(context.Background(), req(t, "tools/call", map[string]any{
		"name":      "nas_decode",
		"arguments": map[string]any{"hex": "7e00"},
	}))
	if resp.Error != nil {
		t.Fatalf("expected result with isError, got JSON-RPC error: %v", resp.Error)
	}
	var r struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !r.IsError {
		t.Fatal("expected isError=true for malformed input")
	}
}

func TestUnknownMethod(t *testing.T) {
	d := testDispatcher(t)
	resp := d.Dispatch(context.Background(), req(t, "does/not/exist", nil))
	if resp.Error == nil || resp.Error.Code != mcperr.CodeMethodNotFound {
		t.Fatalf("expected method-not-found, got %+v", resp.Error)
	}
}

func TestNotificationNoResponse(t *testing.T) {
	d := testDispatcher(t)
	n := &jsonrpc.Request{JSONRPC: "2.0", Method: "notifications/initialized"}
	resp := d.Dispatch(context.Background(), n)
	if resp.Result != nil || resp.Error != nil {
		t.Fatal("notification should yield empty response")
	}
}
