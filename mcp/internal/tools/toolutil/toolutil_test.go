package toolutil

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

func TestValidSUPI(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"imsi-001010000000001", true},
		{"imsi-00101", true},
		{"imsi-001010000000001999", false}, // 18 digits
		{"imsi-0010", false},
		{"imsi-0010100000000a1", false},
		{"nai-user@example.com", false},
		{"", false},
		{"imsi-001010000000001\n", false},
	}
	for _, c := range cases {
		err := ValidSUPI(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ValidSUPI(%q) ok=%v, want %v", c.in, err == nil, c.ok)
		}
		if err != nil && err.Code != mcperr.CodeInvalidParams {
			t.Errorf("ValidSUPI(%q) code %d", c.in, err.Code)
		}
	}
}

func TestValidPSI(t *testing.T) {
	for psi, ok := range map[int]bool{-1: false, 0: false, 1: true, 15: true, 16: false} {
		if (ValidPSI(psi) == nil) != ok {
			t.Errorf("ValidPSI(%d) ok=%v, want %v", psi, !ok, ok)
		}
	}
}

func TestValidDNN(t *testing.T) {
	cases := map[string]bool{
		"internet": true, "ims.mnc001.mcc001": true, "a": true, "a-b": true,
		"": false, "-bad": false, "bad-": false, "has space": false, "under_score": false,
		strings.Repeat("a", 63): true, strings.Repeat("a", 64): false,
	}
	for in, ok := range cases {
		if (ValidDNN(in) == nil) != ok {
			t.Errorf("ValidDNN(%q) ok=%v, want %v", in, !ok, ok)
		}
	}
}

func TestValidFiveQI(t *testing.T) {
	cases := map[int]bool{
		0: false, 1: true, 9: true, 10: true, 11: false, 64: false, 65: true, 69: true, 68: false,
		79: true, 80: true, 81: false, 82: true, 90: true, 91: false,
		127: false, 128: true, 254: true, 255: false, -1: false,
	}
	for v, ok := range cases {
		if ValidFiveQI(v) != ok {
			t.Errorf("ValidFiveQI(%d) = %v, want %v", v, !ok, ok)
		}
	}
}

func TestHashSUPI(t *testing.T) {
	a := HashSUPI("imsi-001010000000001")
	if len(a) != 8 || strings.Contains(a, "001010") {
		t.Errorf("hash %q must be 8 hex chars and not reveal the SUPI", a)
	}
	if a != HashSUPI("imsi-001010000000001") {
		t.Error("hash must be deterministic")
	}
	if a == HashSUPI("imsi-001010000000002") {
		t.Error("different SUPIs must hash differently")
	}
}

// stubTool records the arguments it receives.
type stubTool struct {
	got  json.RawMessage
	plan bool
}

func (s *stubTool) Name() string                 { return "new_tool" }
func (s *stubTool) Description() string          { return "does a thing" }
func (s *stubTool) InputSchema() json.RawMessage { return json.RawMessage(`{}`) }
func (s *stubTool) OutputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object"}`)
}
func (s *stubTool) Risk() registry.Risk { return registry.Mutating }
func (s *stubTool) Invoke(_ context.Context, in json.RawMessage) (any, error) {
	s.got = in
	return "done", nil
}
func (s *stubTool) Plan(_ context.Context, in json.RawMessage) (any, error) {
	s.got, s.plan = in, true
	return "planned", nil
}

func TestDeprecatedAlias(t *testing.T) {
	target := &stubTool{}
	oldSchema := json.RawMessage(`{"type":"object","title":"old"}`)
	alias := Deprecated("old_tool", oldSchema, target, func(in json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"mapped":true}`), nil
	})
	if alias.Name() != "old_tool" || string(alias.InputSchema()) != string(oldSchema) {
		t.Errorf("alias identity: %s %s", alias.Name(), alias.InputSchema())
	}
	if !strings.HasPrefix(alias.Description(), "DEPRECATED: use new_tool") {
		t.Errorf("description: %s", alias.Description())
	}
	if alias.Risk() != registry.Mutating {
		t.Errorf("risk must come from the target, got %v", alias.Risk())
	}
	out, err := alias.Invoke(context.Background(), json.RawMessage(`{"old":1}`))
	if err != nil || out != "done" || string(target.got) != `{"mapped":true}` {
		t.Errorf("invoke: out=%v err=%v got=%s", out, err, target.got)
	}
	planner, ok := alias.(registry.Planner)
	if !ok {
		t.Fatal("alias must be a Planner")
	}
	if p, err := planner.Plan(context.Background(), json.RawMessage(`{}`)); err != nil || p != "planned" || !target.plan {
		t.Errorf("plan: %v %v", p, err)
	}
}

func TestDeprecatedAliasMapError(t *testing.T) {
	target := &stubTool{}
	want := mcperr.New(mcperr.CodeInvalidParams, "removed", nil)
	alias := Deprecated("old_tool", nil, target, func(json.RawMessage) (json.RawMessage, error) { return nil, want })
	if _, err := alias.Invoke(context.Background(), nil); !errors.Is(err, want) {
		t.Errorf("invoke err = %v, want the mapper error", err)
	}
	if target.got != nil {
		t.Error("target must not run when the mapper refuses")
	}
}
