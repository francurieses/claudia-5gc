package registry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type stubTool struct {
	name string
	risk Risk
}

func (s stubTool) Name() string                  { return s.name }
func (s stubTool) Description() string           { return "stub " + s.name }
func (s stubTool) InputSchema() json.RawMessage  { return json.RawMessage(`{"type":"object"}`) }
func (s stubTool) OutputSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (s stubTool) Risk() Risk                    { return s.risk }
func (s stubTool) Invoke(context.Context, json.RawMessage) (any, error) {
	return map[string]any{"ok": true}, nil
}

func TestRegisterAndGet(t *testing.T) {
	r := New()
	if err := r.Register(stubTool{name: "alpha"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, ok := r.Get("alpha"); !ok {
		t.Fatal("alpha not found after register")
	}
	if _, ok := r.Get("missing"); ok {
		t.Fatal("missing tool reported present")
	}
}

func TestRegisterDuplicate(t *testing.T) {
	r := New()
	_ = r.Register(stubTool{name: "dup"})
	if err := r.Register(stubTool{name: "dup"}); err == nil {
		t.Fatal("expected duplicate registration error")
	}
}

func TestRegisterNilAndEmpty(t *testing.T) {
	r := New()
	if err := r.Register(nil); err == nil {
		t.Fatal("expected error registering nil tool")
	}
	if err := r.Register(stubTool{name: ""}); err == nil {
		t.Fatal("expected error registering empty-named tool")
	}
}

func TestListSortedAndManifest(t *testing.T) {
	r := New()
	if err := r.RegisterAll(stubTool{name: "gamma"}, stubTool{name: "alpha"}, stubTool{name: "beta"}); err != nil {
		t.Fatalf("register all: %v", err)
	}
	list := r.List()
	want := []string{"alpha", "beta", "gamma"}
	for i, tl := range list {
		if tl.Name() != want[i] {
			t.Errorf("list[%d]: got %q, want %q", i, tl.Name(), want[i])
		}
	}
	man := r.ManifestFor(Admin)
	if len(man) != 3 {
		t.Fatalf("manifest len: got %d, want 3", len(man))
	}
	if man[0].Name != "alpha" || man[0].Description != "stub alpha" {
		t.Errorf("manifest[0]: %+v", man[0])
	}
}

func TestManifestHidesToolsAboveCeiling(t *testing.T) {
	r := New()
	_ = r.RegisterAll(
		stubTool{name: "read", risk: ReadOnly},
		stubTool{name: "mutate", risk: Mutating},
		stubTool{name: "disrupt", risk: Disruptive},
		stubTool{name: "admin", risk: Admin},
	)
	cases := map[Risk][]string{
		ReadOnly:   {"read"},
		Mutating:   {"mutate", "read"},
		Disruptive: {"disrupt", "mutate", "read"},
		Admin:      {"admin", "disrupt", "mutate", "read"},
	}
	for ceiling, want := range cases {
		got := map[string]bool{}
		for _, m := range r.ManifestFor(ceiling) {
			got[m.Name] = true
		}
		if len(got) != len(want) {
			t.Errorf("ceiling %s: got %v, want %v", ceiling, got, want)
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("ceiling %s: missing %q", ceiling, w)
			}
		}
	}
}

func TestManifestConfirmAndPrefix(t *testing.T) {
	r := New()
	_ = r.RegisterAll(
		stubTool{name: "read", risk: ReadOnly},
		stubTool{name: "disrupt", risk: Disruptive},
	)
	for _, m := range r.ManifestFor(Admin) {
		props := map[string]any{}
		var doc map[string]any
		if err := json.Unmarshal(m.InputSchema, &doc); err != nil {
			t.Fatalf("%s schema: %v", m.Name, err)
		}
		if p, ok := doc["properties"].(map[string]any); ok {
			props = p
		}
		_, hasConfirm := props["confirm"]
		switch m.Name {
		case "read":
			if hasConfirm || strings.HasPrefix(m.Description, "[") {
				t.Errorf("read-only tool must not carry confirm or a risk prefix: %+v", m)
			}
		case "disrupt":
			if !hasConfirm {
				t.Errorf("disruptive tool must carry confirm in its schema")
			}
			if !strings.HasPrefix(m.Description, "[DISRUPTIVE") {
				t.Errorf("disruptive description lacks prefix: %q", m.Description)
			}
		}
	}
}

func TestRiskStringAndConfirm(t *testing.T) {
	if ReadOnly.NeedsConfirm() || Mutating.NeedsConfirm() {
		t.Error("read-only and mutating must not need confirm")
	}
	if !Disruptive.NeedsConfirm() || !Admin.NeedsConfirm() {
		t.Error("disruptive and admin must need confirm")
	}
	if Disruptive.String() != "DISRUPTIVE" {
		t.Errorf("String: got %q", Disruptive.String())
	}
}

func TestRedactJSONFields(t *testing.T) {
	in := json.RawMessage(`{"supi":"imsi-1","K":"aa","profile":{"opc":"bb","list":[{"k":"cc","x":1}]}}`)
	out := string(RedactJSONFields(in, "k", "opc"))
	for _, secret := range []string{`"aa"`, `"bb"`, `"cc"`} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %s survived: %s", secret, out)
		}
	}
	if !strings.Contains(out, "imsi-1") || !strings.Contains(out, `"x":1`) {
		t.Errorf("non-secret fields lost: %s", out)
	}
	if bad := string(RedactJSONFields(json.RawMessage(`{"k":"aa`), "k")); strings.Contains(bad, "aa") {
		t.Errorf("malformed input must be replaced: %s", bad)
	}
}
