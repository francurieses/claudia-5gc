package registry

import (
	"context"
	"encoding/json"
	"testing"
)

type stubTool struct{ name string }

func (s stubTool) Name() string                  { return s.name }
func (s stubTool) Description() string           { return "stub " + s.name }
func (s stubTool) InputSchema() json.RawMessage  { return json.RawMessage(`{"type":"object"}`) }
func (s stubTool) OutputSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (s stubTool) Invoke(context.Context, json.RawMessage) (any, error) {
	return map[string]any{"ok": true}, nil
}

func TestRegisterAndGet(t *testing.T) {
	r := New()
	if err := r.Register(stubTool{"alpha"}); err != nil {
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
	_ = r.Register(stubTool{"dup"})
	if err := r.Register(stubTool{"dup"}); err == nil {
		t.Fatal("expected duplicate registration error")
	}
}

func TestRegisterNilAndEmpty(t *testing.T) {
	r := New()
	if err := r.Register(nil); err == nil {
		t.Fatal("expected error registering nil tool")
	}
	if err := r.Register(stubTool{""}); err == nil {
		t.Fatal("expected error registering empty-named tool")
	}
}

func TestListSortedAndManifest(t *testing.T) {
	r := New()
	if err := r.RegisterAll(stubTool{"gamma"}, stubTool{"alpha"}, stubTool{"beta"}); err != nil {
		t.Fatalf("register all: %v", err)
	}
	list := r.List()
	want := []string{"alpha", "beta", "gamma"}
	for i, tl := range list {
		if tl.Name() != want[i] {
			t.Errorf("list[%d]: got %q, want %q", i, tl.Name(), want[i])
		}
	}
	man := r.Manifest()
	if len(man) != 3 {
		t.Fatalf("manifest len: got %d, want 3", len(man))
	}
	if man[0].Name != "alpha" || man[0].Description != "stub alpha" {
		t.Errorf("manifest[0]: %+v", man[0])
	}
}
