package oapi

import (
	"reflect"
	"testing"
)

const fixture = "../../testdata/spec/Rel-19"

func TestResolve(t *testing.T) {
	l := NewLoader(fixture)
	tests := []struct {
		name     string
		ref      string
		kind     Kind
		required []string
		props    []string
		alts     int
		wantErr  bool
	}{
		{name: "local ref via allOf merge", ref: "TSA_Sample.yaml#/components/schemas/Item", kind: KindObject,
			required: []string{"id", "name"},
			props:    []string{"attrs", "choice", "count", "id", "kind", "loop", "name", "nested", "ok", "ratio", "supi", "tags"}},
		{name: "oneOf is a union, required not mandatory", ref: "TSA_Sample.yaml#/components/schemas/Choice", kind: KindAny,
			required: nil, props: []string{"x", "y"}, alts: 2},
		{name: "cross-file simple type", ref: "TSB_Common.yaml#/components/schemas/Supi", kind: KindString},
		{name: "ref cycle terminates", ref: "TSA_Sample.yaml#/components/schemas/CycA", kind: KindAny},
		{name: "missing schema", ref: "TSA_Sample.yaml#/components/schemas/Nope", wantErr: true},
		{name: "missing file", ref: "Gone.yaml#/components/schemas/X", wantErr: true},
		{name: "bad pointer", ref: "TSA_Sample.yaml#components", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := l.Resolve(tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.Kind != tc.kind {
				t.Errorf("kind = %s want %s", s.Kind, tc.kind)
			}
			if !reflect.DeepEqual(s.Required, tc.required) {
				t.Errorf("required = %v want %v", s.Required, tc.required)
			}
			if tc.props != nil && !reflect.DeepEqual(s.PropNames(), tc.props) {
				t.Errorf("props = %v want %v", s.PropNames(), tc.props)
			}
			if len(s.Alts) != tc.alts {
				t.Errorf("alts = %d want %d", len(s.Alts), tc.alts)
			}
		})
	}
}

func TestPropertyKinds(t *testing.T) {
	l := NewLoader(fixture)
	item, err := l.Resolve("TSA_Sample.yaml#/components/schemas/Item")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		prop string
		kind Kind
		is   func(Kind) bool
	}{
		{"count", KindInteger, nil},
		{"tags", KindArray, nil},
		{"attrs", KindObject, nil},
		{"supi", KindString, nil}, // cross-file $ref
		{"nested", KindObject, nil},
		{"kind", KindAny, func(k Kind) bool { return k == KindString }}, // anyOf enum union
	}
	for _, tc := range tests {
		t.Run(tc.prop, func(t *testing.T) {
			ps, err := l.Flatten(item.Props[tc.prop])
			if err != nil {
				t.Fatal(err)
			}
			if ps.Kind != tc.kind {
				t.Errorf("kind = %s want %s", ps.Kind, tc.kind)
			}
			if tc.is != nil && !ps.Accepts(tc.is) {
				t.Error("union does not accept string branch")
			}
		})
	}
	// Lazy loop: Item.loop -> Item resolves without recursion trouble.
	if _, err := l.Flatten(item.Props["loop"]); err != nil {
		t.Fatal(err)
	}
}

func TestHasYAML(t *testing.T) {
	tests := []struct {
		dir  string
		want bool
	}{{fixture, true}, {"/nonexistent-dir", false}, {"../../testdata/src", false}}
	for _, tc := range tests {
		if got := HasYAML(tc.dir); got != tc.want {
			t.Errorf("HasYAML(%s) = %v", tc.dir, got)
		}
	}
}
