package jsoncompat

import (
	"encoding/json"
	"testing"
)

type inner struct {
	A int `json:"a"`
}

type rec struct {
	inner
	ID    string `json:"id"`
	Opt   string `json:"opt,omitempty"`
	Skip  string `json:"-"`
	NoTag string
	Extra map[string]json.RawMessage `json:"-"`
}

type recAlias rec

func (r *rec) UnmarshalJSON(b []byte) error { return Unmarshal(b, (*recAlias)(r), &r.Extra) }
func (r rec) MarshalJSON() ([]byte, error)  { return Marshal(recAlias(r), r.Extra) }

func TestRoundTripPreservesUnknown(t *testing.T) {
	in := `{"id":"x","a":3,"future":{"k":[1,2]},"zzz":null,"NoTag":"n"}`
	var r rec
	if err := json.Unmarshal([]byte(in), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Extra) != 2 || string(r.Extra["future"]) != `{"k":[1,2]}` {
		t.Fatalf("extra = %v", r.Extra)
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]any
	_ = json.Unmarshal([]byte(in), &a)
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("keys differ: %s vs %s", in, out)
	}
	out2, _ := json.Marshal(r)
	if string(out) != string(out2) {
		t.Fatal("non-deterministic output")
	}
}

func TestNoExtraIsByteIdentical(t *testing.T) {
	r := rec{ID: "x"}
	got, _ := json.Marshal(r)
	want, _ := json.Marshal(recAlias(r))
	if string(got) != string(want) {
		t.Fatalf("%s != %s", got, want)
	}
}

func TestKnownFieldsWinOnClash(t *testing.T) {
	r := rec{ID: "real", Extra: map[string]json.RawMessage{"id": json.RawMessage(`"fake"`), "ID": json.RawMessage(`1`), "new": json.RawMessage(`true`)}}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":0,"id":"real","NoTag":"","new":true}`
	if string(out) != want {
		t.Fatalf("got %s want %s", out, want)
	}
}

func TestEmptyObjectWithExtra(t *testing.T) {
	type empty struct {
		X int `json:"x,omitempty"`
	}
	out, err := Marshal(empty{}, map[string]json.RawMessage{"b": json.RawMessage(`2`), "a": json.RawMessage(`1`)})
	if err != nil || string(out) != `{"a":1,"b":2}` {
		t.Fatalf("%s %v", out, err)
	}
}

func TestUnmarshalErrors(t *testing.T) {
	var e map[string]json.RawMessage
	var s struct{}
	for name, tc := range map[string]struct {
		data string
		v    any
	}{
		"non-pointer": {`{}`, s},
		"non-struct":  {`{}`, new(int)},
		"bad json":    {`{`, &s},
		"array":       {`[1]`, &s},
	} {
		if err := Unmarshal([]byte(tc.data), tc.v, &e); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestNextVersion(t *testing.T) {
	for _, c := range []struct{ stored, cur, want int }{{0, 1, 1}, {1, 1, 1}, {2, 1, 2}} {
		if got := NextVersion(c.stored, c.cur); got != c.want {
			t.Errorf("NextVersion(%d,%d)=%d want %d", c.stored, c.cur, got, c.want)
		}
	}
}

func TestReadAndStampVersion(t *testing.T) {
	if v := ReadVersion([]byte(`{"a":1}`)); v != 0 {
		t.Errorf("absent: %d", v)
	}
	if v := ReadVersion([]byte(`{"schema_version":"x"}`)); v != 0 {
		t.Errorf("bad type: %d", v)
	}
	if v := ReadVersion([]byte(`not json`)); v != 0 {
		t.Errorf("invalid: %d", v)
	}
	out, err := StampVersion([]byte(`{"a":{"z":1},"schema_version":3}`), 1)
	if err != nil || ReadVersion(out) != 3 {
		t.Fatalf("keep newer: %s %v", out, err)
	}
	out, err = StampVersion([]byte(`{"a":{"z":1}}`), 1)
	if err != nil || ReadVersion(out) != 1 || !json.Valid(out) {
		t.Fatalf("stamp: %s %v", out, err)
	}
	if _, err := StampVersion([]byte(`[1]`), 1); err == nil {
		t.Error("array must fail")
	}
	if _, err := StampVersion([]byte(`null`), 1); err == nil {
		t.Error("null must fail")
	}
}
