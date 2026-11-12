package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const (
	spec = "testdata/spec/Rel-19"
	src  = "testdata/src/..."
)

func TestRun(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		rc     int
		outHas []string
		outNot []string
		errHas string
	}{
		{"report mode exits 0 with findings", []string{"-spec", spec, src}, 0,
			[]string{"openapi-drift report", "branch=REL-19 commit=abc123", "[missing-mandatory]", "BadItem.name", "summary:"}, []string{"unannotated"}, ""},
		{"fail-on hit", []string{"-spec", spec, "-fail-on", "missing-mandatory", src}, 1, nil, nil, ""},
		{"fail-on all hit", []string{"-spec", spec, "-fail-on", "all", src}, 1, nil, nil, ""},
		{"fail-on category without hits", []string{"-spec", spec, "-fail-on", "version-drift", src}, 0, nil, nil, ""},
		{"fail-on extension explicit", []string{"-spec", spec, "-fail-on", "extension", src}, 1, nil, nil, ""},
		{"format md", []string{"-spec", spec, "-format", "md", src}, 0, []string{"# openapi-drift report", "| extension | 2 |"}, nil, ""},
		{"fail-on unknown category", []string{"-spec", spec, "-fail-on", "bogus", src}, 2, nil, nil, "unknown category"},
		{"missing spec dir", []string{"-spec", "/nonexistent", src}, 2, nil, nil, "make sync-openapi"},
		{"spec dir without yaml", []string{"-spec", "testdata/src", src}, 2, nil, nil, "no *.yaml"},
		{"spec required", []string{src}, 2, nil, nil, "-spec is required"},
		{"bad flag", []string{"-nope"}, 2, nil, nil, ""},
		{"bad profile", []string{"-spec", spec, "-profile", "rel9", src}, 2, nil, nil, "unknown -profile"},
		{"bad pattern", []string{"-spec", spec, "nope/..."}, 2, nil, nil, "not a directory"},
		{"unannotated works without spec", []string{"-unannotated", src}, 0,
			[]string{"unannotated total: 2", "types.go:"}, []string{"openapi-drift report"}, ""},
		{"unannotated custom scope", []string{"-unannotated", "-scope", "/other", src}, 0,
			[]string{"unannotated total: 1", "Thing"}, nil, ""},
		{"profile from dir name rel17", []string{"-spec", "testdata/spec/Rel-17", src}, 0,
			[]string{"profile: rel17"}, nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			rc := run(tc.args, &out, &errb)
			if rc != tc.rc {
				t.Fatalf("rc = %d want %d\nstdout:\n%s\nstderr:\n%s", rc, tc.rc, out.String(), errb.String())
			}
			for _, s := range tc.outHas {
				if !strings.Contains(out.String(), s) {
					t.Errorf("stdout lacks %q:\n%s", s, out.String())
				}
			}
			for _, s := range tc.outNot {
				if strings.Contains(out.String(), s) {
					t.Errorf("stdout has %q", s)
				}
			}
			if tc.errHas != "" && !strings.Contains(errb.String(), tc.errHas) {
				t.Errorf("stderr lacks %q: %s", tc.errHas, errb.String())
			}
		})
	}
}

func TestRunJSON(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run([]string{"-spec", spec, "-format", "json", "-unannotated", src}, &out, &errb); rc != 0 {
		t.Fatalf("rc=%d %s", rc, errb.String())
	}
	var v struct {
		Header      struct{ Commit string }
		Findings    []map[string]any
		Counts      map[string]int
		Unannotated []map[string]any
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Header.Commit != "abc123" || len(v.Findings) == 0 || v.Counts["missing-mandatory"] == 0 || len(v.Unannotated) != 2 {
		t.Errorf("unexpected json: %+v", v)
	}
}

func TestRunDeterministic(t *testing.T) {
	var a, b, e bytes.Buffer
	run([]string{"-spec", spec, src}, &a, &e)
	run([]string{"-spec", spec, src}, &b, &e)
	if a.String() != b.String() {
		t.Error("report is not deterministic")
	}
}

func TestRunDiff(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-diff", "testdata/diff/old", "testdata/diff/new", "-used", "-format", "json", "./testdata/diff/src"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var rep struct {
		Unresolved []string `json:"unresolved"`
		Files      []struct {
			File    string `json:"file"`
			Changes []struct{ Kind, Schema, Prop, Detail string }
		} `json:"files"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("bad json: %v\n%s", err, out.String())
	}
	found := false
	for _, f := range rep.Files {
		for _, c := range f.Changes {
			if c.Schema == "Unused" {
				t.Errorf("Unused must be filtered: %+v", c)
			}
			if f.File == "TSD_Sample.yaml" && c.Kind == "added-optional" && c.Schema == "Thing" && c.Prop == "newOpt" && c.Detail == "string" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("want added-optional Thing.newOpt string: %s", out.String())
	}
	if len(rep.Unresolved) != 0 {
		t.Errorf("unexpected unresolved: %v", rep.Unresolved)
	}

	// md output with direct detail carries the line and the new sections.
	out.Reset()
	if c := run([]string{"-diff", "testdata/diff/old", "testdata/diff/new", "-used", "-format", "md", "-detail", "direct", "./testdata/diff/src"}, &out, &errb); c != 0 {
		t.Fatalf("md exit %d: %s", c, errb.String())
	}
	if !strings.Contains(out.String(), "`Thing.newOpt  string`") || !strings.Contains(out.String(), "## Skipped schemas") {
		t.Errorf("md output:\n%s", out.String())
	}

	for name, args := range map[string][]string{
		"missing dir":    {"-diff", "testdata/diff/old", "testdata/nonexistent"},
		"one arg":        {"-diff", "only-one"},
		"diff with spec": {"-diff", "testdata/diff/old", "testdata/diff/new", "-spec", "testdata/diff/new"},
		"detail non-md":  {"-diff", "testdata/diff/old", "testdata/diff/new", "-detail", "direct"},
		"bad detail":     {"-diff", "testdata/diff/old", "testdata/diff/new", "-format", "md", "-detail", "x"},
	} {
		if c := run(args, &out, &errb); c != 2 {
			t.Errorf("%s: want 2, got %d", name, c)
		}
	}
}
