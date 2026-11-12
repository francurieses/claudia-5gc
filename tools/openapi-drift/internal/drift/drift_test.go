package drift

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/tools/openapi-drift/internal/oapi"
)

const (
	specDir = "../../testdata/spec/Rel-19"
	srcDir  = "../../testdata/src"
)

func scan(t *testing.T) []*Package {
	t.Helper()
	dirs, err := ExpandPatterns([]string{srcDir + "/..."})
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := ScanDirs(dirs)
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

func keys(f []Finding) map[string]bool {
	m := map[string]bool{}
	for _, x := range f {
		m[x.Category+"|"+x.Type+"|"+x.Field] = true
	}
	return m
}

func TestCheckStructs(t *testing.T) {
	got := CheckStructs(oapi.NewLoader(specDir), scan(t))
	k := keys(got)
	tests := []struct {
		key  string
		want bool
	}{
		// BadItem: every category, positive.
		{"missing-mandatory|BadItem|name", true},
		{"unknown-attr|BadItem|bogus", true},
		{"unknown-attr|BadItem|Untag", true}, // untagged field uses Go name
		{"type-mismatch|BadItem|count", true},
		{"type-mismatch|BadItem|kind", true},
		{"type-mismatch|BadItem|ratio", true},
		{"type-mismatch|BadItem|tags", true},
		{"type-mismatch|BadItem|nested", true},
		{"type-mismatch|BadItem|choice", true},
		{"missing-mandatory|BadItem|id", false},
		{"type-mismatch|BadItem|id", false},
		// GoodItem: no findings at all (embedded flatten, pointers, named
		// string, RawMessage, unions, json:"-", unexported).
		{"missing-mandatory|GoodItem|id", false},
		{"missing-mandatory|GoodItem|name", false},
		// Foreign embed: mandatory check skipped (cannot see embedded fields).
		{"missing-mandatory|ForeignEmbed|id", false},
		// oneOf branches' required are not mandatory.
		{"missing-mandatory|UnionObj|x", false},
		{"unknown-attr|UnionObj|y", false},
		{"bad-annotation|Malformed|", true},
		{"unresolved-ref|NoSchema|", true},
		{"unresolved-ref|NoFile|", true},
		{"unresolved-ref|Cyc|", false},
		{"unknown-attr|Cyc|a", false}, // truncated by cycle: never a false positive
		{"missing-mandatory|Trailing|id", false},
		// oapi: none suppresses everything.
		{"unknown-attr|OptOut|a", false},
	}
	for _, tc := range tests {
		if k[tc.key] != tc.want {
			t.Errorf("finding %q present=%v want %v", tc.key, k[tc.key], tc.want)
		}
	}
	for _, f := range got {
		if f.Type == "GoodItem" || f.Type == "OptOut" || f.Type == "Plain" {
			t.Errorf("unexpected finding %+v", f)
		}
	}
}

func TestCheckStructsDeterministic(t *testing.T) {
	a := CheckStructs(oapi.NewLoader(specDir), scan(t))
	b := CheckStructs(oapi.NewLoader(specDir), scan(t))
	if len(a) != len(b) {
		t.Fatal("length differs")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("order differs at %d", i)
		}
	}
}

func TestParseAnnotations(t *testing.T) {
	tests := []struct {
		src  string
		kind string
		ref  string
	}{
		{"// oapi: TS1_X.yaml#/components/schemas/Y\ntype T struct{}", annRef, "TS1_X.yaml#/components/schemas/Y"},
		{"// oapi: none because\ntype T struct{}", annNone, ""},
		{"// oapi: none\ntype T struct{}", annNone, ""},
		{"// oapi: nonex\ntype T struct{}", annBad, ""},
		{"// oapi: X.yaml#/paths/foo\ntype T struct{}", annBad, ""},
		{"// oapi: X.yaml#/components/schemas/\ntype T struct{}", annBad, ""},
		{"// oapi: A.yaml#/components/schemas/A\n// oapi: none x\ntype T struct{}", annBad, ""},
	}
	for _, tc := range tests {
		dir := t.TempDir()
		src := "package p\n\n" + tc.src + "\n"
		if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		pkgs, err := ScanDirs([]string{dir})
		if err != nil {
			t.Fatal(err)
		}
		a := pkgs[0].Structs[0].Ann
		if a == nil || a.Kind != tc.kind || a.Ref != tc.ref {
			t.Errorf("%q: got %+v", tc.src, a)
		}
	}
}

func TestTrailingComment(t *testing.T) {
	dir := t.TempDir()
	src := "package p\n\ntype T struct{ A string `json:\"a\"` } // oapi: none trailing\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := ScanDirs([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if a := pkgs[0].Structs[0].Ann; a == nil || a.Kind != annNone {
		t.Errorf("trailing annotation not parsed: %+v", a)
	}
}

func TestFindUnannotated(t *testing.T) {
	pkgs := scan(t)
	tests := []struct {
		name  string
		scope string
		want  []string
	}{
		{"default scope", DefaultScope, []string{"BaseEmb", "Plain"}},
		{"everything", `.`, []string{"BaseEmb", "Plain", "Thing"}},
		{"no match", `/nomatch/`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FindUnannotated(pkgs, regexp.MustCompile(tc.scope))
			var names []string
			for _, u := range got {
				names = append(names, u.Type)
			}
			if strings.Join(names, ",") != strings.Join(tc.want, ",") {
				t.Errorf("got %v want %v", names, tc.want)
			}
		})
	}
}

func TestExpandPatternsSkips(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a/b", "a/testdata", "a/vendor", "a/.hidden", "a/node_modules"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ExpandPatterns([]string{root + "/..."})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{root, filepath.Join(root, "a"), filepath.Join(root, "a/b")}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v want %v", got, want)
	}
	if _, err := ExpandPatterns([]string{root + "/nope"}); err == nil {
		t.Error("want error for missing dir")
	}
}

func TestCheckVersions(t *testing.T) {
	entries := []apiversion.Entry{
		{Service: "ok", YAML: "TSA_Sample", InURI: "v1", Rel17: "1.2.0", Rel19: "1.4.0"},
		{Service: "badfull", YAML: "TSA_Sample", InURI: "v1", Rel17: "1.2.0", Rel19: "9.9.9"},
		{Service: "baduri", YAML: "TSA_Sample", InURI: "v2", Rel17: "1.2.0", Rel19: "1.4.0"},
		{Service: "gone", YAML: "TSZ_Gone", InURI: "v1", Rel17: "1.0.0", Rel19: "1.0.0"},
	}
	tests := []struct {
		name    string
		dir     string
		profile string
		want    []string
	}{
		{"rel19", specDir, apiversion.ProfileRel19, []string{
			"version-drift|badfull|apiFullVersion", "version-drift|baduri|apiVersionInUri", "missing-yaml|gone|"}},
		// Rel-17 fixture has no servers URL major drift (v1) but lacks the
		// Rel19 column: use the rel17 column against the Rel-17 dir.
		{"rel17", "../../testdata/spec/Rel-17", apiversion.ProfileRel17, []string{
			"version-drift|baduri|apiVersionInUri", "missing-yaml|gone|"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := keys(CheckVersions(oapi.NewLoader(tc.dir), entries, tc.profile))
			if len(k) != len(tc.want) {
				t.Errorf("got %v want %v", k, tc.want)
			}
			for _, w := range tc.want {
				if !k[w] {
					t.Errorf("missing %q in %v", w, k)
				}
			}
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			t.Fatal("go.mod not found")
		}
		d = p
	}
}

func TestRealApiversionTable(t *testing.T) {
	for _, rel := range []struct{ dir, profile string }{
		{"Rel-19", apiversion.ProfileRel19}, {"Rel-17", apiversion.ProfileRel17},
	} {
		dir := filepath.Join(repoRoot(t), "specs/3gpp-openapi", rel.dir)
		if !oapi.HasYAML(dir) {
			t.Skipf("%s not present; run: make sync-openapi REL=%s", dir, rel.dir)
		}
		if f := CheckVersions(oapi.NewLoader(dir), apiversion.All(), rel.profile); len(f) != 0 {
			t.Errorf("%s: version drift: %+v", rel.dir, f)
		}
	}
}

func TestFieldExtension(t *testing.T) {
	got := CheckStructs(oapi.NewLoader(specDir), scan(t))
	k := keys(got)
	for key, want := range map[string]bool{
		"extension|ExtItem|hint":          true,
		"extension|ExtItem|tail":          true,
		"unknown-attr|ExtItem|hint":       false,
		"unknown-attr|ExtItem|tail":       false,
		"unknown-attr|ExtItem|stray":      true,
		"extension|ExtItem|stray":         false,
		"bad-annotation|ExtItem|noReason": true,
		// a reasonless marker does not suppress the unknown-attr either
		"unknown-attr|ExtItem|noReason": true,
	} {
		if k[key] != want {
			t.Errorf("finding %q present=%v want %v", key, k[key], want)
		}
	}
	r := NewReport(Header{Spec: "s", Profile: "rel19"}, got)
	if r.Counts[CatExtension] != 2 {
		t.Errorf("extension count = %d want 2", r.Counts[CatExtension])
	}
	var txt, md strings.Builder
	r.WriteText(&txt)
	r.WriteMarkdown(&md)
	if !strings.Contains(txt.String(), "extension=2") || !strings.Contains(md.String(), "| extension | 2 |") {
		t.Errorf("extension counter missing:\n%s\n%s", txt.String(), md.String())
	}
	// extension is never a failing category on its own
	if n := r.Count(map[string]bool{}); n != 0 {
		t.Errorf("empty category set counted %d", n)
	}
}
