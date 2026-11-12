package diff

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/tools/openapi-drift/internal/oapi"
)

const (
	oldDir = "../../testdata/diff/old"
	newDir = "../../testdata/diff/new"
)

// has reports whether fd holds a change of the given kind/schema/prop whose
// detail contains detailPart; an empty detailPart requires an empty detail.
func has(fd *FileDiff, kind, schema, prop, detailPart string) bool {
	for _, c := range fd.Changes {
		if c.Kind != kind || c.Schema != schema || c.Prop != prop {
			continue
		}
		if detailPart == "" {
			if c.Detail == "" {
				return true
			}
			continue
		}
		if strings.Contains(c.Detail, detailPart) {
			return true
		}
	}
	return false
}

func file(t *testing.T, r *Report, name string) *FileDiff {
	t.Helper()
	for _, f := range r.Files {
		if f.File == name {
			return f
		}
	}
	t.Fatalf("file %s not in report", name)
	return nil
}

func TestCompareAll(t *testing.T) {
	r, err := Compare(oldDir, newDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := file(t, r, "TSD_Sample.yaml")
	cases := []struct{ kind, schema, prop, detail string }{
		{KAddedOptional, "Thing", "newOpt", "string"},
		{KAddedMandatory, "Thing", "mand", "string"},
		{KBecameRequired, "Thing", "opt", ""},
		{KRemoved, "Thing", "gone", "integer"},
		{KPossibleRename, "Thing", "newName", "oldName"},
		{KEnumAdded, "Thing", "kind", "+C"},
		{KEnumAdded, "Thing", "cause", "+Y"},
		{KAddedOptional, "Child", "b", "string"},
		{KSchemaAdded, "Added", "", ""},
		{KSchemaRemoved, "Removed", "", ""},
		{KBecameOptional, "Mut", "r", ""},
		{KTypeChanged, "Mut", "t", "integer -> string"},
		{KEnumRemoved, "Mut", "e", "-Q"},
	}
	for _, c := range cases {
		if !has(f, c.kind, c.schema, c.prop, c.detail) {
			t.Errorf("missing %+v in %+v", c, f.Changes)
		}
	}
	if f.Major {
		t.Error("TSD_Sample must not be a major bump")
	}
	m := file(t, r, "TSE_Major.yaml")
	if !m.Major || m.Counts[KMajorBump] != 1 {
		t.Errorf("TSE_Major: want major bump, got %+v", m)
	}
}

func TestHasEmptyDetail(t *testing.T) {
	fd := &FileDiff{Changes: []Change{{Kind: KRemoved, Schema: "S", Prop: "p", Detail: "x"}}}
	if has(fd, KRemoved, "S", "p", "") {
		t.Error("empty detailPart must not match a non-empty detail")
	}
}

func TestCompareSkipped(t *testing.T) {
	r, err := Compare(oldDir, newDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := file(t, r, "TSD_Sample.yaml")
	if len(f.Skipped) != 1 || f.Skipped[0].Schema != "Broken" || f.Skipped[0].Error == "" {
		t.Fatalf("want Broken skipped with error, got %+v", f.Skipped)
	}
	var md, tx, js bytes.Buffer
	r.WriteMarkdown(&md, false)
	r.WriteText(&tx)
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "## Skipped schemas") || !strings.Contains(md.String(), "`Broken`") {
		t.Errorf("markdown lacks skipped section:\n%s", md.String())
	}
	if !strings.Contains(tx.String(), "skipped schemas: 1") || !strings.Contains(tx.String(), "Broken") {
		t.Errorf("text lacks skipped:\n%s", tx.String())
	}
	if !strings.Contains(js.String(), `"skipped_schemas"`) || !strings.Contains(js.String(), `"Broken"`) {
		t.Errorf("json lacks skipped:\n%s", js.String())
	}
}

func TestCompareUsedFilter(t *testing.T) {
	seeds := []string{"TSD_Sample.yaml#/components/schemas/Thing"}
	sch, unres := Closure(seeds, oapi.NewLoader(oldDir), oapi.NewLoader(newDir))
	if len(unres) != 0 {
		t.Fatalf("unexpected unresolved: %v", unres)
	}
	u := &Used{Schemas: sch,
		Direct: map[string]map[string]bool{"TSD_Sample.yaml": {"Thing": true}}, Files: map[string]bool{}}
	r, err := Compare(oldDir, newDir, u)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 1 || r.Files[0].File != "TSD_Sample.yaml" {
		t.Fatalf("want only TSD_Sample, got %d files", len(r.Files))
	}
	f := r.Files[0]
	if !has(f, KAddedOptional, "Child", "b", "string") {
		t.Error("transitive Child must be included")
	}
	for _, c := range f.Changes {
		if c.Schema == "Unused" || c.Schema == "Added" || c.Schema == "Removed" {
			t.Errorf("schema %s must be filtered out", c.Schema)
		}
		if c.Schema == "Child" && c.Direct {
			t.Error("Child is transitive, not direct")
		}
	}
	// A listed file without used schemas still gets its version compared.
	u.Files["TSE_Major.yaml"] = true
	r, err = Compare(oldDir, newDir, u)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 2 {
		t.Errorf("want 2 files with Files entry, got %d", len(r.Files))
	}
}

func TestClosureUnresolved(t *testing.T) {
	seeds := []string{
		"TSD_Sample.yaml#/components/schemas/Thing",
		"TSD_Sample.yaml#/components/schemas/Missing",
		"TSD_Sample.yaml#/components/schemas/Added", // only in new: not unresolved
		"not-a-ref",
		"TSD_Sample.yaml#/components/schemas/Thing/properties/id",
	}
	sch, unres := Closure(seeds, oapi.NewLoader(oldDir), oapi.NewLoader(newDir))
	if !sch["TSD_Sample.yaml"]["Added"] || !sch["TSD_Sample.yaml"]["Thing"] {
		t.Errorf("closure lacks resolved schemas: %v", sch)
	}
	joined := strings.Join(unres, "\n")
	for _, want := range []string{"Missing", "seed not-a-ref", "properties/id"} {
		if !strings.Contains(joined, want) {
			t.Errorf("unresolved lacks %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "schemas/Added") || strings.Contains(joined, "schemas/Thing:") {
		t.Errorf("resolved seeds reported unresolved:\n%s", joined)
	}
	u := &Used{Schemas: sch, Unresolved: unres, Direct: map[string]map[string]bool{}, Files: map[string]bool{}}
	r, err := Compare(oldDir, newDir, u)
	if err != nil {
		t.Fatal(err)
	}
	var md, tx, js bytes.Buffer
	r.WriteMarkdown(&md, false)
	r.WriteText(&tx)
	_ = r.WriteJSON(&js)
	for name, out := range map[string]string{"md": md.String(), "text": tx.String(), "json": js.String()} {
		if !strings.Contains(out, "Missing") {
			t.Errorf("%s output lacks unresolved seed:\n%s", name, out)
		}
	}
	if !strings.Contains(md.String(), "## Unresolved references") {
		t.Error("markdown lacks unresolved section")
	}
}

func TestCompareFilesAddedRemoved(t *testing.T) {
	dir := t.TempDir()
	o, n := filepath.Join(dir, "o"), filepath.Join(dir, "n")
	writeYAML(t, o, "A.yaml", "1.0.0")
	writeYAML(t, o, "OnlyOld.yaml", "1.0.0")
	writeYAML(t, n, "A.yaml", "1.0.0")
	writeYAML(t, n, "OnlyNew.yaml", "1.0.0")
	r, err := Compare(o, n, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.FilesAdded) != 1 || r.FilesAdded[0] != "OnlyNew.yaml" || len(r.FilesRemoved) != 1 || r.FilesRemoved[0] != "OnlyOld.yaml" {
		t.Errorf("added=%v removed=%v", r.FilesAdded, r.FilesRemoved)
	}
	var md bytes.Buffer
	r.WriteMarkdown(&md, false)
	if !strings.Contains(md.String(), "added: OnlyNew.yaml") || !strings.Contains(md.String(), "removed: OnlyOld.yaml") {
		t.Errorf("markdown lacks files added/removed:\n%s", md.String())
	}
}

func TestCompareMissingDir(t *testing.T) {
	if _, err := Compare(filepath.Join(oldDir, "nope"), newDir, nil); err == nil {
		t.Fatal("want error for missing dir")
	}
}

func TestMarkdownMajorSection(t *testing.T) {
	r, err := Compare(oldDir, newDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	r.WriteMarkdown(&sb, false)
	if !strings.Contains(sb.String(), "TSE_Major.yaml: info.version 1.9.0 -> 2.0.0") {
		t.Errorf("major section missing:\n%s", sb.String())
	}
}

func TestMarkdownDirectDetail(t *testing.T) {
	sch, _ := Closure([]string{"TSD_Sample.yaml#/components/schemas/Thing"}, oapi.NewLoader(oldDir), oapi.NewLoader(newDir))
	u := &Used{Schemas: sch, Direct: map[string]map[string]bool{"TSD_Sample.yaml": {"Thing": true}}, Files: map[string]bool{}}
	r, err := Compare(oldDir, newDir, u)
	if err != nil {
		t.Fatal(err)
	}
	var all, direct strings.Builder
	r.WriteMarkdown(&all, false)
	r.WriteMarkdown(&direct, true)
	if !strings.Contains(all.String(), "`Child.b  string`") {
		t.Errorf("detail all must list Child.b:\n%s", all.String())
	}
	if strings.Contains(direct.String(), "`Child.b") || !strings.Contains(direct.String(), "transitive (not annotated) schemas, counts only: added-optional 1") {
		t.Errorf("detail direct must summarise Child:\n%s", direct.String())
	}
	if !strings.Contains(direct.String(), "`Thing.newOpt  string`") {
		t.Errorf("detail direct must list Thing.newOpt:\n%s", direct.String())
	}
}

func TestRenderDeterministic(t *testing.T) {
	render := func() (string, string, string) {
		r, err := Compare(oldDir, newDir, nil)
		if err != nil {
			t.Fatal(err)
		}
		var md, tx, js bytes.Buffer
		r.WriteMarkdown(&md, false)
		r.WriteText(&tx)
		if err := r.WriteJSON(&js); err != nil {
			t.Fatal(err)
		}
		return md.String(), tx.String(), js.String()
	}
	m1, t1, j1 := render()
	for i := 0; i < 5; i++ {
		m2, t2, j2 := render()
		if m1 != m2 || t1 != t2 || j1 != j2 {
			t.Fatal("rendering is not deterministic")
		}
	}
}

func TestWriteTextJSON(t *testing.T) {
	r, err := Compare(oldDir, newDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tx, js bytes.Buffer
	r.WriteText(&tx)
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tx.String(), "added-optional") || !strings.Contains(tx.String(), "Thing.newOpt  string") {
		t.Errorf("text output:\n%s", tx.String())
	}
	if !strings.Contains(js.String(), `"kind": "type-changed"`) || !strings.Contains(js.String(), `"files_added"`) {
		t.Errorf("json output:\n%s", js.String())
	}
}

func writeYAML(t *testing.T, dir, name, ver string) {
	t.Helper()
	if err := mkdirWrite(dir, name, "openapi: 3.0.0\ninfo:\n  version: "+ver+"\ncomponents:\n  schemas: {}\n"); err != nil {
		t.Fatal(err)
	}
}

func mkdirWrite(dir, name, content string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
}
