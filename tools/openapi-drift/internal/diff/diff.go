// Package diff compares two 3GPP OpenAPI release directories (for example
// Rel-17 and Rel-19) at the component-schema level: added, removed and
// re-typed properties, optional/mandatory transitions, enum extensions and
// info.version / servers-URL major bumps. It is a checker, not a generator.
package diff

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/francurieses/claudia-5gc/tools/openapi-drift/internal/oapi"
)

// Change kinds.
const (
	KSchemaAdded    = "schema-added"
	KSchemaRemoved  = "schema-removed"
	KAddedOptional  = "added-optional"
	KAddedMandatory = "added-mandatory"
	KBecameRequired = "became-required"
	KBecameOptional = "became-optional"
	KRemoved        = "removed"
	KTypeChanged    = "type-changed"
	KEnumAdded      = "enum-added"
	KEnumRemoved    = "enum-removed"
	KPossibleRename = "possible-rename"
	KVersion        = "version"
	KMajorBump      = "major-bump"
)

// Kinds lists every change kind in report order.
var Kinds = []string{KMajorBump, KSchemaAdded, KSchemaRemoved, KAddedMandatory, KAddedOptional,
	KBecameRequired, KBecameOptional, KRemoved, KPossibleRename, KTypeChanged, KEnumAdded, KEnumRemoved}

// Change is one difference.
type Change struct {
	Kind   string `json:"kind"`
	Schema string `json:"schema,omitempty"`
	Prop   string `json:"prop,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Direct is true when the schema is itself annotated (// oapi:) in Go code.
	Direct bool `json:"direct,omitempty"`
}

// FileDiff is the comparison of one YAML present in both releases.
type FileDiff struct {
	File       string         `json:"file"`
	OldVersion string         `json:"old_version"`
	NewVersion string         `json:"new_version"`
	OldURI     string         `json:"old_uri_version,omitempty"`
	NewURI     string         `json:"new_uri_version,omitempty"`
	Major      bool           `json:"major_bump"`
	Changes    []Change       `json:"changes,omitempty"`
	Counts     map[string]int `json:"counts"`
	// Skipped lists schemas present in both releases that could not be
	// resolved or flattened, so they were not compared.
	Skipped []Skip `json:"skipped_schemas,omitempty"`
}

// Skip records one schema that could not be compared and why.
type Skip struct {
	Schema string `json:"schema"`
	Error  string `json:"error"`
}

// Report is the full comparison.
type Report struct {
	OldDir, NewDir   string
	OldProv, NewProv map[string]string
	Used             bool
	FilesAdded       []string
	FilesRemoved     []string
	Files            []*FileDiff
	// Unresolved lists -used seeds or $ref targets that no release could resolve.
	Unresolved []string
}

// Used restricts a comparison. Files maps a YAML name to the schemas in use;
// a nil inner map means the whole file is of interest (version only is
// reported when the schema set is empty). Direct marks annotated schemas.
type Used struct {
	Schemas map[string]map[string]bool // file -> schema -> true
	Direct  map[string]map[string]bool
	Files   map[string]bool // files reported even without used schemas
	// Unresolved lists seeds/refs found unresolvable by Closure (reported, not fatal).
	Unresolved []string
}

var (
	verMajor = regexp.MustCompile(`^\s*v?(\d+)`)
	uriMajor = regexp.MustCompile(`/(v[0-9]+)(?:/|$)`)
)

// Compare diffs oldDir against newDir. u may be nil (report everything).
func Compare(oldDir, newDir string, u *Used) (*Report, error) {
	for _, d := range []string{oldDir, newDir} {
		if !oapi.HasYAML(d) {
			return nil, fmt.Errorf("diff: %q is missing or has no *.yaml files", d)
		}
	}
	r := &Report{OldDir: oldDir, NewDir: newDir, Used: u != nil}
	if u != nil {
		r.Unresolved = append(r.Unresolved, u.Unresolved...)
	}
	var err error
	if r.OldProv, err = provenance(oldDir); err != nil {
		return nil, err
	}
	if r.NewProv, err = provenance(newDir); err != nil {
		return nil, err
	}
	oldF, err := yamlNames(oldDir)
	if err != nil {
		return nil, err
	}
	newF, err := yamlNames(newDir)
	if err != nil {
		return nil, err
	}
	ol, nl := oapi.NewLoader(oldDir), oapi.NewLoader(newDir)
	want := func(f string) bool { return u == nil || u.Files[f] || len(u.Schemas[f]) > 0 }
	for f := range newF {
		if !oldF[f] && want(f) {
			r.FilesAdded = append(r.FilesAdded, f)
		}
	}
	for f := range oldF {
		if !newF[f] && want(f) {
			r.FilesRemoved = append(r.FilesRemoved, f)
		}
	}
	sort.Strings(r.FilesAdded)
	sort.Strings(r.FilesRemoved)
	var both []string
	for f := range oldF {
		if newF[f] && want(f) {
			both = append(both, f)
		}
	}
	sort.Strings(both)
	for _, f := range both {
		fd, err := compareFile(ol, nl, f, u)
		if err != nil {
			return nil, err
		}
		r.Files = append(r.Files, fd)
	}
	return r, nil
}

// provenance reads dir/UPSTREAM-COMMIT; a missing file yields an empty map
// (rendered as "unknown"), any other read error is returned.
func provenance(dir string) (map[string]string, error) {
	m := map[string]string{}
	b, err := os.ReadFile(filepath.Join(dir, "UPSTREAM-COMMIT"))
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("diff: read provenance: %w", err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m, nil
}

func yamlNames(dir string) (map[string]bool, error) {
	m, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("diff: list yaml in %q: %w", dir, err)
	}
	out := map[string]bool{}
	for _, p := range m {
		out[filepath.Base(p)] = true
	}
	return out, nil
}

func info(doc any) (ver, uri string) {
	m, _ := doc.(map[string]any)
	if i, ok := m["info"].(map[string]any); ok {
		if v, ok := i["version"]; ok {
			ver = fmt.Sprint(v)
		}
	}
	svs, _ := m["servers"].([]any)
	for _, sv := range svs {
		sm, _ := sv.(map[string]any)
		u, _ := sm["url"].(string)
		if mm := uriMajor.FindStringSubmatch(u); mm != nil {
			return ver, mm[1]
		}
	}
	return ver, ""
}

func major(v string) string {
	if m := verMajor.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	return ""
}

func schemasOf(doc any) map[string]any {
	m, _ := doc.(map[string]any)
	c, _ := m["components"].(map[string]any)
	s, _ := c["schemas"].(map[string]any)
	return s
}

func compareFile(ol, nl *oapi.Loader, f string, u *Used) (*FileDiff, error) {
	od, err := ol.File(f)
	if err != nil {
		return nil, fmt.Errorf("diff: %w", err)
	}
	nd, err := nl.File(f)
	if err != nil {
		return nil, fmt.Errorf("diff: %w", err)
	}
	fd := &FileDiff{File: f, Counts: map[string]int{}}
	fd.OldVersion, fd.OldURI = info(od)
	fd.NewVersion, fd.NewURI = info(nd)
	if (major(fd.OldVersion) != major(fd.NewVersion)) || fd.OldURI != fd.NewURI {
		fd.Major = true
		fd.add(Change{Kind: KMajorBump, Detail: fmt.Sprintf("info.version %s -> %s, URI %s -> %s",
			fd.OldVersion, fd.NewVersion, orDash(fd.OldURI), orDash(fd.NewURI))})
	}
	os_, ns := schemasOf(od), schemasOf(nd)
	names := map[string]bool{}
	for k := range os_ {
		names[k] = true
	}
	for k := range ns {
		names[k] = true
	}
	var sorted []string
	for k := range names {
		if u == nil || u.Schemas[f][k] {
			sorted = append(sorted, k)
		}
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		direct := u != nil && u.Direct[f][name]
		_, inOld := os_[name]
		_, inNew := ns[name]
		switch {
		case !inOld:
			fd.add(Change{Kind: KSchemaAdded, Schema: name, Direct: direct})
		case !inNew:
			fd.add(Change{Kind: KSchemaRemoved, Schema: name, Direct: direct})
		default:
			cs, err := compareSchema(ol, nl, f, name, direct)
			if err != nil {
				fd.Skipped = append(fd.Skipped, Skip{Schema: name, Error: err.Error()})
			}
			for _, c := range cs {
				fd.add(c)
			}
		}
	}
	return fd, nil
}

func (fd *FileDiff) add(c Change) {
	fd.Changes = append(fd.Changes, c)
	fd.Counts[c.Kind]++
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func compareSchema(ol, nl *oapi.Loader, f, name string, direct bool) ([]Change, error) {
	ref := f + "#/components/schemas/" + name
	on, err := ol.Lookup("", ref)
	if err != nil {
		return nil, fmt.Errorf("old lookup: %w", err)
	}
	nn, err := nl.Lookup("", ref)
	if err != nil {
		return nil, fmt.Errorf("new lookup: %w", err)
	}
	os_, err := ol.Flatten(on)
	if err != nil {
		return nil, fmt.Errorf("old flatten: %w", err)
	}
	ns, err := nl.Flatten(nn)
	if err != nil {
		return nil, fmt.Errorf("new flatten: %w", err)
	}
	var out []Change
	mk := func(kind, prop, detail string) {
		out = append(out, Change{Kind: kind, Schema: name, Prop: prop, Detail: detail, Direct: direct})
	}
	if ev := enumDelta(on.Raw, nn.Raw); ev != nil {
		emit(ev, func(k, d string) { mk(k, "", d) })
	}
	oreq, nreq := set(os_.Required), set(ns.Required)
	var added, removed []string
	for _, p := range ns.PropNames() {
		if _, ok := os_.Props[p]; !ok {
			added = append(added, p)
		}
	}
	for _, p := range os_.PropNames() {
		if _, ok := ns.Props[p]; !ok {
			removed = append(removed, p)
		}
	}
	// Heuristic rename pairing: same described type, one-to-one.
	usedRem := map[string]bool{}
	for _, a := range added {
		ad := describe(ns.Props[a])
		var cand []string
		for _, r := range removed {
			if !usedRem[r] && describe(os_.Props[r]) == ad {
				cand = append(cand, r)
			}
		}
		if len(cand) == 1 {
			usedRem[cand[0]] = true
			mk(KPossibleRename, a, fmt.Sprintf("heuristic: %s -> %s (same type %s)", cand[0], a, ad))
		}
	}
	for _, a := range added {
		kind := KAddedOptional
		if nreq[a] {
			kind = KAddedMandatory
		}
		mk(kind, a, describe(ns.Props[a]))
	}
	for _, r := range removed {
		mk(KRemoved, r, describe(os_.Props[r]))
	}
	for _, p := range ns.PropNames() {
		on2, ok := os_.Props[p]
		if !ok {
			continue
		}
		nn2 := ns.Props[p]
		if oreq[p] && !nreq[p] {
			mk(KBecameOptional, p, "")
		}
		if !oreq[p] && nreq[p] {
			mk(KBecameRequired, p, "")
		}
		if od, nd := describe(on2), describe(nn2); od != nd {
			mk(KTypeChanged, p, od+" -> "+nd)
		}
		if ev := enumDelta(on2.Raw, nn2.Raw); ev != nil {
			emit(ev, func(k, d string) { mk(k, p, d) })
		}
	}
	return out, nil
}

type enumChange struct{ added, removed []string }

func emit(e *enumChange, f func(kind, detail string)) {
	if len(e.added) > 0 {
		f(KEnumAdded, "+"+strings.Join(e.added, ", "))
	}
	if len(e.removed) > 0 {
		f(KEnumRemoved, "-"+strings.Join(e.removed, ", "))
	}
}

func set(in []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	return m
}

// describe renders a property's type: $ref target name, array<...> or type.
func describe(n oapi.Node) string { return describeRaw(n.Raw, 0) }

func describeRaw(raw any, depth int) string {
	m, ok := raw.(map[string]any)
	if !ok || depth > 4 {
		return "any"
	}
	if r, ok := m["$ref"].(string); ok {
		if i := strings.LastIndex(r, "/"); i >= 0 {
			r = r[i+1:]
		}
		return "$" + r
	}
	if t, ok := m["type"].(string); ok {
		if t == "array" {
			return "array<" + describeRaw(m["items"], depth+1) + ">"
		}
		return t
	}
	for _, k := range []string{"allOf", "anyOf", "oneOf"} {
		if parts, ok := m[k].([]any); ok && len(parts) > 0 {
			var ds []string
			for _, p := range parts {
				d := describeRaw(p, depth+1)
				if d != "any" {
					ds = append(ds, d)
				}
			}
			sort.Strings(ds)
			if len(ds) == 0 {
				return "any"
			}
			if len(ds) == 1 && k == "allOf" {
				return ds[0]
			}
			return k + "(" + strings.Join(ds, "|") + ")"
		}
	}
	if _, ok := m["properties"]; ok {
		return "object"
	}
	return "any"
}

// enums collects enum values reachable through enum/allOf/anyOf/oneOf without
// following $ref (a referenced schema is diffed on its own).
func enums(raw any, depth int, into map[string]bool) {
	m, ok := raw.(map[string]any)
	if !ok || depth > 6 {
		return
	}
	if e, ok := m["enum"].([]any); ok {
		for _, v := range e {
			into[fmt.Sprint(v)] = true
		}
	}
	for _, k := range []string{"allOf", "anyOf", "oneOf"} {
		if parts, ok := m[k].([]any); ok {
			for _, p := range parts {
				enums(p, depth+1, into)
			}
		}
	}
	if it, ok := m["items"]; ok {
		enums(it, depth+1, into)
	}
}

func enumDelta(oldRaw, newRaw any) *enumChange {
	o, n := map[string]bool{}, map[string]bool{}
	enums(oldRaw, 0, o)
	enums(newRaw, 0, n)
	if len(o) == 0 && len(n) == 0 {
		return nil
	}
	e := &enumChange{}
	for v := range n {
		if !o[v] {
			e.added = append(e.added, v)
		}
	}
	for v := range o {
		if !n[v] {
			e.removed = append(e.removed, v)
		}
	}
	sort.Strings(e.added)
	sort.Strings(e.removed)
	if len(e.added) == 0 && len(e.removed) == 0 {
		return nil
	}
	return e
}

// Closure returns, for the seed refs ("File.yaml#/components/schemas/Name"),
// the set of schemas transitively reachable through $ref in either loader,
// plus a sorted list of seeds and schema refs that could not be resolved in
// any loader (malformed refs included). A schema present in only one release
// is not unresolved.
func Closure(seeds []string, loaders ...*oapi.Loader) (map[string]map[string]bool, []string) {
	out := map[string]map[string]bool{}
	failed := map[string]string{} // "file#name" -> first error
	bad := map[string]string{}    // malformed ref -> error
	var visit func(l *oapi.Loader, file, name string)
	seen := map[string]bool{}
	visit = func(l *oapi.Loader, file, name string) {
		key := fmt.Sprintf("%p|%s#%s", l, file, name)
		if seen[key] {
			return
		}
		seen[key] = true
		n, err := l.Lookup("", file+"#/components/schemas/"+name)
		if err != nil {
			if _, ok := failed[file+"#"+name]; !ok {
				failed[file+"#"+name] = err.Error()
			}
			return
		}
		if out[file] == nil {
			out[file] = map[string]bool{}
		}
		out[file][name] = true
		walkRefs(n.Raw, func(ref string) {
			rf, ptr, err := oapi.SplitRef(ref)
			if err != nil {
				bad[file+" -> "+ref] = err.Error()
				return
			}
			if len(ptr) < 2 || ptr[0] != "components" || ptr[1] != "schemas" {
				return // non-schema reference (parameters, responses, ...)
			}
			if len(ptr) != 3 {
				bad[file+" -> "+ref] = "unsupported schema pointer depth"
				return
			}
			if rf == "" {
				rf = file
			} else {
				rf = filepath.Clean(filepath.Join(filepath.Dir(file), rf))
			}
			visit(l, rf, ptr[2])
		})
	}
	for _, s := range seeds {
		f, ptr, err := oapi.SplitRef(s)
		if err != nil || len(ptr) != 3 {
			msg := "expected File.yaml#/components/schemas/Name"
			if err != nil {
				msg = err.Error()
			}
			bad["seed "+s] = msg
			continue
		}
		for _, l := range loaders {
			visit(l, filepath.Clean(f), ptr[2])
		}
	}
	var unresolved []string
	for k, msg := range failed {
		file, name, _ := strings.Cut(k, "#")
		if !out[file][name] {
			unresolved = append(unresolved, fmt.Sprintf("%s#/components/schemas/%s: %s", file, name, msg))
		}
	}
	for k, msg := range bad {
		unresolved = append(unresolved, k+": "+msg)
	}
	sort.Strings(unresolved)
	return out, unresolved
}

func walkRefs(raw any, f func(string)) {
	switch v := raw.(type) {
	case map[string]any:
		for k, x := range v {
			if k == "$ref" {
				if s, ok := x.(string); ok {
					f(s)
				}
				continue
			}
			walkRefs(x, f)
		}
	case []any:
		for _, x := range v {
			walkRefs(x, f)
		}
	}
}
