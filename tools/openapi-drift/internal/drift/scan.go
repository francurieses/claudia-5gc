// Package drift scans Go sources for structs annotated with
// "// oapi: <File>.yaml#/components/schemas/<Name>" and compares them with
// the 3GPP OpenAPI schemas, and checks the apiversion table against the
// YAML info.version / servers URL. It is a checker, never a code generator.
package drift

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// Annotation kinds.
const (
	annNone = "none"
	annRef  = "ref"
	annBad  = "bad"
)

// Annotation is a parsed "// oapi:" line.
type Annotation struct {
	Kind   string // annNone, annRef, annBad
	Ref    string // File.yaml#/components/schemas/Name for annRef
	Reason string // opt-out reason, or error text for annBad
}

// Field is one JSON-visible struct field.
type Field struct {
	JSONName string
	Expr     ast.Expr
	Line     int
	Ext      string // reason from "// oapi-ext: <reason>", "" if none
	ExtBad   bool   // "oapi-ext:" present with an empty reason
}

// Struct is a scanned Go struct type.
type Struct struct {
	Name     string
	File     string
	Line     int
	Dir      string
	Ann      *Annotation
	Fields   []Field
	Embedded []ast.Expr // untagged embedded fields, to be flattened
	HasJSON  bool       // at least one field carries a json tag
	pkg      *Package
}

// Package holds all type declarations of one directory.
type Package struct {
	Dir     string
	Types   map[string]ast.Expr
	Structs []*Struct
}

// ExpandPatterns resolves "./nf/..." style patterns and plain directories to
// a sorted list of directories. Subdirectories named testdata, vendor,
// node_modules or starting with "." or "_" are skipped (a root given
// explicitly is always scanned).
func ExpandPatterns(patterns []string) ([]string, error) {
	seen := map[string]bool{}
	var dirs []string
	add := func(d string) {
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	for _, p := range patterns {
		recursive := false
		root := p
		if root == "..." {
			root, recursive = ".", true
		} else if strings.HasSuffix(root, "/...") {
			root, recursive = strings.TrimSuffix(root, "/..."), true
		}
		root = filepath.Clean(root)
		st, err := os.Stat(root)
		if err != nil || !st.IsDir() {
			return nil, fmt.Errorf("drift: pattern %q: not a directory", p)
		}
		if !recursive {
			add(root)
			continue
		}
		err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				return nil
			}
			if path != root {
				n := d.Name()
				if n == "testdata" || n == "vendor" || n == "node_modules" ||
					strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_") {
					return filepath.SkipDir
				}
			}
			add(path)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("drift: walk %s: %w", root, err)
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}

// ScanDirs parses the non-test Go files of each directory.
func ScanDirs(dirs []string) ([]*Package, error) {
	var out []*Package
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			return nil, fmt.Errorf("drift: read dir %s: %w", d, err)
		}
		fset := token.NewFileSet()
		pkg := &Package{Dir: d, Types: map[string]ast.Expr{}}
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			path := filepath.Join(d, n)
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil, fmt.Errorf("drift: parse %s: %w", path, err)
			}
			collect(pkg, fset, path, f)
		}
		if len(pkg.Types) > 0 {
			out = append(out, pkg)
		}
	}
	return out, nil
}

func collect(pkg *Package, fset *token.FileSet, path string, f *ast.File) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, sp := range gd.Specs {
			ts := sp.(*ast.TypeSpec)
			pkg.Types[ts.Name.Name] = ts.Type
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			s := &Struct{
				Name: ts.Name.Name, File: path, Dir: pkg.Dir,
				Line: fset.Position(ts.Pos()).Line, pkg: pkg,
			}
			var groups []*ast.CommentGroup
			groups = append(groups, ts.Doc, ts.Comment)
			if len(gd.Specs) == 1 {
				groups = append(groups, gd.Doc)
			}
			s.Ann = parseAnnotations(groups)
			for _, fl := range st.Fields.List {
				tag := ""
				if fl.Tag != nil {
					tag = strings.Trim(fl.Tag.Value, "`")
				}
				jt, hasTag := reflect.StructTag(tag).Lookup("json")
				if hasTag {
					s.HasJSON = true
				}
				name, _, _ := strings.Cut(jt, ",")
				if name == "-" && jt == "-" {
					continue
				}
				line := fset.Position(fl.Pos()).Line
				ext, extBad := parseExt(fl.Doc, fl.Comment)
				if len(fl.Names) == 0 {
					if name == "" {
						s.Embedded = append(s.Embedded, fl.Type)
						continue
					}
					s.Fields = append(s.Fields, Field{JSONName: name, Expr: fl.Type, Line: line, Ext: ext, ExtBad: extBad})
					continue
				}
				for _, id := range fl.Names {
					if !id.IsExported() {
						continue
					}
					jn := name
					if jn == "" {
						jn = id.Name
					}
					s.Fields = append(s.Fields, Field{JSONName: jn, Expr: fl.Type, Line: line, Ext: ext, ExtBad: extBad})
				}
			}
			pkg.Structs = append(pkg.Structs, s)
		}
	}
}

// parseExt extracts a field-level "// oapi-ext: <reason>" opt-out. bad is
// true when the marker is present without a reason.
func parseExt(groups ...*ast.CommentGroup) (reason string, bad bool) {
	for _, g := range groups {
		if g == nil {
			continue
		}
		for _, c := range g.List {
			t := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
			if rest, ok := strings.CutPrefix(t, "oapi-ext:"); ok {
				if r := strings.TrimSpace(rest); r != "" {
					return r, false
				}
				return "", true
			}
		}
	}
	return "", false
}

// parseAnnotations extracts the oapi annotation from comment groups; nil if
// there is none.
func parseAnnotations(groups []*ast.CommentGroup) *Annotation {
	var found []string
	for _, g := range groups {
		if g == nil {
			continue
		}
		for _, c := range g.List {
			t := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
			if rest, ok := strings.CutPrefix(t, "oapi:"); ok {
				found = append(found, strings.TrimSpace(rest))
			}
		}
	}
	switch len(found) {
	case 0:
		return nil
	case 1:
	default:
		return &Annotation{Kind: annBad, Reason: "multiple oapi: annotations"}
	}
	v := found[0]
	if rest, ok := strings.CutPrefix(v, "none"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
		return &Annotation{Kind: annNone, Reason: strings.TrimSpace(rest)}
	}
	file, frag, ok := strings.Cut(v, "#")
	if !ok || !strings.HasSuffix(file, ".yaml") || !strings.HasPrefix(frag, "/components/schemas/") ||
		len(frag) == len("/components/schemas/") || strings.ContainsAny(v, " \t") {
		return &Annotation{Kind: annBad, Reason: fmt.Sprintf("malformed annotation %q (want <File>.yaml#/components/schemas/<Name> or none <reason>)", v)}
	}
	return &Annotation{Kind: annRef, Ref: v}
}

// AnnotatedRefs returns the sorted, de-duplicated "File.yaml#/components/..."
// references of every "// oapi:" link in pkgs (opt-outs and bad lines are
// skipped).
func AnnotatedRefs(pkgs []*Package) []string {
	seen := map[string]bool{}
	for _, p := range pkgs {
		for _, s := range p.Structs {
			if s.Ann != nil && s.Ann.Kind == annRef {
				seen[s.Ann.Ref] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
