package drift

import (
	"fmt"
	"go/ast"
	"regexp"
	"sort"
	"strings"

	"github.com/francurieses/claudia-5gc/tools/openapi-drift/internal/oapi"
)

// Finding categories.
const (
	CatBadAnnotation    = "bad-annotation"
	CatUnresolvedRef    = "unresolved-ref"
	CatMissingMandatory = "missing-mandatory"
	CatUnknownAttr      = "unknown-attr"
	CatTypeMismatch     = "type-mismatch"
	CatVersionDrift     = "version-drift"
	CatMissingYAML      = "missing-yaml"
	// CatExtension counts fields that carry "// oapi-ext: <reason>": a
	// documented project-specific member with no spec home. It is not part of
	// -fail-on all; a run fails on it only when "extension" is named
	// explicitly (-fail-on extension).
	CatExtension = "extension"
)

// Categories lists every valid finding category in report order.
var Categories = []string{
	CatBadAnnotation, CatUnresolvedRef, CatMissingMandatory,
	CatUnknownAttr, CatTypeMismatch, CatVersionDrift, CatMissingYAML,
	CatExtension,
}

// Finding is one drift finding.
type Finding struct {
	Category string `json:"category"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Type     string `json:"type"`
	Field    string `json:"field,omitempty"`
	Message  string `json:"message"`
}

// Unannotated is a JSON struct without an oapi: annotation.
type Unannotated struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Type string `json:"type"`
}

// SortFindings orders findings by category, file, line, type, field.
func SortFindings(f []Finding) {
	rank := map[string]int{}
	for i, c := range Categories {
		rank[c] = i
	}
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		switch {
		case rank[a.Category] != rank[b.Category]:
			return rank[a.Category] < rank[b.Category]
		case a.File != b.File:
			return a.File < b.File
		case a.Line != b.Line:
			return a.Line < b.Line
		case a.Type != b.Type:
			return a.Type < b.Type
		case a.Field != b.Field:
			return a.Field < b.Field
		}
		return a.Message < b.Message
	})
}

// CheckStructs compares every annotated struct with its schema.
func CheckStructs(l *oapi.Loader, pkgs []*Package) []Finding {
	var out []Finding
	for _, p := range pkgs {
		for _, s := range p.Structs {
			if s.Ann == nil || s.Ann.Kind == annNone {
				continue
			}
			for _, f := range s.Fields {
				if f.ExtBad {
					out = append(out, Finding{Category: CatBadAnnotation, File: s.File, Line: f.Line, Type: s.Name, Field: f.JSONName,
						Message: "oapi-ext: requires a reason naming why the member has no spec home"})
				}
			}
			if s.Ann.Kind == annBad {
				out = append(out, Finding{Category: CatBadAnnotation, File: s.File, Line: s.Line, Type: s.Name, Message: s.Ann.Reason})
				continue
			}
			out = append(out, checkStruct(l, s)...)
		}
	}
	SortFindings(out)
	return out
}

func checkStruct(l *oapi.Loader, s *Struct) []Finding {
	sc, err := l.Resolve(s.Ann.Ref)
	if err != nil {
		return []Finding{{Category: CatUnresolvedRef, File: s.File, Line: s.Line, Type: s.Name,
			Message: fmt.Sprintf("%s: %v", s.Ann.Ref, err)}}
	}
	fields, complete := flattenFields(s, map[*Struct]bool{})
	have := map[string]bool{}
	var out []Finding
	for _, f := range fields {
		have[f.JSONName] = true
		pn, known := sc.Props[f.JSONName]
		if !known {
			if sc.Truncated {
				continue
			}
			if f.Ext != "" {
				out = append(out, Finding{Category: CatExtension, File: s.File, Line: f.Line, Type: s.Name, Field: f.JSONName,
					Message: fmt.Sprintf("project extension, not a property of %s: %s", s.Ann.Ref, f.Ext)})
				continue
			}
			out = append(out, Finding{Category: CatUnknownAttr, File: s.File, Line: f.Line, Type: s.Name, Field: f.JSONName,
				Message: fmt.Sprintf("JSON name %q is not a property of %s", f.JSONName, s.Ann.Ref)})
			continue
		}
		ps, err := l.Flatten(pn)
		if err != nil {
			continue // unresolvable property schema: never a false positive
		}
		gk := goKind(f.Expr, s.pkg, 0)
		if !compatible(ps, gk) {
			out = append(out, Finding{Category: CatTypeMismatch, File: s.File, Line: f.Line, Type: s.Name, Field: f.JSONName,
				Message: fmt.Sprintf("schema %s vs Go %s (%s)", describe(ps), gk, exprString(f.Expr))})
		}
	}
	if complete {
		for _, r := range sc.Required {
			if !have[r] {
				out = append(out, Finding{Category: CatMissingMandatory, File: s.File, Line: s.Line, Type: s.Name, Field: r,
					Message: fmt.Sprintf("mandatory property %q of %s has no JSON field", r, s.Ann.Ref)})
			}
		}
	}
	return out
}

// flattenFields returns the struct's JSON fields including those of
// resolvable embedded structs; complete is false when an embedded type could
// not be resolved (missing-mandatory is then skipped).
func flattenFields(s *Struct, seen map[*Struct]bool) (fields []Field, complete bool) {
	complete = true
	if seen[s] {
		return nil, true
	}
	seen[s] = true
	fields = append(fields, s.Fields...)
	for _, e := range s.Embedded {
		for {
			if st, ok := e.(*ast.StarExpr); ok {
				e = st.X
				continue
			}
			break
		}
		id, ok := e.(*ast.Ident)
		var emb *Struct
		if ok {
			for _, c := range s.pkg.Structs {
				if c.Name == id.Name {
					emb = c
				}
			}
		}
		if emb == nil {
			complete = false
			continue
		}
		f, c := flattenFields(emb, seen)
		fields = append(fields, f...)
		complete = complete && c
	}
	return fields, complete
}

// Go kinds produced by goKind.
const (
	gString  = "string"
	gInt     = "int"
	gFloat   = "float"
	gBool    = "bool"
	gSlice   = "slice"
	gBytes   = "[]byte"
	gStruct  = "struct"
	gMap     = "map"
	gAny     = "any"
	gUnknown = "unknown"
)

func goKind(e ast.Expr, p *Package, depth int) string {
	if depth > 8 {
		return gUnknown
	}
	switch t := e.(type) {
	case *ast.StarExpr:
		return goKind(t.X, p, depth+1)
	case *ast.Ident:
		switch t.Name {
		case "string":
			return gString
		case "bool":
			return gBool
		case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "byte", "rune":
			return gInt
		case "float32", "float64":
			return gFloat
		case "any":
			return gAny
		}
		if te, ok := p.Types[t.Name]; ok {
			return goKind(te, p, depth+1)
		}
		return gUnknown
	case *ast.SelectorExpr:
		if x, ok := t.X.(*ast.Ident); ok {
			switch x.Name + "." + t.Sel.Name {
			case "json.RawMessage":
				return gAny
			case "time.Time":
				return gString
			case "time.Duration":
				return gInt
			}
		}
		return gUnknown
	case *ast.ArrayType:
		if t.Len == nil {
			if id, ok := t.Elt.(*ast.Ident); ok && (id.Name == "byte" || id.Name == "uint8") {
				return gBytes
			}
		}
		return gSlice
	case *ast.MapType:
		return gMap
	case *ast.StructType:
		return gStruct
	case *ast.InterfaceType:
		return gAny
	}
	return gUnknown
}

func compatible(s *oapi.Schema, gk string) bool {
	if gk == gAny || gk == gUnknown {
		return true
	}
	if s.Kind == oapi.KindAny && len(s.Alts) == 0 {
		return true
	}
	return s.Accepts(func(k oapi.Kind) bool {
		if k == oapi.KindAny {
			return true
		}
		switch gk {
		case gString:
			return k == oapi.KindString
		case gInt:
			return k == oapi.KindInteger || k == oapi.KindNumber
		case gFloat:
			return k == oapi.KindNumber
		case gBool:
			return k == oapi.KindBoolean
		case gSlice:
			return k == oapi.KindArray
		case gBytes:
			return k == oapi.KindString || k == oapi.KindArray
		case gStruct, gMap:
			return k == oapi.KindObject
		}
		return true
	})
}

func describe(s *oapi.Schema) string {
	if len(s.Alts) > 0 && s.Kind == oapi.KindAny {
		var parts []string
		for _, a := range s.Alts {
			parts = append(parts, describe(a))
		}
		return "union(" + strings.Join(parts, "|") + ")"
	}
	return string(s.Kind)
}

func exprString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + exprString(t.Elt)
	case *ast.MapType:
		return "map[" + exprString(t.Key) + "]" + exprString(t.Value)
	case *ast.StructType:
		return "struct{...}"
	case *ast.InterfaceType:
		return "interface{}"
	}
	return "?"
}

// DefaultScope is the default -scope regexp for the unannotated listing.
const DefaultScope = `/internal/(sbi|server)(/|$)`

// FindUnannotated lists JSON-tagged structs without an oapi: line whose
// directory (slash form, with a leading "/") matches scope.
func FindUnannotated(pkgs []*Package, scope *regexp.Regexp) []Unannotated {
	var out []Unannotated
	for _, p := range pkgs {
		d := "/" + strings.TrimPrefix(strings.ReplaceAll(p.Dir, `\`, "/"), "./")
		if !scope.MatchString(d) {
			continue
		}
		for _, s := range p.Structs {
			if s.HasJSON && s.Ann == nil {
				out = append(out, Unannotated{File: s.File, Line: s.Line, Type: s.Name})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}
