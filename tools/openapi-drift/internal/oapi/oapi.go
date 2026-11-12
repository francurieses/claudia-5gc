// Package oapi loads 3GPP OpenAPI YAML files and resolves component schemas
// into a small, flattened view that is sufficient for drift checking: kind,
// required property names, property names and element/union structure.
//
// It understands local ($ref: '#/components/schemas/X') and cross-file
// ($ref: 'TS29571_CommonData.yaml#/components/schemas/Supi', relative paths
// allowed) references, allOf (properties and required are merged),
// oneOf/anyOf (treated as a union: required members of branches are NOT
// mandatory, branch properties are merged as optional), nullable,
// additionalProperties and array items. Files are cached and $ref chains are
// depth-guarded, so reference cycles terminate. Property values and array
// items are resolved lazily so that recursive schemas never loop.
//
// The package is a reusable schema loader: later tooling (release diff,
// used-schema analysis) is expected to build on [Loader].
package oapi

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kind is the coarse JSON type of a schema.
type Kind string

// Schema kinds. KindAny means "unconstrained or not classifiable".
const (
	KindString  Kind = "string"
	KindInteger Kind = "integer"
	KindNumber  Kind = "number"
	KindBoolean Kind = "boolean"
	KindArray   Kind = "array"
	KindObject  Kind = "object"
	KindAny     Kind = "any"
)

// maxRefDepth bounds $ref/allOf/oneOf nesting while flattening one schema.
const maxRefDepth = 24

// Node is an unresolved schema fragment together with the file it lives in
// (needed to resolve local $refs).
type Node struct {
	File string
	Raw  any
}

// Schema is a flattened schema.
type Schema struct {
	Kind     Kind
	Nullable bool
	// Required lists mandatory property names (allOf merged, unions excluded).
	Required []string
	// Props maps property name to its unresolved schema.
	Props map[string]Node
	// Items is the array element schema, if any.
	Items *Node
	// HasAdditional is true when additionalProperties is present and not false.
	HasAdditional bool
	// Alts holds union branches (oneOf/anyOf). A value matches the schema if
	// it matches Kind or any branch.
	Alts []*Schema
	// Truncated is set when flattening stopped on a cycle or depth limit.
	Truncated bool
}

// Loader loads and caches YAML files from one spec directory.
type Loader struct {
	Dir   string
	files map[string]any
}

// NewLoader returns a Loader rooted at dir.
func NewLoader(dir string) *Loader {
	return &Loader{Dir: dir, files: map[string]any{}}
}

// HasYAML reports whether dir exists and contains at least one *.yaml file.
func HasYAML(dir string) bool {
	m, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	return err == nil && len(m) > 0
}

// File returns the decoded document for a file name relative to the spec dir.
func (l *Loader) File(name string) (any, error) {
	name = filepath.Clean(name)
	if d, ok := l.files[name]; ok {
		return d, nil
	}
	b, err := os.ReadFile(filepath.Join(l.Dir, name))
	if err != nil {
		return nil, fmt.Errorf("oapi: read %s: %w", name, err)
	}
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("oapi: parse %s: %w", name, err)
	}
	l.files[name] = doc
	return doc, nil
}

// SplitRef splits "File.yaml#/a/b" into file and JSON-pointer segments. An
// empty file means "same file".
func SplitRef(ref string) (file string, ptr []string, err error) {
	file, frag, found := strings.Cut(ref, "#")
	if !found {
		return file, nil, nil
	}
	if frag == "" {
		return file, nil, nil
	}
	if !strings.HasPrefix(frag, "/") {
		return "", nil, fmt.Errorf("oapi: bad JSON pointer %q", frag)
	}
	for _, s := range strings.Split(frag[1:], "/") {
		s = strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
		ptr = append(ptr, s)
	}
	return file, ptr, nil
}

// Lookup resolves a reference "File.yaml#/ptr" (file relative to the spec
// dir; cur is used when the reference has no file part) to a Node.
func (l *Loader) Lookup(cur, ref string) (Node, error) {
	file, ptr, err := SplitRef(ref)
	if err != nil {
		return Node{}, err
	}
	if file == "" {
		file = cur
	} else if cur != "" {
		file = filepath.Join(filepath.Dir(cur), file)
	}
	file = filepath.Clean(file)
	doc, err := l.File(file)
	if err != nil {
		return Node{}, err
	}
	n := doc
	for _, seg := range ptr {
		switch m := n.(type) {
		case map[string]any:
			v, ok := m[seg]
			if !ok {
				return Node{}, fmt.Errorf("oapi: %s: pointer segment %q not found", file, seg)
			}
			n = v
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(m) {
				return Node{}, fmt.Errorf("oapi: %s: bad array index %q", file, seg)
			}
			n = m[i]
		default:
			return Node{}, fmt.Errorf("oapi: %s: pointer segment %q not found", file, seg)
		}
	}
	return Node{File: file, Raw: n}, nil
}

// Resolve flattens the schema referenced by ref ("File.yaml#/components/...").
func (l *Loader) Resolve(ref string) (*Schema, error) {
	n, err := l.Lookup("", ref)
	if err != nil {
		return nil, err
	}
	return l.Flatten(n)
}

// Flatten flattens a node: $ref is followed, allOf merged, oneOf/anyOf turned
// into a union. Property and item schemas stay unresolved (lazy).
func (l *Loader) Flatten(n Node) (*Schema, error) {
	return l.flatten(n, 0)
}

func (l *Loader) flatten(n Node, depth int) (*Schema, error) {
	if depth > maxRefDepth {
		return &Schema{Kind: KindAny, Truncated: true}, nil
	}
	m, ok := n.Raw.(map[string]any)
	if !ok {
		return &Schema{Kind: KindAny}, nil
	}
	if r, ok := m["$ref"].(string); ok {
		t, err := l.Lookup(n.File, r)
		if err != nil {
			return nil, err
		}
		return l.flatten(t, depth+1)
	}
	s := &Schema{Kind: KindAny}
	if t, ok := m["type"].(string); ok {
		s.Kind = Kind(t)
		switch s.Kind {
		case KindString, KindInteger, KindNumber, KindBoolean, KindArray, KindObject:
		default:
			s.Kind = KindAny
		}
	}
	if b, ok := m["nullable"].(bool); ok {
		s.Nullable = b
	}
	if props, ok := m["properties"].(map[string]any); ok {
		s.Props = map[string]Node{}
		for k, v := range props {
			s.Props[k] = Node{File: n.File, Raw: v}
		}
		if s.Kind == KindAny {
			s.Kind = KindObject
		}
	}
	if req, ok := m["required"].([]any); ok {
		for _, r := range req {
			if rs, ok := r.(string); ok {
				s.Required = append(s.Required, rs)
			}
		}
	}
	switch ap := m["additionalProperties"].(type) {
	case nil:
	case bool:
		s.HasAdditional = ap
	default:
		s.HasAdditional = true
	}
	if s.HasAdditional && s.Kind == KindAny {
		s.Kind = KindObject
	}
	if it, ok := m["items"]; ok {
		s.Items = &Node{File: n.File, Raw: it}
		if s.Kind == KindAny {
			s.Kind = KindArray
		}
	}
	if all, ok := m["allOf"].([]any); ok {
		for _, part := range all {
			ps, err := l.flatten(Node{File: n.File, Raw: part}, depth+1)
			if err != nil {
				return nil, err
			}
			s.merge(ps, true)
		}
	}
	for _, key := range []string{"oneOf", "anyOf"} {
		alts, ok := m[key].([]any)
		if !ok {
			continue
		}
		for _, a := range alts {
			as, err := l.flatten(Node{File: n.File, Raw: a}, depth+1)
			if err != nil {
				return nil, err
			}
			s.Alts = append(s.Alts, as)
			s.merge(as, false)
		}
	}
	sort.Strings(s.Required)
	s.Required = dedupe(s.Required)
	return s, nil
}

// merge folds o into s. Required is only merged when mandatory is true.
func (s *Schema) merge(o *Schema, mandatory bool) {
	if mandatory {
		s.Required = append(s.Required, o.Required...)
		if s.Kind == KindAny {
			s.Kind = o.Kind
		}
		s.Alts = append(s.Alts, o.Alts...)
		if s.Items == nil {
			s.Items = o.Items
		}
	}
	if len(o.Props) > 0 && s.Props == nil {
		s.Props = map[string]Node{}
	}
	for k, v := range o.Props {
		if _, dup := s.Props[k]; !dup {
			s.Props[k] = v
		}
	}
	s.HasAdditional = s.HasAdditional || o.HasAdditional
	s.Nullable = s.Nullable || o.Nullable
	s.Truncated = s.Truncated || o.Truncated
}

// Accepts reports whether pred is true for the schema's kind or for any
// union branch (recursively).
func (s *Schema) Accepts(pred func(Kind) bool) bool {
	// A pure union (no own type) is judged by its branches only.
	if (s.Kind != KindAny || len(s.Alts) == 0) && pred(s.Kind) {
		return true
	}
	for _, a := range s.Alts {
		if a.Accepts(pred) {
			return true
		}
	}
	return false
}

// PropNames returns the sorted property names.
func (s *Schema) PropNames() []string {
	out := make([]string, 0, len(s.Props))
	for k := range s.Props {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
