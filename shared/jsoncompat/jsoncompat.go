// Package jsoncompat provides unknown-key-preserving JSON helpers so that a
// record written by a newer release survives a read-modify-write cycle in an
// older one (rolling upgrade / downgrade) and so that SBI objects carrying
// attributes this implementation does not model are not silently truncated.
//
// Pattern: a struct keeps unknown top-level keys in a field
//
//	Extra map[string]json.RawMessage `json:"-"`
//
// and implements UnmarshalJSON / MarshalJSON on top of Unmarshal / Marshal
// using a method-less alias type (to avoid recursion):
//
//	type fooAlias Foo
//	func (f *Foo) UnmarshalJSON(b []byte) error { return jsoncompat.Unmarshal(b, (*fooAlias)(f), &f.Extra) }
//	func (f Foo) MarshalJSON() ([]byte, error)  { return jsoncompat.Marshal(fooAlias(f), f.Extra) }
//
// Only top-level keys of the struct are preserved; nested structs handle
// their own unknown keys if they use the same pattern.
//
// Persisted records also carry a schema_version (SchemaVersionKey) so a
// rolling upgrade / downgrade can tell which release wrote them: use
// NextVersion when marshalling (never lowers a newer stored version) and
// StampVersion / ReadVersion for stores that keep raw JSON objects.
//
// Ref: TS 29.500 §6.6.2 (unknown attributes shall be ignored - never
// required to be dropped); dev/rel19/PLAN.md steps 2.4 and 7.2.
package jsoncompat

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// knownKeys caches, per struct type, the lower-cased set of JSON keys the
// type declares (encoding/json matches keys case-insensitively on decode).
var knownKeys sync.Map // reflect.Type -> map[string]struct{}

func keysOf(t reflect.Type) map[string]struct{} {
	if v, ok := knownKeys.Load(t); ok {
		return v.(map[string]struct{})
	}
	m := map[string]struct{}{}
	collect(t, m)
	v, _ := knownKeys.LoadOrStore(t, m)
	return v.(map[string]struct{})
}

func collect(t reflect.Type, m map[string]struct{}) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := range t.NumField() {
		f := t.Field(i)
		tag, hasTag := f.Tag.Lookup("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" && !strings.Contains(tag, ",") {
			continue
		}
		if f.Anonymous && name == "" {
			collect(f.Type, m) // embedded struct: fields are promoted
			continue
		}
		if !f.IsExported() {
			continue
		}
		if !hasTag || name == "" {
			name = f.Name
		}
		m[strings.ToLower(name)] = struct{}{}
	}
}

// Unmarshal decodes the JSON object data into v (a non-nil pointer to a
// struct) and stores in *extra every top-level key that is not a JSON field
// of v. *extra is reset first and is left nil when there are no unknown keys.
// A JSON null leaves both untouched beyond the reset.
func Unmarshal(data []byte, v any, extra *map[string]json.RawMessage) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("jsoncompat: unmarshal: target must be a non-nil pointer to struct, got %T", v)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("jsoncompat: unmarshal: %w", err)
	}
	*extra = nil
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return fmt.Errorf("jsoncompat: unmarshal keys: %w", err)
	}
	known := keysOf(rv.Elem().Type())
	for k, raw := range all {
		if _, ok := known[strings.ToLower(k)]; ok {
			continue
		}
		if *extra == nil {
			*extra = map[string]json.RawMessage{}
		}
		(*extra)[k] = append(json.RawMessage(nil), raw...)
	}
	return nil
}

// Marshal encodes v (a struct or pointer to struct) and appends the extra
// keys after the known ones, sorted by key for deterministic output. An
// extra key that clashes (case-insensitively) with a known field is dropped:
// known fields win. With an empty extra the output is exactly
// json.Marshal(v), byte for byte.
func Marshal(v any, extra map[string]json.RawMessage) ([]byte, error) {
	base, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jsoncompat: marshal: %w", err)
	}
	if len(extra) == 0 {
		return base, nil
	}
	if len(base) < 2 || base[0] != '{' || base[len(base)-1] != '}' {
		return nil, fmt.Errorf("jsoncompat: marshal: %T does not encode to a JSON object", v)
	}
	known := keysOf(reflect.TypeOf(v))
	keys := make([]string, 0, len(extra))
	for k := range extra {
		if _, ok := known[strings.ToLower(k)]; !ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return base, nil
	}
	sort.Strings(keys)
	out := append([]byte(nil), base[:len(base)-1]...)
	needComma := len(base) > 2
	for _, k := range keys {
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("jsoncompat: marshal key %q: %w", k, err)
		}
		if needComma {
			out = append(out, ',')
		}
		needComma = true
		out = append(out, kb...)
		out = append(out, ':')
		raw := extra[k]
		if len(raw) == 0 {
			raw = json.RawMessage("null")
		}
		out = append(out, raw...)
	}
	out = append(out, '}')
	if !json.Valid(out) {
		return nil, fmt.Errorf("jsoncompat: marshal: extra values produced invalid JSON")
	}
	return out, nil
}

// SchemaVersionKey is the JSON key under which persisted records carry their
// schema version. A missing key means version 0 (a record written before the
// field existed).
const SchemaVersionKey = "schema_version"

// NextVersion returns the schema version to write: the current build's
// version, unless the record was loaded with a newer one, which is kept so a
// downgraded build never relabels data it does not fully understand.
func NextVersion(stored, current int) int {
	if stored > current {
		return stored
	}
	return current
}

// ReadVersion returns the schema_version of the JSON object data, 0 when the
// key is absent or not a non-negative integer.
func ReadVersion(data []byte) int {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil {
		return 0
	}
	var v int
	if json.Unmarshal(m[SchemaVersionKey], &v) != nil || v < 0 {
		return 0
	}
	return v
}

// StampVersion returns the JSON object data with schema_version set to
// NextVersion(existing, current); all other keys are preserved verbatim.
func StampVersion(data []byte, current int) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("jsoncompat: stamp version: %w", err)
	}
	if m == nil {
		return nil, fmt.Errorf("jsoncompat: stamp version: not a JSON object")
	}
	v, err := json.Marshal(NextVersion(ReadVersion(data), current))
	if err != nil {
		return nil, fmt.Errorf("jsoncompat: stamp version: %w", err)
	}
	m[SchemaVersionKey] = v
	out, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("jsoncompat: stamp version: %w", err)
	}
	return out, nil
}
