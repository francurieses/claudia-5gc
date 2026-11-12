// Package sbi is a test fixture for openapi-drift; it is never compiled.
package sbi

import "encoding/json"

// BaseEmb is flattened into the structs that embed it.
type BaseEmb struct {
	ID string `json:"id"`
}

// Dnn is a named string type.
type Dnn string

// GoodItem matches the schema.
// oapi: TSA_Sample.yaml#/components/schemas/Item
type GoodItem struct {
	BaseEmb
	Name   string            `json:"name"`
	Count  *int64            `json:"count,omitempty"`
	Ratio  float64           `json:"ratio,omitempty"`
	OK     bool              `json:"ok,omitempty"`
	Tags   []string          `json:"tags,omitempty"`
	Attrs  map[string]string `json:"attrs,omitempty"`
	Supi   Dnn               `json:"supi,omitempty"`
	Kind   string            `json:"kind,omitempty"`
	Nested *BaseEmb          `json:"nested,omitempty"`
	Loop   *GoodItem         `json:"loop,omitempty"`
	Choice json.RawMessage   `json:"choice,omitempty"`
	secret string
	Skip   string `json:"-"`
}

// BadItem drifts in every way.
// oapi: TSA_Sample.yaml#/components/schemas/Item
type BadItem struct {
	ID     string `json:"id"`
	Count  string `json:"count"`
	Kind   int    `json:"kind"`
	Bogus  string `json:"bogus"`
	Untag  string
	Ratio  string  `json:"ratio"`
	Tags   string  `json:"tags"`
	Nested []int   `json:"nested"`
	Choice float64 `json:"choice"`
}

// ForeignEmbed embeds a type from another package.
// oapi: TSA_Sample.yaml#/components/schemas/Item
type ForeignEmbed struct {
	other.Thing
	Name string `json:"name"`
}

// UnionObj matches a oneOf: nothing is mandatory.
// oapi: TSA_Sample.yaml#/components/schemas/Choice
type UnionObj struct {
	Y int `json:"y"`
}

// Malformed has a bad annotation.
// oapi: nonsense
type Malformed struct {
	A string `json:"a"`
}

// NoSchema points at a schema that does not exist.
// oapi: TSA_Sample.yaml#/components/schemas/Nope
type NoSchema struct {
	A string `json:"a"`
}

// NoFile points at a missing file.
// oapi: TSZ_Gone.yaml#/components/schemas/Nope
type NoFile struct {
	A string `json:"a"`
}

// OptOut is internal only.
// oapi: none internal-only wire type
type OptOut struct {
	A string `json:"a"`
}

// Plain has JSON tags and no annotation.
type Plain struct {
	A string `json:"a"`
}

// NoTags has no JSON tags and is not listed.
type NoTags struct {
	A string
}

type (
	// Trailing is annotated through the TypeSpec doc inside a group.
	// oapi: TSA_Sample.yaml#/components/schemas/Base
	Trailing struct {
		ID string `json:"id"`
	}
)

// Cyc points at a reference cycle: must not hang.
// oapi: TSA_Sample.yaml#/components/schemas/CycA
type Cyc struct {
	A string `json:"a"`
}
