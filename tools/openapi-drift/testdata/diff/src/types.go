// Package sbi is a test fixture for openapi-drift -diff; it is never compiled.
package sbi

// Thing is annotated.
// oapi: TSD_Sample.yaml#/components/schemas/Thing
type Thing struct {
	ID string `json:"id"`
}
