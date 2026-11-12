// Package sbi: field-level oapi-ext fixtures for openapi-drift.
package sbi

// ExtItem carries documented project extensions.
// oapi: TSA_Sample.yaml#/components/schemas/Item
type ExtItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// oapi-ext: no spec home on this API, Nfoo-internal correlation hint
	Hint string `json:"hint,omitempty"`
	Tail string `json:"tail,omitempty"` // oapi-ext: trailing-comment form
	// Stray has no oapi-ext and must still be an unknown-attr.
	Stray string `json:"stray,omitempty"`
	// oapi-ext:
	NoReason string `json:"noReason,omitempty"`
}
