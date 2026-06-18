// Package mcperr defines the structured error type returned by MCP tools and
// the JSON-RPC dispatcher. Tools never panic on malformed input; they return an
// *Error carrying a machine-readable code plus diagnostic context (e.g. the byte
// offset of a malformed TLV, the offending IE, and the governing 3GPP clause).
package mcperr

import "fmt"

// JSON-RPC 2.0 reserved error codes (https://www.jsonrpc.org/specification §5.1).
const (
	CodeParse          = -32700 // Invalid JSON was received.
	CodeInvalidRequest = -32600 // The JSON sent is not a valid Request object.
	CodeMethodNotFound = -32601 // The method/tool does not exist.
	CodeInvalidParams  = -32602 // Invalid method parameters.
	CodeInternal       = -32603 // Internal JSON-RPC error.

	// CodeToolError is the application-level code used when a registered tool
	// fails on otherwise well-formed input (e.g. a malformed NAS PDU). It sits in
	// the implementation-defined server-error range (-32000..-32099).
	CodeToolError = -32000
)

// Error is a structured MCP error. It satisfies the error interface and
// serialises directly into a JSON-RPC error object.
type Error struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("mcp: [%d] %s", e.Code, e.Message)
}

// New builds an *Error with the given code, message and optional diagnostic data.
func New(code int, message string, data map[string]any) *Error {
	return &Error{Code: code, Message: message, Data: data}
}

// Newf builds an *Error whose message is formatted. The data map carries
// diagnostic context (e.g. {"offset": 12, "ie": "NSSAI", "spec_ref": "..."}).
func Newf(code int, data map[string]any, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...), Data: data}
}

// ToolError wraps an arbitrary error as a tool-level *Error, preserving the
// wrapped error's text. Diagnostic context may be supplied via data.
func ToolError(err error, data map[string]any) *Error {
	return &Error{Code: CodeToolError, Message: err.Error(), Data: data}
}

// From coerces any error into an *Error. If err already is an *Error it is
// returned unchanged; otherwise it is wrapped as an internal error. Returns nil
// for a nil input so callers can use it unconditionally.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		return e
	}
	return &Error{Code: CodeInternal, Message: err.Error()}
}
