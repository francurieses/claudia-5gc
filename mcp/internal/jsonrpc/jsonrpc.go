// Package jsonrpc implements the minimal JSON-RPC 2.0 framing used by both MCP
// transports (stdio and HTTP SSE). It is transport-agnostic: it only parses and
// serialises frames. The dispatcher consumes Request and produces Response.
//
// Reference: https://www.jsonrpc.org/specification
package jsonrpc

import (
	"encoding/json"
	"fmt"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
)

// Version is the only JSON-RPC version this server speaks.
const Version = "2.0"

// Request is an incoming JSON-RPC request or notification. A request with no
// ID (IsNotification) expects no response.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	// ID is the raw request id (string, number, or null). It is echoed verbatim
	// in the response. Absent ID ⇒ notification.
	ID json.RawMessage `json:"id,omitempty"`
}

// IsNotification reports whether the request omitted its id (no response due).
func (r *Request) IsNotification() bool { return len(r.ID) == 0 }

// Response is an outgoing JSON-RPC response. Exactly one of Result or Error is
// set. ID mirrors the request id (null for parse-level failures).
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcperr.Error   `json:"error,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
}

// nullID is the JSON literal used when a request id cannot be determined.
var nullID = json.RawMessage("null")

// NewResult builds a success response, marshalling result into Result.
func NewResult(id json.RawMessage, result any) Response {
	raw, err := json.Marshal(result)
	if err != nil {
		return NewError(id, mcperr.Newf(mcperr.CodeInternal, nil,
			"marshal result: %v", err))
	}
	if len(id) == 0 {
		id = nullID
	}
	return Response{JSONRPC: Version, Result: raw, ID: id}
}

// NewError builds an error response. A nil error is coerced to an internal error.
func NewError(id json.RawMessage, e *mcperr.Error) Response {
	if e == nil {
		e = mcperr.New(mcperr.CodeInternal, "unknown error", nil)
	}
	if len(id) == 0 {
		id = nullID
	}
	return Response{JSONRPC: Version, Error: e, ID: id}
}

// ParseRequest decodes a single JSON-RPC frame. A decode failure is reported as
// a parse error so the caller can still emit a well-formed error response.
func ParseRequest(frame []byte) (*Request, *mcperr.Error) {
	var req Request
	if err := json.Unmarshal(frame, &req); err != nil {
		return nil, mcperr.Newf(mcperr.CodeParse, nil, "parse request: %v", err)
	}
	if req.JSONRPC != Version {
		return nil, mcperr.Newf(mcperr.CodeInvalidRequest,
			map[string]any{"jsonrpc": req.JSONRPC},
			"unsupported jsonrpc version %q (want %q)", req.JSONRPC, Version)
	}
	if req.Method == "" {
		return nil, mcperr.New(mcperr.CodeInvalidRequest, "missing method", nil)
	}
	return &req, nil
}

// WriteFrame serialises a response to a single newline-free JSON document.
func WriteFrame(resp Response) ([]byte, error) {
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("jsonrpc: marshal response: %w", err)
	}
	return b, nil
}
