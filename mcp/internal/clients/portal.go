package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
)

// redactedKeys are subscriber secrets. Portal responses are scrubbed of them in
// this client, so no tool can return them by mistake (TS 33.501 §6.1.1: K and
// OPc are long-term credentials). SQN is state from the same secret set.
var redactedKeys = map[string]bool{"k": true, "opc": true, "op": true, "sqn": true}

// Portal wraps the mgmt-portal HTTP API (plain HTTP, default :8080). It is the
// single entry point for the portal-backed status, control and PCAP tools.
type Portal struct {
	baseURL string
	http    *http.Client
}

// NewPortal builds a mgmt-portal client. baseURL is e.g. http://mgmt-portal:8080.
func NewPortal(baseURL string, httpClient *http.Client) *Portal {
	return &Portal{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// Get performs GET /api/v1/<path> and returns the JSON body with secrets redacted.
// A non-2xx status is an error that carries the portal's message.
func (p *Portal) Get(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	u := p.baseURL + "/api/v1" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	body, status, err := p.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, &PortalStatusError{Method: http.MethodGet, Path: path, Status: status, Body: truncate(body)}
	}
	return Redact(body)
}

// GetUnredacted performs GET /api/v1/<path> and returns the status and the raw body
// WITHOUT scrubbing secrets. It exists for one purpose: a whole-record portal PUT
// requires k and opc, so a tool that edits other fields must carry them through.
// The caller must never return, log or put the body in an error; it must pass it
// through Redact before showing anything. Non-2xx codes are returned, not errors.
func (p *Portal) GetUnredacted(ctx context.Context, path string) ([]byte, int, error) {
	return p.do(ctx, http.MethodGet, p.baseURL+"/api/v1"+path, nil)
}

// PortalStatusError is a non-2xx portal reply. Its text is the same as before the
// type existed; callers use errors.As to read the status.
type PortalStatusError struct {
	Method, Path string
	Status       int
	Body         string
}

// Error implements error.
func (e *PortalStatusError) Error() string {
	return fmt.Sprintf("portal %s %s: status %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// StoreState is what the portal reports about its Postgres store.
type StoreState string

// Store states returned by StoreStatus.
const (
	// StoreUp: the portal answered store:"up".
	StoreUp StoreState = "up"
	// StoreDown: the portal answered store:"down".
	StoreDown StoreState = "down"
	// StoreUnknown: the portal did not say (older portal with an empty health
	// body, no store field, unreachable portal or an unreadable reply).
	StoreUnknown StoreState = "unknown"
)

// StoreUnavailableMessage is the exact message of the tool error returned when the
// portal's store cannot serve a request.
const StoreUnavailableMessage = "PORTAL_STORE_UNAVAILABLE"

// StoreStatus reads GET /api/v1/health and reports the portal's store state. It
// never fails: an empty body, a missing "store" field, a transport error or a
// non-JSON reply all yield StoreUnknown, and the next real call reports its own error.
func (p *Portal) StoreStatus(ctx context.Context) StoreState {
	_, state := p.Health(ctx)
	return state
}

// Health reads GET /api/v1/health. reachable is true when the portal answered at
// all; state is the store state as StoreStatus defines it.
func (p *Portal) Health(ctx context.Context) (reachable bool, state StoreState) {
	body, status, err := p.do(ctx, http.MethodGet, p.baseURL+"/api/v1/health", nil)
	if err != nil {
		return false, StoreUnknown
	}
	if status < 200 || status > 299 || len(bytes.TrimSpace(body)) == 0 {
		return true, StoreUnknown
	}
	var h struct {
		Store string `json:"store"`
	}
	if json.Unmarshal(body, &h) != nil {
		return true, StoreUnknown
	}
	switch StoreState(strings.ToLower(h.Store)) {
	case StoreUp:
		return true, StoreUp
	case StoreDown:
		return true, StoreDown
	}
	return true, StoreUnknown
}

// StoreUnavailableError is the tool error for a portal whose store is down.
func StoreUnavailableError() *mcperr.Error {
	return mcperr.New(mcperr.CodeToolError, StoreUnavailableMessage, map[string]any{
		"reason": "the portal's Postgres store is down",
		"hint":   "docker restart mgmt-portal",
	})
}

// RequireStore returns StoreUnavailableError when the portal reports its store down,
// and nil otherwise. An unknown state passes: the caller then maps a 503 from the
// store route with StoreErr.
func (p *Portal) RequireStore(ctx context.Context) *mcperr.Error {
	if p.StoreStatus(ctx) == StoreDown {
		return StoreUnavailableError()
	}
	return nil
}

// StoreErr maps a portal Get error from a store-backed route: a 503 becomes
// StoreUnavailableError, anything else is returned unchanged (nil stays nil).
func StoreErr(err error) error {
	var se *PortalStatusError
	if errors.As(err, &se) && se.Status == http.StatusServiceUnavailable {
		return StoreUnavailableError()
	}
	return err
}

// Post performs POST /api/v1/<path> with an optional JSON body. It returns the
// status code and the (redacted) response body. Non-2xx responses are returned,
// not converted to errors, so the caller can report 409 and similar states.
func (p *Portal) Post(ctx context.Context, path string, body any) (json.RawMessage, int, error) {
	return p.Send(ctx, http.MethodPost, path, body)
}

// Send performs any mutating request against /api/v1/<path>. It returns the status
// code and the redacted response body; non-2xx codes are returned to the caller.
func (p *Portal) Send(ctx context.Context, method, path string, body any) (json.RawMessage, int, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("portal %s %s: encode body: %w", method, path, err)
		}
		payload = b
	}
	resp, status, err := p.do(ctx, method, p.baseURL+"/api/v1"+path, payload)
	if err != nil {
		return nil, 0, err
	}
	out, rerr := Redact(resp)
	if rerr != nil {
		// A non-JSON reply (usually a plain-text error) cannot carry the structured
		// secret fields Redact removes. Return it as a truncated JSON string.
		text, _ := json.Marshal(truncate(resp))
		return text, status, nil
	}
	return out, status, nil
}

func (p *Portal) do(ctx context.Context, method, u string, body []byte) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, 0, fmt.Errorf("portal: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("portal: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("portal: read body: %w", err)
	}
	return raw, resp.StatusCode, nil
}

// Redact removes subscriber secrets from any JSON document: the value of every
// object key in redactedKeys is replaced with "<redacted>". Non-JSON input is
// returned as an error so callers never pass unscrubbed bytes through.
func Redact(raw []byte) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage("null"), nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("portal: response is not JSON: %w", err)
	}
	out, err := json.Marshal(redactValue(v))
	if err != nil {
		return nil, fmt.Errorf("portal: re-encode: %w", err)
	}
	return out, nil
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if redactedKeys[strings.ToLower(k)] {
				t[k] = "<redacted>"
				continue
			}
			t[k] = redactValue(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactValue(t[i])
		}
		return t
	default:
		return v
	}
}

func truncate(b []byte) string {
	const max = 300
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}

// UELocation reads GET /api/v1/location/ue/{supi}, which makes the portal ask the
// LMF (and so the AMF, through NGAP Location Reporting) for the UE position.
// Ref: TS 23.273 §6.10.1, TS 38.413 §8.12.
func (p *Portal) UELocation(ctx context.Context, supi string) (json.RawMessage, error) {
	return p.Get(ctx, "/location/ue/"+url.PathEscape(supi), nil)
}

// PWSResend posts /api/v1/pws/resend, which re-drives a stored warning to the RAN.
// Ref: TS 38.413 §8.9.1.
func (p *Portal) PWSResend(ctx context.Context, messageIdentifier, serialNumber int) (json.RawMessage, int, error) {
	return p.Post(ctx, "/pws/resend", map[string]int{
		"messageIdentifier": messageIdentifier, "serialNumber": serialNumber})
}
