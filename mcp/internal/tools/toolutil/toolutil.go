// Package toolutil holds the input validators and identifiers shared by every
// MCP tool group, so the same SUPI, PDU session ID, DNN and 5QI rules apply
// everywhere. It also provides the wrapper that keeps a renamed tool working for
// one release.
//
// 3GPP references: SUPI format TS 23.003 §2.2 / §2.2B; DNN TS 23.003 §9.1;
// PDU session ID TS 24.007 §11.2.3.1a (1-15); 5QI TS 23.501 Table 5.7.4-1.
package toolutil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"regexp"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

var (
	supiRe = regexp.MustCompile(`^imsi-[0-9]{5,15}$`)
	dnnRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$`)
)

// ValidSUPI accepts an IMSI-based SUPI such as imsi-001010000000001.
func ValidSUPI(supi string) *mcperr.Error {
	if !supiRe.MatchString(supi) {
		return mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"supi": supi},
			"supi must be imsi-<5-15 digits>, got %q", supi)
	}
	return nil
}

// ValidPSI accepts a PDU session ID in the TS 24.007 range 1-15.
func ValidPSI(psi int) *mcperr.Error {
	if psi < 1 || psi > 15 {
		return mcperr.Newf(mcperr.CodeInvalidParams, nil,
			"pdu_session_id must be 1-15 (TS 24.007 §11.2.3.1a), got %d", psi)
	}
	return nil
}

// ValidDNN accepts a DNN label string (TS 23.003 §9.1). An empty DNN is the
// caller's decision: optional scopes skip the check when the field is absent.
func ValidDNN(dnn string) *mcperr.Error {
	if !dnnRe.MatchString(dnn) {
		return mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"dnn": dnn},
			"dnn %q is not a valid DNN label (TS 23.003 §9.1)", dnn)
	}
	return nil
}

// ValidFiveQI accepts a standardised 5QI (TS 23.501 Table 5.7.4-1) or an
// operator-defined value in 128-254, the same rule the SMF applies.
func ValidFiveQI(v int) bool {
	switch v {
	case 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		65, 66, 67, 69, 70, 71, 72, 73, 74, 75, 76,
		79, 80, 82, 83, 84, 85, 86, 87, 88, 89, 90:
		return true
	}
	return v >= 128 && v <= 254
}

// HashSUPI returns a short, non-reversible identifier for logs, so SUPIs never
// appear in slog output.
func HashSUPI(supi string) string {
	h := sha256.Sum256([]byte(supi))
	return hex.EncodeToString(h[:4])
}

// deprecated forwards a call from a renamed tool to its replacement.
type deprecated struct {
	oldName   string
	oldSchema json.RawMessage
	target    registry.Tool
	mapArgs   func(json.RawMessage) (json.RawMessage, error)
}

// Deprecated returns a tool named oldName that accepts oldSchema and runs target
// after mapArgs has rewritten the arguments. It keeps old callers working for one
// release. The description says what replaces it and the call is logged as
// deprecated. Risk and dry-run behaviour come from target, so the guard treats
// the alias exactly like the tool it forwards to.
func Deprecated(oldName string, oldSchema json.RawMessage, target registry.Tool,
	mapArgs func(json.RawMessage) (json.RawMessage, error)) registry.Tool {
	return deprecated{oldName: oldName, oldSchema: oldSchema, target: target, mapArgs: mapArgs}
}

func (d deprecated) Name() string { return d.oldName }

// AliasOf implements registry.Alias: the name of the tool this one forwards to.
func (d deprecated) AliasOf() string { return d.target.Name() }
func (d deprecated) Description() string {
	return "DEPRECATED: use " + d.target.Name() + " (removed in a later release). " + d.target.Description()
}
func (d deprecated) InputSchema() json.RawMessage  { return d.oldSchema }
func (d deprecated) OutputSchema() json.RawMessage { return d.target.OutputSchema() }
func (d deprecated) Risk() registry.Risk           { return d.target.Risk() }

func (d deprecated) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	args, err := d.rewrite(ctx, in)
	if err != nil {
		return nil, err
	}
	return d.target.Invoke(ctx, args)
}

// Plan lets the guard's dry-run describe the replacement's effect.
func (d deprecated) Plan(ctx context.Context, in json.RawMessage) (any, error) {
	p, ok := d.target.(registry.Planner)
	if !ok {
		return nil, nil
	}
	args, err := d.rewrite(ctx, in)
	if err != nil {
		return nil, err
	}
	return p.Plan(ctx, args)
}

func (d deprecated) rewrite(ctx context.Context, in json.RawMessage) (json.RawMessage, error) {
	slog.WarnContext(ctx, "deprecated tool called", "tool_name", d.oldName, "replacement", d.target.Name())
	args, err := d.mapArgs(in)
	if err != nil {
		return nil, err
	}
	return args, nil
}
