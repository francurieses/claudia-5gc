// Package guard decides, before a tool runs, whether the caller may run it.
//
// Three rules apply, in order:
//
//  1. Access mode (server-wide): read-only, operator or lab. It caps the risk
//     level of any tool that is visible or callable at all.
//  2. Role (per caller): viewer, operator or admin. It caps the risk level the
//     caller may invoke. Calls without a role fail closed to viewer.
//  3. Confirmation: a call at Disruptive or Admin risk must carry confirm:true.
//     Without it the guard returns a dry-run that changes nothing, and the
//     confirmed call is rate limited across all disruptive tools.
//
// Every call above read-only is recorded in a bounded in-memory audit ring and
// logged to slog with audit=true, so state changes can be reviewed afterwards.
//
// 3GPP references appear in tool descriptions, not here: the guard enforces
// operational safety and does not implement a procedure.
package guard

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// AccessMode caps the highest risk level the server exposes.
type AccessMode string

const (
	// ModeReadOnly exposes read-only tools only (the code default).
	ModeReadOnly AccessMode = "read-only"
	// ModeOperator exposes read-only, mutating and disruptive tools.
	ModeOperator AccessMode = "operator"
	// ModeLab additionally exposes admin tools (NF process control).
	ModeLab AccessMode = "lab"
)

// ParseAccessMode validates an access_mode setting.
func ParseAccessMode(s string) (AccessMode, error) {
	switch AccessMode(s) {
	case ModeReadOnly, ModeOperator, ModeLab:
		return AccessMode(s), nil
	default:
		return "", fmt.Errorf("access_mode must be read-only|operator|lab, got %q", s)
	}
}

// Ceiling returns the highest registry.Risk this mode exposes.
func (m AccessMode) Ceiling() registry.Risk {
	switch m {
	case ModeLab:
		return registry.Admin
	case ModeOperator:
		return registry.Disruptive
	default:
		return registry.ReadOnly
	}
}

// Role identifies the caller's trust level.
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// ParseRole validates a role name from configuration.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleViewer, RoleOperator, RoleAdmin:
		return Role(s), nil
	default:
		return "", fmt.Errorf("role must be viewer|operator|admin, got %q", s)
	}
}

// Max returns the highest registry.Risk this role may invoke.
func (r Role) Max() registry.Risk {
	switch r {
	case RoleAdmin:
		return registry.Admin
	case RoleOperator:
		return registry.Disruptive
	default:
		return registry.ReadOnly
	}
}

type roleKey struct{}

// WithRole attaches the caller's role to ctx. The transports set it per request.
func WithRole(ctx context.Context, r Role) context.Context {
	return context.WithValue(ctx, roleKey{}, r)
}

// RoleFrom returns the caller's role, failing closed to viewer when unset.
func RoleFrom(ctx context.Context) Role {
	if r, ok := ctx.Value(roleKey{}).(Role); ok && r != "" {
		return r
	}
	return RoleViewer
}

// Options configures a Guard.
type Options struct {
	Mode           AccessMode
	MinInterval    time.Duration // minimum gap between two confirmed disruptive calls
	AuditSize      int           // ring-buffer capacity (default 256)
	MaxResultBytes int           // result cap applied by the dispatcher (default 256 KiB)
}

// Default values for Options fields left at zero.
const (
	DefaultMinInterval    = 2 * time.Second
	DefaultAuditSize      = 256
	DefaultMaxResultBytes = 256 << 10
)

// Verdict is the guard's decision for one call.
type Verdict int

const (
	// Refused: the call must not run. Decision.Err says why.
	Refused Verdict = iota
	// DryRun: the call was not confirmed. Decision.Result describes what it would do.
	DryRun
	// Proceed: the tool may run. The caller must report the outcome with Record.
	Proceed
)

// Decision is the result of Check.
type Decision struct {
	Verdict Verdict
	Result  any
	Err     *mcperr.Error
}

// Guard enforces access mode, roles, confirmation and rate limits.
type Guard struct {
	mode        AccessMode
	minInterval time.Duration
	maxResult   int
	audit       *Audit
	logger      *slog.Logger
	now         func() time.Time

	mu       sync.Mutex
	lastConf time.Time // time of the last confirmed disruptive call
}

// New builds a Guard. Zero-valued Options fields take their defaults.
func New(opts Options, logger *slog.Logger) *Guard {
	if opts.Mode == "" {
		opts.Mode = ModeReadOnly
	}
	if opts.MinInterval <= 0 {
		opts.MinInterval = DefaultMinInterval
	}
	if opts.AuditSize <= 0 {
		opts.AuditSize = DefaultAuditSize
	}
	if opts.MaxResultBytes <= 0 {
		opts.MaxResultBytes = DefaultMaxResultBytes
	}
	return &Guard{
		mode:        opts.Mode,
		minInterval: opts.MinInterval,
		maxResult:   opts.MaxResultBytes,
		audit:       NewAudit(opts.AuditSize),
		logger:      logger.With("component", "guard"),
		now:         time.Now,
	}
}

// Mode returns the configured access mode.
func (g *Guard) Mode() AccessMode { return g.mode }

// Ceiling returns the highest risk level the access mode exposes.
func (g *Guard) Ceiling() registry.Risk { return g.mode.Ceiling() }

// MaxResultBytes returns the cap on a single tool result.
func (g *Guard) MaxResultBytes() int { return g.maxResult }

// Audit returns the audit ring read by the mcp_audit_log tool.
func (g *Guard) Audit() *Audit { return g.audit }

// Check decides whether tool may run for the caller in ctx with the given args.
// On Proceed the caller must invoke the tool and then call Record.
func (g *Guard) Check(ctx context.Context, tool registry.Tool, args json.RawMessage) Decision {
	risk := EffectiveRisk(tool, args)
	role := RoleFrom(ctx)
	name := tool.Name()

	if risk > g.Ceiling() {
		return g.refuse(ctx, tool, args, role, mcperr.Newf(mcperr.CodeToolError,
			map[string]any{"risk": risk.String(), "access_mode": string(g.mode)},
			"tool %s is %s and access_mode %s does not allow it", name, risk, g.mode))
	}
	if risk > role.Max() {
		return g.refuse(ctx, tool, args, role, mcperr.Newf(mcperr.CodeToolError,
			map[string]any{"risk": risk.String(), "role": string(role)},
			"role %s may not call %s tool %s", role, risk, name))
	}
	if !risk.NeedsConfirm() {
		return Decision{Verdict: Proceed}
	}
	if !confirmed(args) {
		result, err := g.dryRun(ctx, tool, args)
		if err != nil {
			return g.refuse(ctx, tool, args, role, mcperr.From(err))
		}
		g.audit.Add(g.entry(ctx, tool, args, role, "dry_run", ""))
		g.logger.Info("dry run returned", "tool_name", name, "risk", risk.String())
		return Decision{Verdict: DryRun, Result: result}
	}

	g.mu.Lock()
	now := g.now()
	if !g.lastConf.IsZero() && now.Sub(g.lastConf) < g.minInterval {
		wait := g.minInterval - now.Sub(g.lastConf)
		g.mu.Unlock()
		return g.refuse(ctx, tool, args, role, mcperr.Newf(mcperr.CodeToolError,
			map[string]any{"retry_after_ms": wait.Milliseconds()},
			"rate limited: another disruptive call ran %dms ago; minimum interval is %s",
			now.Sub(g.lastConf).Milliseconds(), g.minInterval))
	}
	g.lastConf = now
	g.mu.Unlock()
	return Decision{Verdict: Proceed}
}

// Record writes the outcome of a call that Check allowed to proceed. Read-only
// calls are not audited.
func (g *Guard) Record(ctx context.Context, tool registry.Tool, args json.RawMessage, err error) {
	if EffectiveRisk(tool, args) == registry.ReadOnly {
		return
	}
	outcome, msg := "executed", ""
	if err != nil {
		outcome, msg = "failed", mcperr.From(err).Message
	}
	g.audit.Add(g.entry(ctx, tool, args, RoleFrom(ctx), outcome, msg))
}

func (g *Guard) refuse(ctx context.Context, tool registry.Tool, args json.RawMessage, role Role, e *mcperr.Error) Decision {
	if EffectiveRisk(tool, args) > registry.ReadOnly {
		g.audit.Add(g.entry(ctx, tool, args, role, "refused", e.Message))
	}
	g.logger.Warn("call refused", "tool_name", tool.Name(), "reason", e.Message)
	return Decision{Verdict: Refused, Err: e}
}

// dryRun builds the response for an unconfirmed call. A tool that implements
// registry.Planner describes its own effect; others get the generic message.
func (g *Guard) dryRun(ctx context.Context, tool registry.Tool, args json.RawMessage) (map[string]any, error) {
	out := map[string]any{
		"dry_run": true,
		"tool":    tool.Name(),
		"risk":    tool.Risk().String(),
		"message": "not executed: set confirm:true to run this call",
	}
	if p, ok := tool.(registry.Planner); ok {
		plan, err := p.Plan(ctx, args)
		if err != nil {
			return nil, err
		}
		out["plan"] = plan
	}
	return out, nil
}

func (g *Guard) entry(ctx context.Context, tool registry.Tool, args json.RawMessage, role Role, outcome, msg string) Entry {
	sid := session.Label(ctx)
	e := Entry{
		Time:       g.now().UTC(),
		Tool:       tool.Name(),
		Risk:       EffectiveRisk(tool, args).String(),
		Role:       string(role),
		Session:    sid,
		RemoteAddr: session.RemoteAddrFrom(ctx),
		Outcome:    outcome,
		InputHash:  HashFor(tool, args),
		Error:      msg,
	}
	g.logger.Info("audit", "audit", true, "tool_name", e.Tool, "risk", e.Risk,
		"role", e.Role, "session_id", e.Session, "remote_addr", e.RemoteAddr, "outcome", e.Outcome,
		"input_hash", e.InputHash, "error", e.Error)
	return e
}

// EffectiveRisk returns the risk of one call: the per-call level when the tool
// implements registry.ArgRisker, otherwise the tool's static level.
func EffectiveRisk(tool registry.Tool, args json.RawMessage) registry.Risk {
	if ar, ok := tool.(registry.ArgRisker); ok {
		return ar.RiskFor(args)
	}
	return tool.Risk()
}

// confirmed reports whether the arguments carry confirm:true.
func confirmed(args json.RawMessage) bool {
	var c struct {
		Confirm bool `json:"confirm"`
	}
	_ = json.Unmarshal(args, &c)
	return c.Confirm
}

// HashFor returns the audit hash of one call's arguments. A tool that implements
// registry.Redactor is hashed on its redacted arguments, so secrets never enter the
// hash preimage.
func HashFor(tool registry.Tool, args json.RawMessage) string {
	if r, ok := tool.(registry.Redactor); ok {
		return InputHash(r.RedactArgs(args))
	}
	return InputHash(args)
}

// InputHash returns the first 8 bytes of the SHA-256 of the raw input as hex.
// Hashing avoids logging PII (SUPI, keys) while still correlating identical calls.
func InputHash(in json.RawMessage) string {
	sum := sha256.Sum256(in)
	return fmt.Sprintf("%x", sum[:8])
}
