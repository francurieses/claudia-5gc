// Package logging provides a canonical structured logger for 5GC NFs.
// All NFs MUST use this helper for procedure-related logs to ensure consistent
// fields (CLAUDE.md §5).
package logging

import (
	"context"
	"log/slog"

	"github.com/oklog/ulid/v2"
)

type ctxKey string

const (
	keyCorrelationID ctxKey = "correlation_id"
	keySUPI          ctxKey = "supi"
	keyGUTI          ctxKey = "guti"
	keyPDUSessionID  ctxKey = "pdu_session_id"
	keyAMFUENGAPID   ctxKey = "amf_ue_ngap_id"
	keyRANUENGAPID   ctxKey = "ran_ue_ngap_id"
)

// WithCorrelationID returns a context with a correlation ID. If id is empty,
// a new ULID is generated.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	if id == "" {
		id = ulid.Make().String()
	}
	return context.WithValue(ctx, keyCorrelationID, id)
}

// CorrelationID returns the correlation ID from ctx, or "" if absent.
func CorrelationID(ctx context.Context) string {
	if v, ok := ctx.Value(keyCorrelationID).(string); ok {
		return v
	}
	return ""
}

// WithSUPI attaches a SUPI to the context.
func WithSUPI(ctx context.Context, supi string) context.Context {
	return context.WithValue(ctx, keySUPI, supi)
}

// NewProcedureLogger returns a logger pre-populated with the procedure name
// and any UE/session identifiers stored in ctx. This is the canonical entry
// point — do not call slog directly in NF code.
func NewProcedureLogger(ctx context.Context, base *slog.Logger, procedure string) *slog.Logger {
	l := base.With("procedure", procedure)
	if v := CorrelationID(ctx); v != "" {
		l = l.With("correlation_id", v)
	}
	if v, ok := ctx.Value(keySUPI).(string); ok {
		l = l.With("supi", v)
	}
	if v, ok := ctx.Value(keyGUTI).(string); ok {
		l = l.With("guti", v)
	}
	if v, ok := ctx.Value(keyPDUSessionID).(int); ok {
		l = l.With("pdu_session_id", v)
	}
	if v, ok := ctx.Value(keyAMFUENGAPID).(int64); ok {
		l = l.With("amf_ue_ngap_id", v)
	}
	if v, ok := ctx.Value(keyRANUENGAPID).(int64); ok {
		l = l.With("ran_ue_ngap_id", v)
	}
	return l
}

// LogMessage is a convenience helper that emits a log entry for a single
// 3GPP message (NAS, NGAP, PFCP, SBI). Always include direction and
// interface to enable filtering.
func LogMessage(l *slog.Logger, iface, direction, msgType, specRef string) {
	l.Info("message",
		"interface", iface,
		"direction", direction,
		"message_type", msgType,
		"spec_ref", specRef,
	)
}
