// Package admin hosts the UPF's read-only O&M HTTP handlers. They are mounted
// on the internal metrics port (shared/observability/metrics
// MetricsServerWithAdmin), never on N4, N3 or an SBI listener, and never write
// to UPF state.
//
// The N4 sessions handler implements GET /admin/v1/n4-sessions, a deep-copied
// view of the PFCP session table (task MCP-012). It is project tooling, not a
// 3GPP procedure. Design: docs/procedures/n4-session-inspection.md.
// Ref: TS 29.244 §5.2 (Packet Forwarding Model), §7.5.2.
package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	// n4InspectionProcedure is the canonical procedure name in log lines.
	n4InspectionProcedure = "N4SessionInspection"
	// n4InspectionSpecRef anchors the data being read (Packet Forwarding Model).
	n4InspectionSpecRef = "TS 29.244 §5.2"
	// causeInvalidQueryParam is the ProblemDetails cause for a bad query value.
	causeInvalidQueryParam = "INVALID_QUERY_PARAM"
	// hexPrefixLen is the length of the "0x"/"0X" prefix of a hex SEID.
	hexPrefixLen = 2
	// metricNF is the nf label of fivegc_procedure_total.
	metricNF = "UPF"
)

// SessionDescriber is the read side of the PFCP session table; *pfcp.SessionTable
// implements it. The interface lets tests run without a PFCP server.
type SessionDescriber interface {
	Describe(f pfcp.DescribeFilter) []pfcp.SessionDescription
}

type sessionsResponse struct {
	Count    int                       `json:"count"`
	Sessions []pfcp.SessionDescription `json:"sessions"`
}

type invalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason"`
}

type problemDetails struct {
	Title         string         `json:"title"`
	Status        int            `json:"status"`
	Detail        string         `json:"detail"`
	Cause         string         `json:"cause"`
	InvalidParams []invalidParam `json:"invalidParams,omitempty"`
}

// NewN4SessionsHandler returns the GET /admin/v1/n4-sessions handler. Register
// it with a method-less pattern: the handler itself answers 405 + "Allow: GET"
// for every other method (including HEAD). logger is the NF base logger (it
// already carries nf=UPF).
func NewN4SessionsHandler(src SessionDescriber, logger *slog.Logger) http.Handler {
	return &n4Handler{src: src, base: logger}
}

type n4Handler struct {
	src  SessionDescriber
	base *slog.Logger
}

func (h *n4Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, h.base, n4InspectionProcedure).With(
		"interface", "OAM", "direction", "IN", "spec_ref", n4InspectionSpecRef)

	if r.Method != http.MethodGet {
		metrics.ProcedureTotal.WithLabelValues(metricNF, n4InspectionProcedure, "REJECT").Inc()
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		log.InfoContext(ctx, "n4 session inspection rejected",
			"result", "REJECT", "cause", "METHOD_NOT_ALLOWED", "method", r.Method)
		return
	}

	q := r.URL.Query()
	var f pfcp.DescribeFilter
	if raw := q.Get("seid"); raw != "" {
		seid, err := parseSEID(raw)
		if err != nil {
			h.reject(ctx, w, log, "seid", "must be an unsigned 64-bit decimal or 0x-prefixed hex integer", "seid", raw)
			return
		}
		f.SEID = seid
	}
	if raw := q.Get("ue_ip"); raw != "" {
		ip := net.ParseIP(raw)
		if ip == nil {
			h.reject(ctx, w, log, "ue_ip", "must be an IPv4 or IPv6 address literal", "ue_ip", raw)
			return
		}
		f.UEIP = ip
	}

	sessions := h.src.Describe(f)
	if sessions == nil {
		sessions = []pfcp.SessionDescription{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(sessionsResponse{Count: len(sessions), Sessions: sessions}); err != nil {
		log.WarnContext(ctx, "n4 session inspection: write response failed", "error", err)
	}
	metrics.ProcedureTotal.WithLabelValues(metricNF, n4InspectionProcedure, "OK").Inc()
	attrs := []any{"result", "OK", "count", len(sessions)}
	if v := q.Get("seid"); v != "" {
		attrs = append(attrs, "seid", v)
	}
	if v := q.Get("ue_ip"); v != "" {
		attrs = append(attrs, "ue_ip", v)
	}
	log.InfoContext(ctx, "n4 session inspection", attrs...)
}

// reject writes a 400 application/problem+json (TS 29.571 ProblemDetails shape)
// and the canonical REJECT log line; kv are extra log attributes.
func (h *n4Handler) reject(ctx context.Context, w http.ResponseWriter, log *slog.Logger, param, reason string, kv ...any) {
	metrics.ProcedureTotal.WithLabelValues(metricNF, n4InspectionProcedure, "REJECT").Inc()
	pd := problemDetails{
		Title:         "Invalid query parameter",
		Status:        http.StatusBadRequest,
		Detail:        "query parameter " + param + " " + reason,
		Cause:         causeInvalidQueryParam,
		InvalidParams: []invalidParam{{Param: param, Reason: reason}},
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	if err := json.NewEncoder(w).Encode(pd); err != nil {
		log.WarnContext(ctx, "n4 session inspection: write response failed", "error", err)
	}
	attrs := append([]any{"result", "REJECT", "cause", causeInvalidQueryParam}, kv...)
	log.InfoContext(ctx, "n4 session inspection rejected", attrs...)
}

// parseSEID parses a decimal or 0x/0X-hex uint64. Base 0 is deliberately not
// used: "010" must be decimal 10 and 0o/0b prefixes are not accepted.
func parseSEID(s string) (uint64, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[hexPrefixLen:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}
