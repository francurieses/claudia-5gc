package features

// log_counter_test.go - LogNegotiation increments the generic
// fivegc_procedure_total{procedure="FeatureNegotiation"} once per record
// (REL19-2.8). Ref: TS 29.500 §6.6.2.

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

func TestLogNegotiationCountsProcedure(t *testing.T) {
	base := slog.New(slog.NewJSONHandler(io.Discard, nil))
	tests := []struct {
		name, nf, result, wantNF string
	}{
		{"ok", "ZZTESTNF", "OK", "ZZTESTNF"},
		{"reject", "ZZTESTNF", "REJECT", "ZZTESTNF"},
		{"failure", "ZZTESTNF", "FAILURE", "ZZTESTNF"},
		{"unset nf", "", "OK", UnknownNF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := metrics.ProcedureTotal.WithLabelValues(tc.wantNF, ProcedureName, tc.result)
			before := testutil.ToFloat64(c)
			LogNegotiation(context.Background(), base, Negotiation{
				NF: tc.nf, Interface: "Nx", Direction: "IN", PeerNF: "AMF",
				SpecRef: SpecRef, Result: tc.result,
			})
			if d := testutil.ToFloat64(c) - before; d != 1 {
				t.Fatalf("counter delta = %v, want 1", d)
			}
		})
	}
}
