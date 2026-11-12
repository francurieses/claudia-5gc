package sbi

// features_counter_test.go - the AMF LogNegotiation helper counts one
// fivegc_procedure_total{nf="AMF",procedure="FeatureNegotiation"} per record
// (REL19-2.8). Ref: TS 29.500 §6.6.2.

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func TestLogNegotiationCountsProcedure(t *testing.T) {
	base := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for _, result := range []string{"OK", "REJECT", "FAILURE"} {
		c := metrics.ProcedureTotal.WithLabelValues("AMF", features.ProcedureName, result)
		before := testutil.ToFloat64(c)
		LogNegotiation(context.Background(), base, Negotiation{
			Interface: "Namf", Direction: "IN", PeerNF: "SMF", SpecRef: features.SpecRef, Result: result,
		})
		if d := testutil.ToFloat64(c) - before; d != 1 {
			t.Errorf("%s: counter delta = %v, want 1", result, d)
		}
	}
}
