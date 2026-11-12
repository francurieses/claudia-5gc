package server

// features_counter_test.go - an NF call site sets the nf label: the UDM
// producer counts fivegc_procedure_total{nf="UDM",procedure=
// "FeatureNegotiation"}, never "UNKNOWN" (REL19-2.8). Ref: TS 29.500 §6.6.2.

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func TestFeatureNegotiationCounterLabelsNF(t *testing.T) {
	ok := metrics.ProcedureTotal.WithLabelValues("UDM", features.ProcedureName, "OK")
	rej := metrics.ProcedureTotal.WithLabelValues("UDM", features.ProcedureName, "REJECT")
	unk := metrics.ProcedureTotal.WithLabelValues(features.UnknownNF, features.ProcedureName, "OK")
	okB, rejB, unkB := testutil.ToFloat64(ok), testutil.ToFloat64(rej), testutil.ToFloat64(unk)

	s, _ := newFeatureUDM(t, profileNamed(t, "rel19"), nil, "5G_AKA")
	postAuth(t, s, authReq+`,"supportedFeatures":"1"}`)
	postAuth(t, s, authReq+`,"supportedFeatures":"zz"}`)

	if d := testutil.ToFloat64(ok) - okB; d != 1 {
		t.Errorf("UDM OK delta = %v, want 1", d)
	}
	if d := testutil.ToFloat64(rej) - rejB; d != 1 {
		t.Errorf("UDM REJECT delta = %v, want 1", d)
	}
	if d := testutil.ToFloat64(unk) - unkB; d != 0 {
		t.Errorf("UNKNOWN OK delta = %v, want 0 (nf label unset at a call site)", d)
	}
}
