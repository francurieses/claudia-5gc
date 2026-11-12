package nrf

// negotiate_counter_test.go - REL19-2.8: the Nnrf_NFDiscovery consumer record
// is counted in fivegc_procedure_total{nf=<requester NF type>,
// procedure="FeatureNegotiation",result} exactly once per discovery.
// Ref: TS 29.500 §6.6.2; TS 29.510 §6.2.3.2.3.1.

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func negotiationCount(nf, result string) float64 {
	return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues(nf, features.ProcedureName, result))
}

func TestDiscoverNegotiationCounter(t *testing.T) {
	for _, tc := range []struct {
		name, answer, result string
	}{
		{"valid answer counts OK", `"3"`, "OK"},
		{"malformed answer counts FAILURE", `"zz"`, "FAILURE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := goldenQuery() // RequesterNFType "AMF"
			okBefore, failBefore := negotiationCount("AMF", "OK"), negotiationCount("AMF", "FAILURE")
			unknownBefore := negotiationCount(features.UnknownNF, tc.result)
			capture(t, profileFor(t, capability.ProfileRel19), nil, q,
				`{"nfInstances":[],"nrfSupportedFeatures":`+tc.answer+`}`)
			wantOK, wantFail := 0.0, 0.0
			if tc.result == "OK" {
				wantOK = 1
			} else {
				wantFail = 1
			}
			if d := negotiationCount("AMF", "OK") - okBefore; d != wantOK {
				t.Errorf("nf=AMF result=OK delta = %v, want %v", d, wantOK)
			}
			if d := negotiationCount("AMF", "FAILURE") - failBefore; d != wantFail {
				t.Errorf("nf=AMF result=FAILURE delta = %v, want %v", d, wantFail)
			}
			if d := negotiationCount(features.UnknownNF, tc.result) - unknownBefore; d != 0 {
				t.Errorf("nf=UNKNOWN delta = %v, want 0", d)
			}
		})
	}
}
