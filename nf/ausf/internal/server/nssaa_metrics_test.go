package server

// nssaa_metrics_test.go - fivegc_procedure_total{nf="AUSF",procedure="NSSAA"}
// counter deltas for Nnssaaf_NSSAA (REL19-3.5 observability).
// Ref: TS 29.526 §5.2.2.2, §5.2.2.3

import (
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

func TestSliceAuth_ProcedureTotal(t *testing.T) {
	cnt := func(res string) float64 {
		return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("AUSF", "NSSAA", res))
	}
	srv := profileSrv(t, "rel19")

	// One-round success: OK.
	ok0 := cnt("OK")
	if r := doJSON(srv, "POST", nssaaCtxPath, createBody("alice@nssaa.example.com")); r.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", r.StatusCode)
	}
	if d := cnt("OK") - ok0; d != 1 {
		t.Errorf("one-round OK delta = %v, want 1", d)
	}

	// AAA-S refusal (403) and malformed body (400): REJECT.
	rej0 := cnt("REJECT")
	if r := doJSON(srv, "POST", nssaaCtxPath, createBody("m@reject.example.com")); r.StatusCode != http.StatusForbidden {
		t.Fatalf("reject: %d", r.StatusCode)
	}
	if r := doJSON(srv, "POST", nssaaCtxPath, `{"gpsi":"msisdn-1","snssai":{"sst":1}}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad: %d", r.StatusCode)
	}
	if d := cnt("REJECT") - rej0; d != 2 {
		t.Errorf("REJECT delta = %v, want 2", d)
	}

	// Multi-round: the pending create is not terminal; the PUT counts OK.
	ok1, rej1 := cnt("OK"), cnt("REJECT")
	resp := doJSON(srv, "POST", nssaaCtxPath, createBody("bob@challenge.example.com"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("challenge create: %d", resp.StatusCode)
	}
	c, pkt := decodeCtx(t, resp)
	if cnt("OK") != ok1 || cnt("REJECT") != rej1 {
		t.Errorf("a PENDING create must not be counted")
	}
	if r := doJSON(srv, "PUT", nssaaCtxPath+"/"+c.AuthCtxID, confirmBody(pkt[1], 2)); r.StatusCode != http.StatusOK {
		t.Fatalf("confirm: %d", r.StatusCode)
	}
	if d := cnt("OK") - ok1; d != 1 {
		t.Errorf("confirm OK delta = %v, want 1", d)
	}

	// Unknown context: REJECT.
	rej2 := cnt("REJECT")
	if r := doJSON(srv, "PUT", nssaaCtxPath+"/nope", confirmBody(1, 2)); r.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown ctx: %d", r.StatusCode)
	}
	if d := cnt("REJECT") - rej2; d != 1 {
		t.Errorf("unknown-context REJECT delta = %v, want 1", d)
	}
}
