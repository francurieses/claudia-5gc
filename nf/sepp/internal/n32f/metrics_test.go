package n32f

import (
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// PORTAL-UI-22: every handled N32-f message is counted once, by direction,
// remote PLMN (or "unknown" before routing) and result.
func TestN32fMetrics(t *testing.T) {
	okOut := n32fMessagesTotal.WithLabelValues("OUT", remotePLMN.String(), "OK")
	rejUnknown := n32fMessagesTotal.WithLabelValues("OUT", peerUnknown, "REJECT")
	b0, r0 := testutil.ToFloat64(okOut), testutil.ToFloat64(rejUnknown)

	fx := newFixture(t, opts{})
	if rec := do(fx.f.Outbound(), httptest.NewRequest("GET", "https://"+remoteNF+"/nudm-sdm/v2/x", nil)); rec.Code != 204 {
		t.Fatalf("forward status %d", rec.Code)
	}
	if got := testutil.ToFloat64(okOut) - b0; got != 1 {
		t.Fatalf("OUT OK delta = %v, want 1", got)
	}

	none := newFixture(t, opts{noCtx: true})
	if rec := do(none.f.Outbound(), httptest.NewRequest("GET", "https://"+remoteNF+"/nudm-sdm/v2/x", nil)); rec.Code != 403 {
		t.Fatalf("no-context status %d", rec.Code)
	}
	if got := testutil.ToFloat64(rejUnknown) - r0; got != 1 {
		t.Fatalf("OUT unknown REJECT delta = %v, want 1", got)
	}
}
