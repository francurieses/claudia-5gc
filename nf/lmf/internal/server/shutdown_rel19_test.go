package server

import (
	"context"
	"testing"
	"time"
)

// TestShutdown_Rel19CancelsLegacyAndDeferred: under rel19 Shutdown cancels the
// legacy subscription (no further notifications, registry emptied) and the
// deferred-location sessions, and drains their goroutines.
func TestShutdown_Rel19CancelsLegacyAndDeferred(t *testing.T) {
	p := profileNamed(t, "rel19")
	o := observeLegacyShutdown(t, p)
	if o.registryActive != 0 {
		t.Errorf("registry after Shutdown = %d, want 0", o.registryActive)
	}
	if o.afterShutdown != o.atShutdown {
		t.Errorf("legacy subscription still notified after Shutdown (%d -> %d)", o.atShutdown, o.afterShutdown)
	}

	ts, srv := newDeferredLMF(t, p, goodAMF(), newEventSink())
	resp, body := post(t, ts, detLM, periodicBody(1000, true))
	if srv.registry.countDeferred() != 1 {
		t.Fatalf("deferred sessions = %d, want 1 (status %d: %s)", srv.registry.countDeferred(), resp.StatusCode, body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if n := srv.registry.count(); n != 0 {
		t.Errorf("registry after rel19 Shutdown = %d, want 0", n)
	}
	if ctx.Err() != nil {
		t.Error("drain did not finish before the deadline")
	}
}
