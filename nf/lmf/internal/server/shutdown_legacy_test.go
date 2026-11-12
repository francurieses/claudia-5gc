package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/lmf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

// httpNotifClient is a NotificationClient that POSTs to the real notificationUri
// (an httptest receiver), so the test observes what a peer would observe.
type httpNotifClient struct{}

func (httpNotifClient) PostNotification(ctx context.Context, uri string, n LocationNotification) error {
	b, _ := json.Marshal(n)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// shutdownObservation is what a legacy-subscription peer and the registry see
// around Server.Shutdown.
type shutdownObservation struct {
	atShutdown     int  // notifications received when Shutdown returned
	afterShutdown  int  // notifications received two intervals later
	registryActive int  // registry size right after Shutdown
	drained        bool // tracked goroutines had exited when Shutdown returned
	lateCreate     int  // status of a Create issued after Shutdown
	lateRegistry   int  // registry size after that refused Create
}

// observeLegacyShutdown creates one legacy PERIODIC_REPORTING subscription
// (1 s interval), waits for its first notification, calls Shutdown and reports
// what the receiver, the registry and the goroutine tracker show.
func observeLegacyShutdown(t *testing.T, p *capability.Profile) shutdownObservation {
	t.Helper()
	var got atomic.Int32
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		got.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer recv.Close()

	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.DefaultCoord = config.CellCoord{Lat: 40.4168, Lon: -3.7038}
	cfg.LocationSubscription = config.LocationSubscriptionConfig{
		DefaultSamplingIntervalS: 5, DefaultReportingIntervalS: 10, MaxDurationS: 3600,
	}
	srv := NewWithNotifClient(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), goodAMF(), nil, httpNotifClient{})
	srv.SetProfile(p)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	create := func(supi string) int {
		resp := postSub(t, ts, map[string]any{
			"ueContextId": supi, "supi": supi,
			"eventTrigger": "PERIODIC_REPORTING", "notificationUri": recv.URL, "reportingInterval": 1,
		})
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := create("imsi-001010000000001"); c != http.StatusCreated {
		t.Fatalf("create subscription: %d", c)
	}
	waitFor(t, 5*time.Second, "first notification", func() bool { return got.Load() >= 1 })

	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	obs := shutdownObservation{atShutdown: int(got.Load()), registryActive: srv.registry.count()}
	// Shutdown returns early only when sctx expires; with a live ctx it has
	// waited for every tracked goroutine. bg.Wait then confirms synchronously.
	obs.drained = sctx.Err() == nil
	srv.bg.Wait()
	// Cross two reporting intervals: a surviving goroutine would POST.
	time.Sleep(2200 * time.Millisecond)
	obs.afterShutdown = int(got.Load())
	obs.lateCreate = create("imsi-001010000000002")
	obs.lateRegistry = srv.registry.count()
	srv.registry.cancelAll()
	return obs
}

// TestLegacySubscriptionShutdown pins the Shutdown contract for the legacy
// /subscriptions resource in every profile (nil, rel17, rel19): registry
// emptied, runSubscription goroutines exited when Shutdown returns, no
// notification afterwards, and a late Create is refused with 503.
func TestLegacySubscriptionShutdown(t *testing.T) {
	profiles := map[string]*capability.Profile{
		"nil": nil, "rel17": profileNamed(t, "rel17"), "rel19": profileNamed(t, "rel19"),
	}
	for name, p := range profiles {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := observeLegacyShutdown(t, p)
			if o.registryActive != 0 {
				t.Errorf("registry after Shutdown = %d, want 0", o.registryActive)
			}
			if !o.drained {
				t.Error("runSubscription goroutine still running after Shutdown returned")
			}
			if o.afterShutdown != o.atShutdown {
				t.Errorf("notifications after Shutdown: %d -> %d", o.atShutdown, o.afterShutdown)
			}
			if o.lateCreate != http.StatusServiceUnavailable || o.lateRegistry != 0 {
				t.Errorf("late create = %d, registry %d; want 503 / 0", o.lateCreate, o.lateRegistry)
			}
		})
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}
