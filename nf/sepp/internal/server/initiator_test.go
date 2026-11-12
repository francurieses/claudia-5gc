package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32c"
)

type fakeEx struct {
	mu    sync.Mutex
	calls int
	roots []string
	errs  []error // returned in order; nil past the end
}

func (f *fakeEx) Exchange(_ context.Context, root string, _ n32c.PlmnId) (n32c.Context, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.roots = append(f.roots, root)
	if f.calls <= len(f.errs) {
		return n32c.Context{}, f.errs[f.calls-1]
	}
	return n32c.Context{}, nil
}

func initiatorServer(t *testing.T) (*Server, []config.N32Peer) {
	t.Helper()
	cfg, _ := config.Load()
	peers := []config.N32Peer{{PLMN: config.PLMN{MCC: "001", MNC: "02"}, FQDN: "sepp.5gc.mnc002.mcc001.3gppnetwork.org", Address: "peer:8443"}}
	return New(cfg, slog.New(slog.NewJSONHandler(io.Discard, nil))), peers
}

var fastTiming = initiatorTiming{time.Millisecond, time.Millisecond, 2 * time.Millisecond}

func TestInitiatorRetriesThenSucceeds(t *testing.T) {
	s, peers := initiatorServer(t)
	ex := &fakeEx{errs: []error{errors.New("dial"), errors.New("dial")}}
	s.runInitiator(context.Background(), ex, peers, fastTiming)()
	if ex.calls != 3 || ex.roots[0] != "https://peer:8443" {
		t.Fatalf("calls=%d roots=%v", ex.calls, ex.roots)
	}
}

func TestInitiatorStopsOnRejection(t *testing.T) {
	s, peers := initiatorServer(t)
	ex := &fakeEx{errs: []error{n32c.ErrNegotiationNotAllowed}}
	s.runInitiator(context.Background(), ex, peers, fastTiming)()
	if ex.calls != 1 {
		t.Fatalf("calls=%d", ex.calls)
	}
}

func TestInitiatorGivesUpAndHonoursContext(t *testing.T) {
	s, peers := initiatorServer(t)
	errs := make([]error, 100)
	for i := range errs {
		errs[i] = errors.New("down")
	}
	ex := &fakeEx{errs: errs}
	s.runInitiator(context.Background(), ex, peers, fastTiming)()
	if ex.calls != initiatorMaxAttempts {
		t.Fatalf("calls=%d", ex.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ex2 := &fakeEx{}
	s.runInitiator(ctx, ex2, peers, fastTiming)()
	if ex2.calls != 0 {
		t.Fatalf("exchange after cancel: %d", ex2.calls)
	}
}

func TestInitiatorSkipsWhenContextExists(t *testing.T) {
	s, peers := initiatorServer(t)
	s.n32.Store().Replace(n32c.Context{RemotePLMN: n32c.PlmnId{Mcc: "001", Mnc: "02"}, SecCapability: n32c.CapTLS})
	ex := &fakeEx{}
	s.runInitiator(context.Background(), ex, peers, fastTiming)()
	if ex.calls != 0 {
		t.Fatalf("calls=%d", ex.calls)
	}
}

func TestListenersWithoutForwarderReturn404(t *testing.T) {
	s, _ := initiatorServer(t)
	for name, h := range map[string]http.Handler{"sbi": s.Handler(), "n32": s.N32Handler()} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nudm-sdm/v2/x/nssai", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}
