package oauth2

// transport_test.go - NewBearerClient must keep the redirect policy of the
// wrapped client so ES3XX handling (shared/sbi.ApplyRedirectPolicy) survives
// the OAuth2 wrap. Ref: TS 29.500 §6.10.9.1.

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewBearerClientPropagatesCheckRedirect(t *testing.T) {
	var called atomic.Int32
	base := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			called.Add(1)
			return http.ErrUseLastResponse
		},
	}
	c := NewBearerClient(base, NewTokenCache(base, "http://127.0.0.1:0/token", "nf", "scope"))
	if c.CheckRedirect == nil {
		t.Fatal("CheckRedirect not propagated")
	}
	if c.Timeout != base.Timeout {
		t.Errorf("Timeout = %v, want %v", c.Timeout, base.Timeout)
	}

	// End to end: the propagated policy is the one net/http consults.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/next", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	resp, err := c.Get(srv.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if called.Load() != 1 || resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("policy calls=%d status=%d, want 1 / 307", called.Load(), resp.StatusCode)
	}
}

func TestNewBearerClientNilCheckRedirectStaysNil(t *testing.T) {
	base := &http.Client{}
	c := NewBearerClient(base, NewTokenCache(base, "http://127.0.0.1:0/token", "nf", "scope"))
	if c.CheckRedirect != nil {
		t.Error("nil policy must stay nil (Go default)")
	}
}
