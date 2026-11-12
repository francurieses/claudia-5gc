package main

// smf_redirect_test.go - SBI-FEAT-001: the AMF, as Nsmf_PDUSession consumer,
// follows HTTP 307/308 for SM-context operations (ES3XX) and never follows
// other 3xx. The policy is installed exactly as cmd/amf/main.go does
// (sbi.ApplyRedirectPolicy on the SBI client).
// Ref: TS 29.502 §6.1.8 (feature 8 ES3XX), §6.1.10; TS 29.500 §6.10.9.1.

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

type mockSMF struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []string // "METHOD path body"
}

func newMockSMF(t *testing.T, h http.HandlerFunc) *mockSMF {
	t.Helper()
	m := &mockSMF{}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.reqs = append(m.reqs, r.Method+" "+r.URL.Path+" "+string(raw))
		m.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockSMF) addr() string { return strings.TrimPrefix(m.srv.URL, "https://") }

func (m *mockSMF) got() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.reqs...)
}

// redirectingSMFs returns SMF-A (always answers `status` with Location to SMF-B)
// and SMF-B (answers via `target`), plus a client wired to SMF-A.
func redirectingSMFs(t *testing.T, status int, target http.HandlerFunc) (a, b *mockSMF, c *HTTPSMFClient) {
	t.Helper()
	b = newMockSMF(t, target)
	a = newMockSMF(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", b.srv.URL+r.URL.Path)
		w.WriteHeader(status)
	})
	hc := a.srv.Client()
	sbi.ApplyRedirectPolicy(hc, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	c = &HTTPSMFClient{address: a.addr(), client: hc, logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	return a, b, c
}

func TestHTTPSMFClient_FollowsRedirect(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run("CreateSMContext/"+http.StatusText(status), func(t *testing.T) {
			a, b, c := redirectingSMFs(t, status, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"smContextRef":"ctx-b-1"}`))
			})
			ref, _, _, _, err := c.CreateSMContext(t.Context(), "imsi-001010000000001", "internet", 1,
				[]byte{1, 2, 3}, amfctx.SNSSAISubscribed{SST: 1, SD: "000001"})
			if err != nil {
				t.Fatalf("CreateSMContext: %v", err)
			}
			ga, gb := a.got(), b.got()
			if ref != "ctx-b-1" || len(ga) != 1 || len(gb) != 1 {
				t.Fatalf("ref=%q A=%d B=%d", ref, len(ga), len(gb))
			}
			if ga[0] != gb[0] || !strings.HasPrefix(gb[0], "POST /nsmf-pdusession/v1/sm-contexts {") {
				t.Errorf("retransmission differs:\nA=%s\nB=%s", ga[0], gb[0])
			}
		})
	}

	t.Run("UpdateSMContext", func(t *testing.T) {
		a, b, c := redirectingSMFs(t, http.StatusTemporaryRedirect, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		if err := c.UpdateSMContext(t.Context(), "ctx-1", []byte{9}); err != nil {
			t.Fatal(err)
		}
		ga, gb := a.got(), b.got()
		if len(ga) != 1 || len(gb) != 1 || ga[0] != gb[0] || !strings.HasPrefix(gb[0], "POST /nsmf-pdusession/v1/sm-contexts/ctx-1/modify ") {
			t.Errorf("A=%v B=%v", ga, gb)
		}
	})

	t.Run("ActivateSMContext", func(t *testing.T) {
		a, b, c := redirectingSMFs(t, http.StatusPermanentRedirect, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"n2SmInfo":"` + base64.StdEncoding.EncodeToString([]byte{7, 7}) + `"}`))
		})
		n2, err := c.ActivateSMContext(t.Context(), "ctx-1")
		if err != nil || len(n2) != 2 {
			t.Fatalf("n2=%v err=%v", n2, err)
		}
		if ga, gb := a.got(), b.got(); len(ga) != 1 || len(gb) != 1 || ga[0] != gb[0] {
			t.Errorf("A=%v B=%v", ga, gb)
		}
	})

	t.Run("DeleteSMContext keeps method", func(t *testing.T) {
		a, b, c := redirectingSMFs(t, http.StatusTemporaryRedirect, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		if err := c.DeleteSMContext(t.Context(), "ctx-1"); err != nil {
			t.Fatal(err)
		}
		ga, gb := a.got(), b.got()
		if len(ga) != 1 || len(gb) != 1 || gb[0] != "DELETE /nsmf-pdusession/v1/sm-contexts/ctx-1 " || ga[0] != gb[0] {
			t.Errorf("A=%v B=%v", ga, gb)
		}
	})
}

func TestHTTPSMFClient_DoesNotFollowOther3xx(t *testing.T) {
	for _, status := range []int{301, 302, 303} {
		a, b, c := redirectingSMFs(t, status, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
		})
		_, _, _, _, err := c.CreateSMContext(t.Context(), "imsi-001010000000001", "internet", 1,
			[]byte{1}, amfctx.SNSSAISubscribed{SST: 1})
		if err == nil || !strings.Contains(err.Error(), "status "+strconv.Itoa(status)) {
			t.Errorf("%d: err = %v, want status %d", status, err, status)
		}
		if len(a.got()) != 1 || len(b.got()) != 0 {
			t.Errorf("%d: A=%d B=%d", status, len(a.got()), len(b.got()))
		}
	}
}
