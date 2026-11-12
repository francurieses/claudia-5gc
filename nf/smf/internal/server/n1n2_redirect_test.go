package server

// n1n2_redirect_test.go - SBI-FEAT-001: the SMF, as Namf_Communication
// consumer, follows HTTP 307/308 for N1N2MessageTransfer (ES3XX) and does not
// follow other 3xx. The policy is installed on the SBI client exactly as New()
// does (sbi.ApplyRedirectPolicy).
// Ref: TS 29.518 §6.1.8 (feature 7 ES3XX), §6.1.10; TS 29.500 §6.10.9.1.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/sbi"
)

type mockAMF struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []string // "METHOD path body"
}

func newMockAMF(t *testing.T, h http.HandlerFunc) *mockAMF {
	t.Helper()
	m := &mockAMF{}
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

func (m *mockAMF) got() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.reqs...)
}

// redirectingAMFs wires a rel19 SMF to AMF-A, which answers `status` with a
// Location to AMF-B, which answers 200 with cause N1_N2_TRANSFER_INITIATED.
func redirectingAMFs(t *testing.T, status int) (*Server, *mockAMF, *mockAMF) {
	t.Helper()
	b := newMockAMF(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"cause":"N1_N2_TRANSFER_INITIATED"}`)
	})
	a := newMockAMF(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", b.srv.URL+r.URL.Path)
		w.WriteHeader(status)
	})
	s, _ := newFeatureServer(t, "rel19", nil, nil)
	pointAtAMF(s, a.srv)
	sbi.ApplyRedirectPolicy(s.httpClient, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	return s, a, b
}

func TestN1N2_FollowsRedirect(t *testing.T) {
	const path = "POST /namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages "
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run("paging/"+strconv.Itoa(status), func(t *testing.T) {
			s, a, b := redirectingAMFs(t, status)
			cause, err := s.triggerN1N2MessageTransfer(context.Background(), "imsi-001010000000001", 1)
			if err != nil || cause != "N1_N2_TRANSFER_INITIATED" {
				t.Fatalf("cause=%q err=%v", cause, err)
			}
			ga, gb := a.got(), b.got()
			want := path + `{"pduSessionId":1,"supportedFeatures":"40"}`
			if len(ga) != 1 || len(gb) != 1 || ga[0] != want || gb[0] != want {
				t.Errorf("A=%v B=%v", ga, gb)
			}
		})
		t.Run("push/"+strconv.Itoa(status), func(t *testing.T) {
			s, a, b := redirectingAMFs(t, status)
			cause, err := s.pushN1N2Message(context.Background(), "imsi-001010000000001", 1,
				[]byte{0x2e, 0x01, 0x05, 0xc5}, []byte{1, 2}, "PDU_RES_SETUP_REQ")
			if err != nil || cause != "N1_N2_TRANSFER_INITIATED" {
				t.Fatalf("cause=%q err=%v", cause, err)
			}
			ga, gb := a.got(), b.got()
			if len(ga) != 1 || len(gb) != 1 || ga[0] != gb[0] || !strings.HasPrefix(gb[0], path+"{") || !strings.Contains(gb[0], `"n1SmMsg":"LgEFxQ=="`) {
				t.Errorf("A=%v B=%v", ga, gb)
			}
		})
	}
}

func TestN1N2_DoesNotFollowOther3xx(t *testing.T) {
	for _, status := range []int{301, 302, 303} {
		s, a, b := redirectingAMFs(t, status)
		_, err := s.triggerN1N2MessageTransfer(context.Background(), "imsi-001010000000001", 1)
		if err == nil || !strings.Contains(err.Error(), "status "+strconv.Itoa(status)) {
			t.Errorf("%d: err = %v", status, err)
		}
		if len(a.got()) != 1 || len(b.got()) != 0 {
			t.Errorf("%d: A=%d B=%d", status, len(a.got()), len(b.got()))
		}
	}
}

// TestNew_InstallsRedirectPolicy: New() installs the ES3XX policy on the
// shared SBI client.
func TestNew_InstallsRedirectPolicy(t *testing.T) {
	s, _ := newFeatureServer(t, "rel19", nil, nil)
	if s.httpClient.CheckRedirect == nil {
		t.Fatal("SBI client has no redirect policy")
	}
}
