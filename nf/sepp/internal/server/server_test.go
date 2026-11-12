package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(cfg, slog.Default()).Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestHealthzAndCorrelationID(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Correlation-Id") == "" {
		t.Fatalf("status=%d corr=%q", resp.StatusCode, resp.Header.Get("X-Correlation-Id"))
	}
}

func TestCorrelationIDEchoed(t *testing.T) {
	ts := newTestServer(t)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/healthz", nil)
	req.Header.Set("X-Correlation-Id", "abc")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Correlation-Id"); got != "abc" {
		t.Fatalf("corr = %q", got)
	}
}

func TestUnknownRouteAndMethod(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/nope")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	resp, err = http.Post(ts.URL+"/healthz", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestN32HandlerExposesOnlyN32cRoute(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(cfg, slog.Default()).N32Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("healthz on N32 listener: %d", resp.StatusCode)
	}
	resp, err = http.Post(ts.URL+"/n32c-handshake/v1/exchange-capability", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("exchange-capability status = %d", resp.StatusCode)
	}
}

func TestStartN32RefusesWithoutCertificates(t *testing.T) {
	cfg, _ := config.Load()
	cfg.SBI.TLS.CertFile, cfg.N32.TLS.CertFile = "", ""
	s := New(cfg, slog.Default())
	if err := s.StartN32(context.Background()); err == nil || !strings.Contains(err.Error(), "requires TLS") {
		t.Fatalf("err = %v", err)
	}
}

func TestStartN32AllowsPlainOnlyWhenFlagged(t *testing.T) {
	cfg, _ := config.Load()
	cfg.SBI.TLS.CertFile = ""
	cfg.N32.Address = "127.0.0.1:0"
	s := New(cfg, slog.Default())
	s.AllowPlainN32ForTests()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.StartN32(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("StartN32 did not return")
	}
}

func TestStartN32RejectsBadCABundle(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	write := func(name string, b []byte) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg, _ := config.Load()
	cfg.N32.TLS.CertFile = write("c.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	cfg.N32.TLS.KeyFile = write("k.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	cfg.N32.TLS.CAFile = write("ca.pem", []byte("not a pem"))
	s := New(cfg, slog.Default())
	if err := s.StartN32(context.Background()); err == nil || !strings.Contains(err.Error(), "no valid certificate") {
		t.Fatalf("err = %v", err)
	}
}

func TestN32ServerHasTimeoutsAndHeaderLimit(t *testing.T) {
	cfg, _ := config.Load()
	s := New(cfg, slog.Default())
	if s.n32Srv.ReadTimeout == 0 || s.n32Srv.IdleTimeout == 0 || s.n32Srv.WriteTimeout == 0 || s.n32Srv.MaxHeaderBytes == 0 {
		t.Fatalf("limits not set: %+v", s.n32Srv)
	}
}
