package server

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32trust/testpki"
)

const (
	localFQDN = "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
	peerFQDN  = "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
)

// trustCfg returns a default config whose N32 cert is written under dir.
func trustCfg(t *testing.T, dir string, san ...string) (*config.Config, *testpki.CA) {
	t.Helper()
	t.Setenv(config.PartnersFileEnv, filepath.Join(dir, "absent-partners.yaml"))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	ca := testpki.NewCA(t, "n32-local")
	if len(san) > 0 {
		cfg.N32.TLS.CertFile, cfg.N32.TLS.KeyFile = testpki.WriteCert(t, dir, "sepp", ca.Issue(t, san, testpki.Both, time.Now().Add(time.Hour)))
	} else {
		cfg.N32.TLS.CertFile, cfg.N32.TLS.KeyFile = filepath.Join(dir, "none.crt"), filepath.Join(dir, "none.key")
	}
	return cfg, ca
}

func addPartner(t *testing.T, cfg *config.Config, dir string, ca *testpki.CA, address string) {
	t.Helper()
	cfg.N32.Partners = append(cfg.N32.Partners, config.Partner{PLMN: config.PLMN{MCC: "001", MNC: "02"},
		N32: config.PartnerN32{CAFile: testpki.WriteFile(t, dir, "peer-ca.crt", ca.PEM), Address: address}})
}

func TestLoadN32TLS(t *testing.T) {
	dir := t.TempDir()
	peerCA := testpki.NewCA(t, "peer")

	cfg, _ := trustCfg(t, dir) // no cert, no partner: default core without N32 PKI
	if tl, err := LoadN32TLS(cfg, nil); tl != nil || err != nil {
		t.Fatalf("no cert/no partners: %v %v (want nil,nil)", tl, err)
	}

	addPartner(t, cfg, dir, peerCA, "")
	if _, err := LoadN32TLS(cfg, nil); err == nil || !strings.Contains(err.Error(), "no fallback to sbi.tls") {
		t.Fatalf("partners without own cert must be fatal: %v", err)
	}

	cfg, _ = trustCfg(t, dir, localFQDN)
	tl, err := LoadN32TLS(cfg, nil) // no partners but own cert: responder ready
	if err != nil || tl == nil {
		t.Fatalf("own cert, no partners: %v %v", tl, err)
	}
	addPartner(t, cfg, dir, peerCA, "")
	if tl, err = LoadN32TLS(cfg, nil); err != nil || len(tl.Verifier.Anchors()) != 1 {
		t.Fatalf("partner: %v", err)
	}

	cfg, _ = trustCfg(t, dir, peerFQDN) // SAN names another SEPP
	if _, err := LoadN32TLS(cfg, nil); err == nil || !strings.Contains(err.Error(), "SEPP FQDN") {
		t.Fatalf("wrong own SAN must be fatal: %v", err)
	}

	cfg, _ = trustCfg(t, dir, localFQDN) // SBI CA as partner anchor
	sbiCA := testpki.NewCA(t, "sbi")
	cfg.SBI.TLS.CAFile = testpki.WriteFile(t, dir, "sbi-ca.crt", sbiCA.PEM)
	addPartner(t, cfg, dir, sbiCA, "")
	if _, err := LoadN32TLS(cfg, nil); err == nil || !strings.Contains(err.Error(), "SBI CA") {
		t.Fatalf("SBI CA as N32 anchor must be fatal: %v", err)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// With no partner the N32 listener is up (responder ready) but rejects every handshake.
func TestN32ListenerReadyWithoutPartnersRejectsHandshake(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := trustCfg(t, dir, localFQDN)
	cfg.N32.Address = freeAddr(t)
	tl, err := LoadN32TLS(cfg, nil)
	if err != nil || tl == nil {
		t.Fatal(err)
	}
	s := New(cfg, discardLogger())
	s.SetN32TLS(tl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.StartN32(ctx) }()

	peerCA := testpki.NewCA(t, "peer")
	peerCert := peerCA.Issue(t, []string{peerFQDN}, testpki.Both, time.Now().Add(time.Hour))
	var conn *tls.Conn
	for i := 0; i < 100; i++ { // listener readiness
		c, derr := tls.Dial("tcp", cfg.N32.Address, &tls.Config{Certificates: []tls.Certificate{peerCert},
			InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}) //nolint:gosec // test client
		if derr == nil || !strings.Contains(derr.Error(), "refused") {
			conn, err = c, derr
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn != nil {
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Read(make([]byte, 1)) // TLS 1.3: the client-cert rejection arrives after the handshake
	}
	if err == nil {
		t.Fatal("handshake from a non-partner accepted by a partner-less SEPP")
	}
}

// The N32-c initiator client verifies the partner with the per-PLMN anchor and
// treats a rejection as a non-retryable identity error.
func TestPeerIdentityClientWithTrust(t *testing.T) {
	dir := t.TempDir()
	peerCA, sbiCA := testpki.NewCA(t, "peer"), testpki.NewCA(t, "sbi")
	peerCert := peerCA.Issue(t, []string{peerFQDN}, testpki.Both, time.Now().Add(time.Hour))
	sbiCert := sbiCA.Issue(t, []string{peerFQDN}, testpki.Both, time.Now().Add(time.Hour))
	for name, tc := range map[string]struct {
		cert tls.Certificate
		ok   bool
	}{"partner cert": {peerCert, true}, "SBI-CA cert for the same SAN": {sbiCert, false}} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			srv.EnableHTTP2 = true
			srv.TLS = &tls.Config{Certificates: []tls.Certificate{tc.cert}}
			srv.StartTLS()
			defer srv.Close()
			c2, _ := trustCfg(t, dir, localFQDN)
			addPartner(t, c2, dir, peerCA, srv.Listener.Addr().String())
			tl, err := LoadN32TLS(c2, nil)
			if err != nil {
				t.Fatal(err)
			}
			base := &http.Client{Transport: &http2.Transport{TLSClientConfig: tl.ClientTLSConfig()}}
			c, err := NewPeerIdentityClient(base, c2.Initiators())
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Get("https://" + srv.Listener.Addr().String() + "/")
			if tc.ok {
				if err != nil {
					t.Fatalf("partner rejected: %v", err)
				}
				resp.Body.Close()
				return
			}
			if err == nil {
				resp.Body.Close()
				t.Fatal("SBI-CA-signed server cert accepted")
			}
			if !isCertIdentityError(err) {
				t.Fatalf("not classified as non-retryable identity error: %v", err)
			}
		})
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }
