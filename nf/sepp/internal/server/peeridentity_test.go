package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
)

// tlsPeer starts an HTTP/2 TLS server whose certificate carries dnsSAN and
// 127.0.0.1, signed by a throwaway CA; it returns the server and the CA pool.
func tlsPeer(t *testing.T, dnsSAN string) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsSAN},
		DNSNames: []string{dnsSAN}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return srv, pool
}

func TestPeerIdentityClientVerifiesFQDN(t *testing.T) {
	const fqdn = "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
	tests := []struct {
		name    string
		san     string
		wantErr bool
	}{
		{"SAN matches peers[].fqdn", fqdn, false},
		{"SAN differs from peers[].fqdn", "other.example.org", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, pool := tlsPeer(t, tc.san)
			base := &http.Client{Transport: &http2.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
			addr := srv.Listener.Addr().String() // dialled by IP: only ServerName can match the SAN
			c, err := NewPeerIdentityClient(base, []config.N32Peer{{FQDN: fqdn, Address: addr}})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Get("https://" + addr + "/")
			if tc.wantErr {
				if err == nil {
					resp.Body.Close()
					t.Fatal("expected certificate identity rejection")
				}
				if !isCertIdentityError(err) {
					t.Fatalf("error not classified as identity error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("matching SAN rejected: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status %d", resp.StatusCode)
			}
		})
	}
}

func TestPeerIdentityClientRejectsBadBase(t *testing.T) {
	if _, err := NewPeerIdentityClient(&http.Client{}, nil); err == nil {
		t.Fatal("expected error for non-http2 base transport")
	}
}

func TestIsCertIdentityError(t *testing.T) {
	if !isCertIdentityError(fmt.Errorf("send: %w", &tls.CertificateVerificationError{Err: x509.HostnameError{Host: "x"}})) {
		t.Fatal("wrapped verification error not detected")
	}
	if isCertIdentityError(errors.New("dial tcp: refused")) {
		t.Fatal("plain error misclassified")
	}
}

func TestInitiatorStopsOnCertIdentityError(t *testing.T) {
	s, peers := initiatorServer(t)
	ex := &fakeEx{errs: []error{fmt.Errorf("n32c: exchange: send: %w", &tls.CertificateVerificationError{Err: x509.HostnameError{Host: "x"}})}}
	s.runInitiator(t.Context(), ex, peers, fastTiming)()
	if ex.calls != 1 {
		t.Fatalf("identity error retried: calls=%d", ex.calls)
	}
}
