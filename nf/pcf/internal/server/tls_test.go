package server

// tls_test.go - the SBI listener is mTLS: sbi.tls.ca_file is the client CA pool
// and a client certificate is required. Also the SM policy API's resource-type
// guard on the shared policies map.
// Ref: TS 33.501 §13.1, TS 29.500 §4.4.2; TS 29.512 §4.2.5.2.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCA is a throw-away CA able to sign leaf certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf signs a certificate usable for both server and client authentication.
func (c *testCA) leaf(t *testing.T, cn string) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair, certPEM, keyPEM
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadTLSConfig_RequiresClientCertificate: a client without a certificate
// (or with one from another CA) is rejected at the handshake; a client with a
// certificate signed by ca_file succeeds.
func TestLoadTLSConfig_RequiresClientCertificate(t *testing.T) {
	ca := newTestCA(t, "pcf-test-ca")
	other := newTestCA(t, "other-ca")
	_, srvCertPEM, srvKeyPEM := ca.leaf(t, "pcf")
	goodClient, _, _ := ca.leaf(t, "amf")
	foreignClient, _, _ := other.leaf(t, "rogue")

	dir := t.TempDir()
	cfg, err := loadTLSConfig(
		writeFile(t, dir, "pcf.crt", srvCertPEM),
		writeFile(t, dir, "pcf.key", srvKeyPEM),
		writeFile(t, dir, "ca.crt", ca.pem))
	if err != nil {
		t.Fatalf("loadTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.ClientCAs == nil {
		t.Fatalf("ClientAuth=%v ClientCAs=%v", cfg.ClientAuth, cfg.ClientCAs)
	}
	if cfg.MinVersion != tls.VersionTLS13 || len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h2" {
		t.Errorf("MinVersion=%x NextProtos=%v", cfg.MinVersion, cfg.NextProtos)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(ca.pem)
	get := func(certs ...tls.Certificate) (int, error) {
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS13, Certificates: certs},
			DisableKeepAlives: true,
		}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(srv.URL)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := get(); err == nil {
		t.Errorf("client without certificate accepted (status %d)", code)
	}
	if code, err := get(foreignClient); err == nil {
		t.Errorf("client certificate of an unrelated CA accepted (status %d)", code)
	}
	if code, err := get(goodClient); err != nil || code != http.StatusOK {
		t.Errorf("CA-signed client certificate: status %d err %v", code, err)
	}
}

// TestLoadTLSConfig_CAErrors: an unreadable or non-PEM ca_file is an error
// (never a silently empty client CA pool).
func TestLoadTLSConfig_CAErrors(t *testing.T) {
	ca := newTestCA(t, "pcf-test-ca")
	_, certPEM, keyPEM := ca.leaf(t, "pcf")
	dir := t.TempDir()
	cert := writeFile(t, dir, "pcf.crt", certPEM)
	key := writeFile(t, dir, "pcf.key", keyPEM)
	for _, tc := range []struct{ name, caFile string }{
		{"missing", filepath.Join(dir, "absent.crt")},
		{"empty path", ""},
		{"not PEM", writeFile(t, dir, "junk.crt", []byte("not a certificate"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadTLSConfig(cert, key, tc.caFile); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// TestSmPolicyDelete_DoesNotDeleteUEPolicy: the SM policy delete operation only
// removes SM policies; a UE policy association id answers 404 and the record
// (and its negotiated features) survive. Same for the SM update operation.
// Ref: TS 29.512 §4.2.5.2, §4.2.3.
func TestSmPolicyDelete_DoesNotDeleteUEPolicy(t *testing.T) {
	s := newTestPCF(t)
	ue := serve(s, http.MethodPost, "/npcf-ue-policy-control/v1/policies", `{"supi":"imsi-001010000000001"}`)
	if ue.Code != http.StatusCreated {
		t.Fatalf("UE create: %d %s", ue.Code, ue.Body.String())
	}
	id := lastSegment(ue.Header().Get("Location"))

	d := serve(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+id+"/delete", "")
	if d.Code != http.StatusNotFound || problemCause(t, d) != "POLICY_ASSOCIATION_NOT_FOUND" {
		t.Errorf("SM delete of a UE policy id: %d %s", d.Code, d.Body.String())
	}
	u := serve(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+id+"/update", `{}`)
	if u.Code != http.StatusNotFound {
		t.Errorf("SM update of a UE policy id: %d %s", u.Code, u.Body.String())
	}
	if !smPolicyStored(s, id) {
		t.Fatal("UE policy association removed through the SM policy API")
	}
	// The UE policy API still deletes it.
	if w := serve(s, http.MethodDelete, "/npcf-ue-policy-control/v1/policies/"+id, ""); w.Code != http.StatusNoContent {
		t.Errorf("UE delete: %d", w.Code)
	}
	// And an SM policy is not deletable through the UE API.
	sm := createSmPolicyID(t, s)
	if w := serve(s, http.MethodDelete, "/npcf-ue-policy-control/v1/policies/"+sm, ""); w.Code != http.StatusNotFound {
		t.Errorf("UE delete of an SM policy id: %d", w.Code)
	}
	if w := serve(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+sm+"/delete", ""); w.Code != http.StatusNoContent {
		t.Errorf("SM delete of an SM policy: %d", w.Code)
	}
}
