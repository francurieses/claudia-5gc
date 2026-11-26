package n32trust

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32trust/testpki"
)

const (
	fqdnA = "sepp.5gc.mnc001.mcc001.3gppnetwork.org" // local core, PLMN 001/01
	fqdnB = "sepp.5gc.mnc002.mcc001.3gppnetwork.org" // partner B, PLMN 001/02
	fqdnC = "sepp.5gc.mnc003.mcc001.3gppnetwork.org" // partner C, PLMN 001/03
)

var (
	plmnA = config.PLMN{MCC: "001", MNC: "01"}
	plmnB = config.PLMN{MCC: "001", MNC: "02"}
	plmnC = config.PLMN{MCC: "001", MNC: "03"}
)

func future() time.Time { return time.Now().Add(time.Hour) }

func partner(t *testing.T, dir string, p config.PLMN, ca *testpki.CA) config.Partner {
	t.Helper()
	return config.Partner{PLMN: p, N32: config.PartnerN32{CAFile: testpki.WriteFile(t, dir, "ca-"+p.Key()+".crt", ca.PEM)}}
}

func discard() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func counter(reason string) float64 { return testutil.ToFloat64(rejectTotal.WithLabelValues(reason)) }

func TestPLMNsFromCert(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	c := ca.Issue(t, []string{fqdnB, "*." + fqdnB, "other.example.org", "SEPP.5GC.MNC003.MCC001.3GPPNETWORK.ORG"}, testpki.Both, future())
	got := PLMNsFromCert(c.Leaf)
	if len(got) != 2 || got[0].Key() != "001-002" || got[1].Key() != "001-003" {
		t.Fatalf("plmns=%v (wildcard/duplicates must collapse, case-insensitive)", got)
	}
	if n := len(PLMNsFromCert(ca.Issue(t, []string{"a.example.org"}, testpki.Both, future()).Leaf)); n != 0 {
		t.Fatalf("non-3gpp SAN gave %d PLMNs", n)
	}
}

func TestVerifierRejectReasons(t *testing.T) {
	dir := t.TempDir()
	caB, caC, sbiCA := testpki.NewCA(t, "n32-B"), testpki.NewCA(t, "n32-C"), testpki.NewCA(t, "sbi")
	v, err := NewVerifier([]config.Partner{partner(t, dir, plmnB, caB), partner(t, dir, plmnC, caC)}, discard())
	if err != nil {
		t.Fatal(err)
	}
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	clientAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	cs := func(c tls.Certificate, name string) tls.ConnectionState {
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{c.Leaf}, ServerName: name}
	}
	tests := []struct {
		name   string
		client bool // true: VerifyServer, false: VerifyClient
		cert   tls.Certificate
		dialed string
		reason string // "" = accepted
	}{
		{"server side ok", false, caB.Issue(t, []string{fqdnB, "*." + fqdnB}, testpki.Both, future()), "", ""},
		{"server side: no PLMN SAN", false, caB.Issue(t, []string{"sepp.example.org"}, testpki.Both, future()), "", ReasonNoPLMN},
		{"server side: PLMN is not a partner", false, caB.Issue(t, []string{"sepp.5gc.mnc009.mcc001.3gppnetwork.org"}, testpki.Both, future()), "", ReasonNotPartner},
		{"server side: SAN PLMNs with different anchors", false, caB.Issue(t, []string{fqdnB, fqdnC}, testpki.Both, future()), "", ReasonAnchorConflict},
		{"PLMN B cert on PLMN C anchor (signed by the wrong N32 CA)", false, caB.Issue(t, []string{fqdnC}, testpki.Both, future()), "", ReasonChain},
		{"cert of PLMN B signed by the SBI CA", false, sbiCA.Issue(t, []string{fqdnB}, testpki.Both, future()), "", ReasonChain},
		{"expired cert", false, caB.Issue(t, []string{fqdnB}, testpki.Both, time.Now().Add(-time.Minute)), "", ReasonChain},
		{"server side: serverAuth-only cert lacks clientAuth", false, caB.Issue(t, []string{fqdnB}, serverAuth, future()), "", ReasonChain},
		{"client side ok", true, caB.Issue(t, []string{fqdnB, "*." + fqdnB}, testpki.Both, future()), fqdnB, ""},
		{"client side: clientAuth-only cert lacks serverAuth", true, caB.Issue(t, []string{fqdnB}, clientAuth, future()), fqdnB, ReasonChain},
		{"client side: SBI-CA cert", true, sbiCA.Issue(t, []string{fqdnB}, testpki.Both, future()), fqdnB, ReasonChain},
		{"client side: valid partner C cert while dialling B", true, caC.Issue(t, []string{fqdnC}, testpki.Both, future()), fqdnB, ReasonPLMNMismatch},
		{"client side: SAN does not cover the partner FQDN", true, caB.Issue(t, []string{"other." + fqdnB}, testpki.Both, future()), fqdnB, ReasonPLMNMismatch},
		{"client side: dialled name is no partner", true, caB.Issue(t, []string{fqdnB}, testpki.Both, future()), "sepp.example.org", ReasonNotPartner},
		{"client side: no PLMN SAN", true, caB.Issue(t, []string{"sepp.example.org"}, testpki.Both, future()), fqdnB, ReasonNoPLMN},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := map[string]float64{}
			for _, r := range []string{ReasonNoPLMN, ReasonNotPartner, ReasonAnchorConflict, ReasonChain, ReasonPLMNMismatch} {
				before[r] = counter(r)
			}
			var err error
			if tc.client {
				err = v.VerifyServer(cs(tc.cert, tc.dialed))
			} else {
				err = v.VerifyClient(cs(tc.cert, ""))
			}
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			var rj *RejectError
			if !errors.As(err, &rj) || rj.Reason != tc.reason {
				t.Fatalf("err=%v want reason %s", err, tc.reason)
			}
			if got := counter(tc.reason) - before[tc.reason]; got != 1 {
				t.Fatalf("metric delta %v for %s", got, tc.reason)
			}
		})
	}
}

func TestRejectLogLine(t *testing.T) {
	var buf bytes.Buffer
	caB, sbiCA := testpki.NewCA(t, "B"), testpki.NewCA(t, "sbi")
	v, err := NewVerifier([]config.Partner{partner(t, t.TempDir(), plmnB, caB)}, slog.New(slog.NewJSONHandler(&buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c := sbiCA.Issue(t, []string{fqdnB}, testpki.Both, future())
	_ = v.VerifyClient(tls.ConnectionState{PeerCertificates: []*x509.Certificate{c.Leaf}})
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log not JSON: %q", buf.String())
	}
	for k, want := range map[string]string{"nf": "SEPP", "procedure": "N32Handshake", "interface": "N32c", "direction": "IN",
		"cause": "n32_tls_chain", "result": "REJECT", "spec_ref": "TS 33.501 §13.1.2"} {
		if rec[k] != want {
			t.Errorf("%s=%v want %s", k, rec[k], want)
		}
	}
	if rec["correlation_id"] == nil || rec["level"] != "WARN" {
		t.Errorf("missing correlation_id / level: %v", rec)
	}
}

func TestNewVerifierErrors(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "ca")
	p := func(file string) []config.Partner {
		return []config.Partner{{PLMN: plmnB, N32: config.PartnerN32{CAFile: file}}}
	}
	if _, err := NewVerifier(p(dir+"/missing.crt"), nil); err == nil {
		t.Error("unreadable ca_file accepted")
	}
	if _, err := NewVerifier(p(testpki.WriteFile(t, dir, "bad.crt", []byte("not pem"))), nil); err == nil {
		t.Error("ca_file without certificate accepted")
	}
	sbi := testpki.WriteFile(t, dir, "sbi-ca.crt", ca.PEM)
	_, err := NewVerifier(p(sbi), nil, sbi)
	if err == nil || !strings.Contains(err.Error(), "SBI CA") {
		t.Errorf("SBI CA as N32 anchor accepted: %v", err)
	}
	v, err := NewVerifier(p(sbi), nil, dir+"/no-such-sbi-ca")
	if err != nil || len(v.Anchors()) != 1 || v.Anchors()[0].Subject != "CN=ca" {
		t.Errorf("anchor info: %v %+v", err, v)
	}
}

func TestLoadLocalCert(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "ca")
	good := ca.Issue(t, []string{"*.5gc.mnc001.mcc001.3gppnetwork.org"}, testpki.Both, future())
	gc, gk := testpki.WriteCert(t, dir, "good", good)
	if _, err := LoadLocalCert(gc, gk, fqdnA); err != nil {
		t.Errorf("wildcard SAN covering the FQDN rejected: %v", err)
	}
	bad := ca.Issue(t, []string{fqdnB}, testpki.Both, future())
	bc, bk := testpki.WriteCert(t, dir, "bad", bad)
	if _, err := LoadLocalCert(bc, bk, fqdnA); err == nil || errors.Is(err, ErrNoLocalCert) {
		t.Errorf("SAN naming another SEPP accepted or misclassified: %v", err)
	}
	if _, err := LoadLocalCert(dir+"/none.crt", dir+"/none.key", fqdnA); !errors.Is(err, ErrNoLocalCert) {
		t.Errorf("missing cert: %v", err)
	}
	if _, err := LoadLocalCert(gc, bk, fqdnA); err == nil || errors.Is(err, ErrNoLocalCert) {
		t.Errorf("mismatching key accepted: %v", err)
	}
}

// handshake runs a real TLS handshake: server (cfg s) on loopback, client dials
// with ServerName name. It returns the server-side and client-side errors (the
// client reads a byte so a TLS 1.3 post-handshake client-cert rejection surfaces).
func handshake(t *testing.T, s, c *tls.Config, name string) (serverErr, clientErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		sc := tls.Server(conn, s)
		_ = sc.SetDeadline(time.Now().Add(5 * time.Second))
		if err := sc.Handshake(); err != nil {
			done <- err
			return
		}
		_, _ = sc.Write([]byte("x"))
		done <- nil
	}()
	cc := c.Clone()
	cc.ServerName = name
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := tls.Client(conn, cc)
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	clientErr = tc.Handshake()
	if clientErr == nil {
		_, clientErr = tc.Read(make([]byte, 1))
	}
	return <-done, clientErr
}

func TestRealHandshakes(t *testing.T) {
	dir := t.TempDir()
	caA, caB, caX, sbiCA := testpki.NewCA(t, "A"), testpki.NewCA(t, "B"), testpki.NewCA(t, "X"), testpki.NewCA(t, "sbi")
	certA := caA.Issue(t, []string{fqdnA, "*." + fqdnA}, testpki.Both, future())
	certB := caB.Issue(t, []string{fqdnB, "*." + fqdnB}, testpki.Both, future())
	vA, err := NewVerifier([]config.Partner{partner(t, dir, plmnB, caB)}, discard()) // local core A trusts partner B
	if err != nil {
		t.Fatal(err)
	}
	vB, err := NewVerifier([]config.Partner{partner(t, dir, plmnA, caA)}, discard()) // partner B trusts A
	if err != nil {
		t.Fatal(err)
	}
	vNone, err := NewVerifier(nil, discard())
	if err != nil {
		t.Fatal(err)
	}
	vWrong, err := NewVerifier([]config.Partner{partner(t, dir, plmnB, caX)}, discard()) // B anchored on the wrong CA
	if err != nil {
		t.Fatal(err)
	}
	for _, minV := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		maxV := minV
		pin := func(c *tls.Config) *tls.Config { c.MaxVersion = maxV; return c }
		t.Run(tls.VersionName(minV), func(t *testing.T) {
			if se, ce := handshake(t, pin(vA.ServerTLSConfig(certA, minV, nil)), pin(vB.ClientTLSConfig(certB, minV, nil)), fqdnA); se != nil || ce != nil {
				t.Fatalf("happy path A<-B: server=%v client=%v", se, ce)
			}
			if se, ce := handshake(t, pin(vB.ServerTLSConfig(certB, minV, nil)), pin(vA.ClientTLSConfig(certA, minV, nil)), fqdnB); se != nil || ce != nil {
				t.Fatalf("happy path B<-A: server=%v client=%v", se, ce)
			}
			// No partner at all: listener is ready but every handshake is rejected.
			if se, ce := handshake(t, pin(vNone.ServerTLSConfig(certA, minV, nil)), pin(vB.ClientTLSConfig(certB, minV, nil)), fqdnA); se == nil || ce == nil {
				t.Fatalf("no partners must reject: server=%v client=%v", se, ce)
			}
			// PLMN B certificate presented to an anchor that is not B's CA.
			if se, ce := handshake(t, pin(vWrong.ServerTLSConfig(certA, minV, nil)), pin(vB.ClientTLSConfig(certB, minV, nil)), fqdnA); se == nil || ce == nil {
				t.Fatalf("PLMN B cert on a foreign anchor accepted: server=%v client=%v", se, ce)
			}
			// SBI-CA-signed certificate naming PLMN B.
			sbiB := sbiCA.Issue(t, []string{fqdnB}, testpki.Both, future())
			if se, ce := handshake(t, pin(vA.ServerTLSConfig(certA, minV, nil)), pin(vB.ClientTLSConfig(sbiB, minV, nil)), fqdnA); se == nil || ce == nil {
				t.Fatalf("SBI CA cert accepted by the server: server=%v client=%v", se, ce)
			}
			// Server presents an SBI-CA cert: the client verifier rejects it.
			sbiA := sbiCA.Issue(t, []string{fqdnA}, testpki.Both, future())
			if _, ce := handshake(t, pin(vA.ServerTLSConfig(sbiA, minV, nil)), pin(vB.ClientTLSConfig(certB, minV, nil)), fqdnA); ce == nil {
				t.Fatal("SBI CA server cert accepted by the client")
			}
			// Client without a certificate.
			noCert := &tls.Config{InsecureSkipVerify: true, MinVersion: minV, MaxVersion: maxV} //nolint:gosec // test client
			if se, ce := handshake(t, pin(vA.ServerTLSConfig(certA, minV, nil)), noCert, fqdnA); se == nil || ce == nil {
				t.Fatalf("client without certificate accepted: server=%v client=%v", se, ce)
			}
		})
	}
}

func TestPLMNsFromCertLabelBoundary(t *testing.T) {
	c := &x509.Certificate{DNSNames: []string{"xmnc001.mcc001.3gppnetwork.org", "sepp.mnc002.mcc001.3gppnetwork.org."}}
	got := PLMNsFromCert(c)
	if len(got) != 1 || got[0].MNC != "002" {
		t.Fatalf("got %v", got)
	}
}

func TestNewVerifierEmptyCAFile(t *testing.T) {
	if _, err := NewVerifier([]config.Partner{{}}, nil); err == nil {
		t.Fatal("empty ca_file accepted")
	}
}
