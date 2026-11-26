// Package n32trust implements the per-PLMN N32 trust model of the SEPP: every
// roaming partner PLMN has its own trust-anchor pool, the peer PLMN is read
// from the certificate SAN, and a certificate is accepted only if it chains to
// the anchor of the PLMN it names. The core-internal SBI CA is never in any
// pool. It uses crypto/x509 and crypto/tls only (never shared/crypto).
//
// Server side: tls.Config{ClientAuth: RequireAnyClientCert} + VerifyConnection.
// Client side: InsecureSkipVerify + VerifyConnection (the manual x509.Verify,
// the SAN/FQDN check and the dialled-PLMN check replace the stock verifier).
//
// Ref: TS 33.501 §13.1.2 (mutual authentication, PLMN from certificate),
// TS 33.210 §6.2, TS 23.003 §28.5.1/§28.5.2 (3gppnetwork.org FQDNs).
package n32trust

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

// Reject reasons: the bounded label set of fivegc_sepp_n32_tls_reject_total.
const (
	// ReasonNoPLMN: the peer leaf names no PLMN in its SAN.
	ReasonNoPLMN = "no_plmn"
	// ReasonNotPartner: a SAN PLMN (or the dialled name) is not a partner.
	ReasonNotPartner = "not_partner"
	// ReasonAnchorConflict: the SAN PLMNs map to different trust anchors.
	ReasonAnchorConflict = "anchor_conflict"
	// ReasonChain: the chain does not verify against the partner anchor.
	ReasonChain = "chain"
	// ReasonPLMNMismatch: client side, the server PLMN/SAN is not the dialled partner.
	ReasonPLMNMismatch = "plmn_mismatch"

	// causeNoClientCert is the log-only cause of a peer without a client
	// certificate (E6); it is not a metric reason (the label set is bounded).
	causeNoClientCert = "n32_tls_no_client_cert"

	procedure = "N32Handshake"
	specRef   = "TS 33.501 §13.1.2"
	maxLogSAN = 8
)

var (
	// plmnSAN extracts the PLMN of a 3gppnetwork.org FQDN (TS 23.003 §28.5.1).
	plmnSAN = regexp.MustCompile(`(?i)(^|\.)mnc(\d{3})\.mcc(\d{3})\.3gppnetwork\.org\.?$`)

	rejectTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_sepp_n32_tls_reject_total",
		Help: "N32 TLS peers rejected by the per-PLMN trust verification, by reason (no_plmn|not_partner|anchor_conflict|chain|plmn_mismatch) (TS 33.501 §13.1.2).",
	}, []string{"reason"})

	// ErrNoLocalCert is wrapped by LoadLocalCert when the cert or key file is absent.
	ErrNoLocalCert = errors.New("n32trust: local N32 certificate not found")
)

func init() {
	for _, r := range []string{ReasonNoPLMN, ReasonNotPartner, ReasonAnchorConflict, ReasonChain, ReasonPLMNMismatch} {
		rejectTotal.WithLabelValues(r)
	}
}

// RejectError is a TLS peer rejected by the verifier.
type RejectError struct {
	// Reason is one of the Reason* constants.
	Reason string
	Detail string
}

// Error implements error.
func (e *RejectError) Error() string {
	return "n32trust: peer certificate rejected (" + e.Reason + "): " + e.Detail
}

// PLMNsFromCert returns the PLMNs named by the SAN DNS names of c that match
// mnc<3>.mcc<3>.3gppnetwork.org, deduplicated, MNC always three digits.
func PLMNsFromCert(c *x509.Certificate) []config.PLMN {
	seen := map[string]bool{}
	var out []config.PLMN
	for _, n := range c.DNSNames {
		if m := plmnSAN.FindStringSubmatch(n); m != nil {
			p := config.PLMN{MCC: m[3], MNC: m[2]}
			if !seen[p.Key()] {
				seen[p.Key()] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// plmnOfName parses the PLMN of an FQDN (dialled name).
func plmnOfName(name string) (config.PLMN, bool) {
	m := plmnSAN.FindStringSubmatch(name)
	if m == nil {
		return config.PLMN{}, false
	}
	return config.PLMN{MCC: m[3], MNC: m[2]}, true
}

type anchor struct {
	id       string // hash of the sorted DER of the bundle
	pool     *x509.CertPool
	caFile   string
	subject  string
	notAfter time.Time
}

// AnchorInfo describes the trust anchor of one partner (admin view).
type AnchorInfo struct {
	PLMN     string // "mcc-mnc" as configured
	CAFile   string
	Subject  string
	NotAfter time.Time
}

// Verifier verifies N32 peer certificates against the per-PLMN anchors.
type Verifier struct {
	logger   *slog.Logger
	anchors  map[string]*anchor        // by PLMN key
	partners map[string]config.Partner // by PLMN key
	byFQDN   map[string]config.Partner // by lower-case SEPP FQDN
	info     []AnchorInfo
	now      func() time.Time
}

// NewVerifier loads the anchor bundle of every partner (ca_file). It fails
// when a bundle is unreadable/empty or contains a certificate of any file in
// forbiddenCAFiles (the SBI CA must never become an N32 anchor).
func NewVerifier(partners []config.Partner, logger *slog.Logger, forbiddenCAFiles ...string) (*Verifier, error) {
	if logger == nil {
		logger = slog.Default()
	}
	forbidden := map[string]bool{}
	for _, f := range forbiddenCAFiles {
		if f == "" {
			continue
		}
		data, err := os.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			logger.Warn("forbidden SBI CA file not found: nothing to exclude from the N32 anchors",
				"nf", "SEPP", "path", f, "spec_ref", specRef)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("n32trust: read SBI CA file %q: %w", f, err)
		}
		certs, err := parseBundle(data)
		if err != nil {
			return nil, fmt.Errorf("n32trust: parse SBI CA file %q: %w", f, err)
		}
		for _, c := range certs {
			forbidden[string(c.Raw)] = true
		}
	}
	v := &Verifier{logger: logger, anchors: map[string]*anchor{}, partners: map[string]config.Partner{},
		byFQDN: map[string]config.Partner{}, now: time.Now}
	for _, p := range partners {
		if p.N32.CAFile == "" {
			return nil, fmt.Errorf("n32trust: partner %s: n32.ca_file is empty: every N32 partner needs its own trust anchor", p.PLMN)
		}
		data, err := os.ReadFile(p.N32.CAFile)
		if err != nil {
			return nil, fmt.Errorf("n32trust: partner %s: read ca_file: %w", p.PLMN, err)
		}
		certs, err := parseBundle(data)
		if err != nil {
			return nil, fmt.Errorf("n32trust: partner %s: ca_file %q: %w", p.PLMN, p.N32.CAFile, err)
		}
		a := &anchor{pool: x509.NewCertPool(), caFile: p.N32.CAFile}
		raws := make([]string, 0, len(certs))
		for i, c := range certs {
			if forbidden[string(c.Raw)] {
				return nil, fmt.Errorf("n32trust: partner %s: ca_file %q contains the SBI CA: N32 never trusts the core-internal CA", p.PLMN, p.N32.CAFile)
			}
			a.pool.AddCert(c)
			raws = append(raws, string(c.Raw))
			if i == 0 || c.NotAfter.Before(a.notAfter) {
				a.notAfter, a.subject = c.NotAfter, c.Subject.String()
			}
		}
		sort.Strings(raws)
		h := sha256.New()
		for _, r := range raws {
			h.Write([]byte(r))
		}
		a.id = fmt.Sprintf("%x", h.Sum(nil))
		v.anchors[p.PLMN.Key()] = a
		v.partners[p.PLMN.Key()] = p
		v.byFQDN[strings.ToLower(p.FQDN())] = p
		v.info = append(v.info, AnchorInfo{PLMN: p.PLMN.String(), CAFile: a.caFile, Subject: a.subject, NotAfter: a.notAfter})
	}
	return v, nil
}

func parseBundle(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate found")
	}
	return out, nil
}

// Anchors returns the loaded anchors (nil-safe).
func (v *Verifier) Anchors() []AnchorInfo {
	if v == nil {
		return nil
	}
	return append([]AnchorInfo(nil), v.info...)
}

// ServerTLSConfig returns the N32 listener TLS config: any client certificate
// is requested and verified by VerifyClient (no ClientCAs: a shared pool would
// defeat the per-PLMN anchors). NextProtos is set before http2.ConfigureServer.
func (v *Verifier) ServerTLSConfig(cert tls.Certificate, minVersion uint16, keyLog io.Writer) *tls.Config {
	base := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// RequestClientCert (not RequireAnyClientCert): Go would abort a
		// certificate-less handshake before VerifyConnection, so the reject
		// would be neither logged nor attributable (E6). VerifyClient enforces
		// the presence of the certificate.
		ClientAuth:       tls.RequestClientCert,
		MinVersion:       minVersion,
		NextProtos:       []string{"h2"},
		VerifyConnection: func(cs tls.ConnectionState) error { return v.verifyClient(cs, "") },
		KeyLogWriter:     keyLog,
	}
	// A per-connection clone carries the remote address into the reject log.
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.GetConfigForClient = nil
		if hello.Conn != nil {
			addr := hello.Conn.RemoteAddr().String()
			c.VerifyConnection = func(cs tls.ConnectionState) error { return v.verifyClient(cs, addr) }
		}
		return c, nil
	}
	return base
}

// ClientTLSConfig returns the N32 client TLS config (N32-c initiator, N32-f
// outbound). The stock verification is disabled and replaced by VerifyServer,
// which reads the dialled name from the ServerName set per connection.
func (v *Verifier) ClientTLSConfig(cert tls.Certificate, minVersion uint16, keyLog io.Writer) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         minVersion,
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection (per-PLMN anchors)
		VerifyConnection:   v.VerifyServer,
		KeyLogWriter:       keyLog,
	}
}

// VerifyClient is the server-side VerifyConnection: the peer is the initiator
// and must present a clientAuth certificate of a partner PLMN.
func (v *Verifier) VerifyClient(cs tls.ConnectionState) error { return v.verifyClient(cs, "") }

func (v *Verifier) verifyClient(cs tls.ConnectionState, remote string) error {
	if v == nil {
		return errors.New("n32trust: no verifier configured")
	}
	if len(cs.PeerCertificates) == 0 {
		return v.reportNoClientCert(remote)
	}
	_, err := v.check(cs, x509.ExtKeyUsageClientAuth, nil)
	return v.report(cs, "IN", remote, err)
}

// reportNoClientCert logs the E6 reject (peer without a client certificate).
// The bounded metric label set is deliberately not extended.
func (v *Verifier) reportNoClientCert(remote string) error {
	ctx := logging.WithCorrelationID(context.Background(), "")
	logging.NewProcedureLogger(ctx, v.logger, procedure).WarnContext(ctx, "n32 tls peer rejected",
		"nf", "SEPP", "interface", "N32c", "direction", "IN", "result", "REJECT",
		"cause", causeNoClientCert, "peer_addr", remote, "detail", "no client certificate", "spec_ref", specRef)
	return errors.New("n32trust: peer presented no client certificate")
}

// CountReject increments fivegc_sepp_n32_tls_reject_total for one of the
// bounded Reason* values (used by the N32-f context cross-check).
func CountReject(reason string) { rejectTotal.WithLabelValues(reason).Inc() }

// VerifyServer is the client-side VerifyConnection: the peer must present a
// serverAuth certificate of the dialled partner (cs.ServerName), whose SAN
// covers that name.
func (v *Verifier) VerifyServer(cs tls.ConnectionState) error {
	if v == nil {
		return errors.New("n32trust: no verifier configured")
	}
	dialled, ok := v.byFQDN[strings.ToLower(cs.ServerName)]
	if !ok {
		if p, found := plmnOfName(cs.ServerName); found {
			dialled, ok = v.partners[p.Key()]
		}
	}
	if !ok {
		return v.report(cs, "OUT", cs.ServerName, &RejectError{ReasonNotPartner, "dialled name " + cs.ServerName + " is not a partner SEPP"})
	}
	// The server PLMN set must contain the dialled partner before any anchor
	// lookup: a server of another PLMN is a plmn_mismatch (E5).
	if len(cs.PeerCertificates) > 0 {
		set := PLMNsFromCert(cs.PeerCertificates[0])
		inSet := false
		for _, p := range set {
			inSet = inSet || p.Key() == dialled.PLMN.Key()
		}
		if !inSet && len(set) > 0 {
			return v.report(cs, "OUT", cs.ServerName, &RejectError{ReasonPLMNMismatch, "server PLMN is not the dialled partner " + dialled.PLMN.String()})
		}
	}
	_, err := v.check(cs, x509.ExtKeyUsageServerAuth, &dialled)
	return v.report(cs, "OUT", cs.ServerName, err)
}

func (v *Verifier) check(cs tls.ConnectionState, eku x509.ExtKeyUsage, dialled *config.Partner) (*anchor, *RejectError) {
	if v == nil {
		return nil, &RejectError{ReasonNotPartner, "no verifier configured"}
	}
	if len(cs.PeerCertificates) == 0 {
		return nil, &RejectError{ReasonNoPLMN, "no peer certificate"}
	}
	leaf := cs.PeerCertificates[0]
	plmns := PLMNsFromCert(leaf)
	if len(plmns) == 0 {
		return nil, &RejectError{ReasonNoPLMN, "no SAN of the form mncXXX.mccYYY.3gppnetwork.org"}
	}
	var a *anchor
	for _, p := range plmns {
		pa, ok := v.anchors[p.Key()]
		if !ok {
			return nil, &RejectError{ReasonNotPartner, "PLMN " + p.String() + " is not a roaming partner"}
		}
		if a != nil && a.id != pa.id {
			return nil, &RejectError{ReasonAnchorConflict, "SAN PLMNs map to different trust anchors"}
		}
		a = pa
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: a.pool, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{eku}, CurrentTime: v.now()}); err != nil {
		return nil, &RejectError{ReasonChain, err.Error()}
	}
	if dialled != nil {
		inSet := false
		for _, p := range plmns {
			if p.Key() == dialled.PLMN.Key() {
				inSet = true
			}
		}
		if !inSet {
			return nil, &RejectError{ReasonPLMNMismatch, "server PLMN is not the dialled partner " + dialled.PLMN.String()}
		}
		if err := leaf.VerifyHostname(dialled.FQDN()); err != nil {
			return nil, &RejectError{ReasonPLMNMismatch, "SAN does not cover partner SEPP FQDN " + dialled.FQDN()}
		}
		if err := leaf.VerifyHostname(cs.ServerName); err != nil {
			return nil, &RejectError{ReasonPLMNMismatch, "SAN does not cover dialled name " + cs.ServerName}
		}
	}
	return a, nil
}

// report counts and logs a rejection and returns it as an error (nil stays nil).
// peer is the remote address (server side) or the dialled name (client side);
// the TLS callbacks carry no request context, so the correlation id is a fresh one.
func (v *Verifier) report(cs tls.ConnectionState, direction, peer string, rej *RejectError) error {
	if rej == nil {
		return nil
	}
	rejectTotal.WithLabelValues(rej.Reason).Inc()
	var sans []string
	if len(cs.PeerCertificates) > 0 {
		sans = cs.PeerCertificates[0].DNSNames
		if len(sans) > maxLogSAN {
			sans = sans[:maxLogSAN]
		}
	}
	ctx := logging.WithCorrelationID(context.Background(), "")
	logging.NewProcedureLogger(ctx, v.logger, procedure).WarnContext(ctx, "n32 tls peer rejected",
		"nf", "SEPP", "interface", "N32c", "direction", direction, "result", "REJECT",
		"cause", "n32_tls_"+rej.Reason, "peer_addr", peer, "peer_sans", sans, "detail", rej.Detail, "spec_ref", specRef)
	return rej
}

// LoadLocalCert loads the local N32 certificate and checks that its SAN names
// fqdn (the local SEPP FQDN; wildcard SANs count). A missing file wraps
// ErrNoLocalCert; any other failure is a configuration error.
func LoadLocalCert(certFile, keyFile, fqdn string) (tls.Certificate, error) {
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	certMissing, keyMissing := errors.Is(certErr, fs.ErrNotExist), errors.Is(keyErr, fs.ErrNotExist)
	switch {
	case certMissing && keyMissing:
		return tls.Certificate{}, fmt.Errorf("%w: n32.tls.cert_file %s", ErrNoLocalCert, certFile)
	case certMissing:
		return tls.Certificate{}, fmt.Errorf("n32trust: n32.tls.cert_file %q is missing while n32.tls.key_file %q exists", certFile, keyFile)
	case keyMissing:
		return tls.Certificate{}, fmt.Errorf("n32trust: n32.tls.key_file %q is missing while n32.tls.cert_file %q exists", keyFile, certFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("n32trust: load local N32 certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("n32trust: parse local N32 certificate: %w", err)
	}
	if err := leaf.VerifyHostname(fqdn); err != nil {
		return tls.Certificate{}, fmt.Errorf("n32trust: local N32 certificate %q SAN does not name the SEPP FQDN %q: %w", certFile, fqdn, err)
	}
	cert.Leaf = leaf
	return cert, nil
}
