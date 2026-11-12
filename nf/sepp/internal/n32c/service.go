package n32c

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

const (
	// procedureName is the canonical log procedure. Ref: docs/procedures/n32-roaming-interconnect.md "Logging".
	procedureName = "N32cSecurityCapabilityNegotiation"
	// interfaceN32c is the canonical log interface value.
	interfaceN32c = "N32c"
	// featureNFTLST is TS 29.573 Table 6.1.7-1 feature 1 (N32-f TLS termination via NONE).
	featureNFTLST = 1
	// maxBodyBytes bounds the request/response body read.
	maxBodyBytes = 64 << 10
	// exchangeCapabilityPath is the operation path below {apiRoot}/n32c-handshake/{ver}.
	exchangeCapabilityPath = "/exchange-capability"
	// Reasons passed to Terminator.
	reasonTeardown = "teardown"
	reasonReplace  = "replace"
)

// Spec references used in logs. Ref: TS 29.573 §5.2.2 (steps 1, 2a, 2b; no sub-clauses).
const (
	specStep1  = "TS 29.573 §5.2.2 step 1"
	specStep2a = "TS 29.573 §5.2.2 step 2a"
	specStep2b = "TS 29.573 §5.2.2 step 2b"
)

// ErrAbandoned is returned by Exchange when the outgoing request was dropped
// because an incoming request from the same peer won the collision
// (TS 29.573 §5.2.2 step 2b).
var ErrAbandoned = errors.New("n32c: outgoing exchange-capability abandoned after collision")

// PeerIdentity is the authenticated identity of the N32-c peer.
type PeerIdentity struct {
	// FQDN is the verified certificate SAN carrying the Home Network Domain.
	FQDN string
	// PLMN is parsed from the trailing domain of FQDN.
	PLMN PlmnId
}

// CertPeerIdentity derives the peer identity from the verified TLS client
// certificate SAN (TS 33.501 §13.1.2; TS 23.003 §28.5.1). It is the default
// Config.PeerIdentity.
func CertPeerIdentity(r *http.Request) (PeerIdentity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return PeerIdentity{}, errors.New("n32c: peer identity: no client certificate")
	}
	for _, san := range r.TLS.PeerCertificates[0].DNSNames {
		if p, err := ParsePLMNFromFQDN(san); err == nil {
			return PeerIdentity{FQDN: strings.ToLower(san), PLMN: p}, nil
		}
	}
	return PeerIdentity{}, errors.New("n32c: peer identity: no SAN with a 3gppnetwork.org PLMN domain")
}

// CertResponderIdentity derives the responder identity from the verified TLS
// server certificate SAN (TS 33.501 §13.1.2; TS 23.003 §28.5.1).
func CertResponderIdentity(resp *http.Response) (PeerIdentity, error) {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return PeerIdentity{}, errors.New("n32c: responder identity: no server certificate")
	}
	for _, san := range resp.TLS.PeerCertificates[0].DNSNames {
		if p, err := ParsePLMNFromFQDN(san); err == nil {
			return PeerIdentity{FQDN: strings.ToLower(san), PLMN: p}, nil
		}
	}
	return PeerIdentity{}, errors.New("n32c: responder identity: no SAN with a 3gppnetwork.org PLMN domain")
}

// Config configures a Service.
type Config struct {
	LocalPLMN PlmnId
	LocalFQDN string
	// Partners is the roaming-partner list (remote PLMNs accepted).
	Partners []PlmnId
	// Profile is the release profile; nil behaves as Rel-17.
	Profile *capability.Profile
	// TargetAPIRootSupported: local support of 3gpp-Sbi-Target-apiRoot.
	TargetAPIRootSupported bool
	Logger                 *slog.Logger
	// Store is optional; a fresh one is created when nil.
	Store *Store
	// HTTPClient is used by Exchange/Teardown (production: sbi.NewMTLSClient).
	HTTPClient *http.Client
	// PeerIdentity overrides CertPeerIdentity (tests run without TLS).
	PeerIdentity func(*http.Request) (PeerIdentity, error)
	// ResponderIdentity authenticates the responder of an outgoing request
	// from its verified server certificate (default CertResponderIdentity).
	// TS 33.501 §13.1.2.
	ResponderIdentity func(*http.Response) (PeerIdentity, error)
	// Terminator closes the N32-f TLS connections of a remote PLMN.
	// reason is "teardown" or "replace". The N32-c HTTP/2 connection that
	// carried the request is closed by the handler itself (Connection: close,
	// TS 29.573 §5.2.2). Called after the response has been written and
	// flushed; it must not block.
	Terminator func(ctx context.Context, remote PlmnId, reason string)
	Now        func() time.Time
}

// Service is the N32-c exchange-capability responder and initiator.
type Service struct {
	cfg      Config
	store    *Store
	catalog  *features.Catalog
	specLit  bool // Rel-19 profile
	logger   *slog.Logger
	mu       sync.Mutex
	inflight map[uint64]*inflightReq
	nextTok  uint64
}

type inflightReq struct {
	plmn      string
	localFQDN string
	cancel    context.CancelCauseFunc
}

// New builds a Service.
func New(cfg Config) (*Service, error) {
	if cfg.LocalFQDN == "" || !cfg.LocalPLMN.Valid() {
		return nil, errors.New("n32c: new: local FQDN and valid local PLMN are required")
	}
	entries, err := features.Implement(features.N32HandshakeEntries(), featureNFTLST)
	if err != nil {
		return nil, fmt.Errorf("n32c: new: feature table: %w", err)
	}
	cat, err := features.NewCatalog(entries...)
	if err != nil {
		return nil, fmt.Errorf("n32c: new: feature catalog: %w", err)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.PeerIdentity == nil {
		cfg.PeerIdentity = CertPeerIdentity
	}
	if cfg.ResponderIdentity == nil {
		cfg.ResponderIdentity = CertResponderIdentity
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.LocalFQDN = strings.ToLower(cfg.LocalFQDN)
	st := cfg.Store
	if st == nil {
		st = NewStore(nil)
	}
	return &Service{
		cfg: cfg, store: st, catalog: cat,
		specLit:  features.SpecLiteral(cfg.Profile),
		logger:   cfg.Logger,
		inflight: map[uint64]*inflightReq{},
	}, nil
}

// Store returns the N32 context store.
func (s *Service) Store() *Store { return s.store }

// SetHTTPClient sets the client used by Exchange/Teardown (wiring only).
func (s *Service) SetHTTPClient(c *http.Client) { s.cfg.HTTPClient = c }

// SetTerminator sets the connection-terminator hook (wiring only).
func (s *Service) SetTerminator(f func(ctx context.Context, remote PlmnId, reason string)) {
	s.cfg.Terminator = f
}

// RoutePattern is the ServeMux pattern of the exchange-capability operation.
func (s *Service) RoutePattern() string {
	return "POST /" + string(apiversion.N32cHandshake) + "/" +
		apiversion.Of(s.cfg.Profile, apiversion.N32cHandshake).InURI + exchangeCapabilityPath
}

// Handler returns a mux with only the N32-c route (for the N32 listener).
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(s.RoutePattern(), s.HandleExchangeCapability)
	return mux
}

func (s *Service) isPartner(p PlmnId) bool {
	for _, q := range s.cfg.Partners {
		if q.Key() == p.Key() {
			return true
		}
	}
	return false
}

// plog returns the procedure logger for ctx with the fixed N32-c fields.
func (s *Service) plog(ctx context.Context, direction string) *slog.Logger {
	return logging.NewProcedureLogger(ctx, s.logger, procedureName).With(
		"nf", "SEPP", "interface", interfaceN32c, "direction", direction)
}

// ---- in-flight registry (collision detection, Rel-19 only) -------------

// registerInflight records an outgoing request and returns its token, so
// overlapping Exchange calls towards one PLMN do not clobber each other.
func (s *Service) registerInflight(p PlmnId, cancel context.CancelCauseFunc) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextTok++
	s.inflight[s.nextTok] = &inflightReq{plmn: p.Key(), localFQDN: s.cfg.LocalFQDN, cancel: cancel}
	return s.nextTok
}

func (s *Service) clearInflight(tok uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, tok)
}

// lookupInflight returns an outgoing request towards p, if any.
func (s *Service) lookupInflight(p PlmnId) (*inflightReq, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.inflight {
		if r.plmn == p.Key() {
			return r, true
		}
	}
	return nil, false
}

// abandonInflight cancels every outgoing request towards p (collision loser).
func (s *Service) abandonInflight(p PlmnId) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.inflight {
		if r.plmn == p.Key() {
			r.cancel(ErrAbandoned)
		}
	}
}
