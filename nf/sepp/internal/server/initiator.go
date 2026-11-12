package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32c"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

const (
	// initiatorStartDelay lets the N32 listener come up before the first
	// exchange (implementation choice; retries cover a slower start).
	initiatorStartDelay = 1 * time.Second
	// initiatorInitialBackoff is the delay before the first retry.
	initiatorInitialBackoff = 1 * time.Second
	// initiatorMaxBackoff caps the exponential retry delay.
	initiatorMaxBackoff = 30 * time.Second
	// initiatorMaxAttempts bounds the attempts per peer (implementation limit).
	initiatorMaxAttempts = 10
	// initiatorSpecRef: initiator side of the Security Capability Negotiation.
	initiatorSpecRef = "TS 29.573 §5.2.2 step 1"
)

// exchanger is the n32c.Service subset the initiator needs.
type exchanger interface {
	Exchange(ctx context.Context, peerAPIRoot string, target n32c.PlmnId) (n32c.Context, error)
}

// initiator timing; tests shorten it.
type initiatorTiming struct{ startDelay, initial, max time.Duration }

// StartInitiator runs the N32-c initiator towards every configured n32.peers
// entry in the background, with exponential backoff, until ctx is cancelled.
// A failure is logged and never stops the SEPP. It returns a WaitGroup-style
// wait function for tests and shutdown.
func (s *Server) StartInitiator(ctx context.Context) (wait func()) {
	if s.n32 == nil || len(s.cfg.N32.Peers) == 0 {
		return func() {}
	}
	t := initiatorTiming{initiatorStartDelay, initiatorInitialBackoff, initiatorMaxBackoff}
	return s.runInitiator(ctx, s.n32, s.cfg.N32.Peers, t)
}

func (s *Server) runInitiator(ctx context.Context, ex exchanger, peers []config.N32Peer, t initiatorTiming) func() {
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.initiate(ctx, ex, p, t)
		}()
	}
	return wg.Wait
}

// sleep waits d or until ctx is done; it reports whether the wait completed.
func sleep(ctx context.Context, d time.Duration) bool {
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-tm.C:
		return true
	}
}

func (s *Server) initiate(ctx context.Context, ex exchanger, p config.N32Peer, t initiatorTiming) {
	target := n32c.PlmnId{Mcc: p.PLMN.MCC, Mnc: p.PLMN.MNC}
	apiRoot := "https://" + p.Address
	ctx = logging.WithCorrelationID(ctx, "")
	lg := logging.NewProcedureLogger(ctx, s.logger, "N32cExchangeCapability").With(
		"nf", "SEPP", "interface", "N32c", "direction", "OUT",
		"peer_plmn", target.String(), "peer_fqdn", p.FQDN, "spec_ref", initiatorSpecRef)
	if !sleep(ctx, t.startDelay) {
		return
	}
	backoff := t.initial
	for attempt := 1; attempt <= initiatorMaxAttempts; attempt++ {
		if c, ok := s.n32.Store().Get(target); ok { // the peer initiated first
			lg.InfoContext(ctx, "n32 context already established", "result", "OK", "peer_fqdn", c.PeerFQDN)
			return
		}
		_, err := ex.Exchange(ctx, apiRoot, target)
		if err == nil {
			lg.InfoContext(ctx, "n32 initiator exchange completed", "result", "OK", "attempt", attempt)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, n32c.ErrNegotiationNotAllowed) || errors.Is(err, n32c.ErrForbidden) ||
			errors.Is(err, n32c.ErrInvalidSelected) || errors.Is(err, n32c.ErrResponderIdentity) ||
			isCertIdentityError(err) { // peer cert SAN != peers[].fqdn (TS 33.501 §13.1.2)
			lg.WarnContext(ctx, "n32 initiator exchange rejected, not retrying",
				"result", "FAILURE", "cause", err.Error(), "attempt", attempt)
			return
		}
		lg.WarnContext(ctx, "n32 initiator exchange failed",
			"result", "FAILURE", "cause", err.Error(), "attempt", attempt, "retry_in_ms", backoff.Milliseconds())
		if attempt == initiatorMaxAttempts || !sleep(ctx, backoff) {
			break
		}
		backoff = min(backoff*2, t.max)
	}
	if ctx.Err() == nil {
		lg.ErrorContext(ctx, "n32 initiator gave up", "result", "FAILURE", "cause", "max_attempts_reached")
	}
}
