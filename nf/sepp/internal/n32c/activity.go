package n32c

import (
	"context"
	"sort"
	"time"
)

// Attempt is the last N32-c exchange-capability outcome seen for a remote
// PLMN, in either role. It is operator state for the read-only admin view
// (PORTAL-UI-22), not a 3GPP information element.
type Attempt struct {
	At     time.Time `json:"at"`
	Role   string    `json:"role"`
	Result string    `json:"result"`
	Cause  string    `json:"cause,omitempty"`
}

// peerCtxKey carries the authenticated peer PLMN of an incoming request, so
// the reject path can attribute the outcome to it.
type peerCtxKey struct{}

func withPeer(ctx context.Context, p PlmnId) context.Context {
	return context.WithValue(ctx, peerCtxKey{}, p)
}

func peerFrom(ctx context.Context) (PlmnId, bool) {
	p, ok := ctx.Value(peerCtxKey{}).(PlmnId)
	return p, ok
}

// record counts the outcome (fivegc_sepp_n32c_handshake_total) and, for a
// configured partner, keeps it as the PLMN's last attempt.
func (s *Service) record(p PlmnId, role, result, cause string) {
	label := s.peerLabel(p)
	n32cHandshakeTotal.WithLabelValues(label, role, result).Inc()
	if label == peerLabelOther {
		return
	}
	s.amu.Lock()
	defer s.amu.Unlock()
	s.activity[p.Key()] = Attempt{At: s.cfg.Now(), Role: role, Result: result, Cause: cause}
}

// LastAttempt returns the last recorded exchange-capability outcome for p.
func (s *Service) LastAttempt(p PlmnId) (Attempt, bool) {
	s.amu.Lock()
	defer s.amu.Unlock()
	a, ok := s.activity[p.Key()]
	return a, ok
}

// Partners returns the configured roaming partners in canonical order.
func (s *Service) Partners() []PlmnId {
	out := make([]PlmnId, len(s.cfg.Partners))
	copy(out, s.cfg.Partners)
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// LocalPLMN returns the PLMN this SEPP fronts.
func (s *Service) LocalPLMN() PlmnId { return s.cfg.LocalPLMN }

// LocalFQDN returns the SEPP FQDN used as N32-c sender.
func (s *Service) LocalFQDN() string { return s.cfg.LocalFQDN }

// SpecLiteral reports whether the Rel-19 (spec-literal) behaviour is active.
func (s *Service) SpecLiteral() bool { return s.specLit }

// Snapshot returns a copy of every stored N32 context, ordered by PLMN.
func (st *Store) Snapshot() []Context {
	st.mu.RLock()
	out := make([]Context, 0, len(st.m))
	for _, c := range st.m {
		out = append(out, c)
	}
	st.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].RemotePLMN.Key() < out[j].RemotePLMN.Key() })
	return out
}
