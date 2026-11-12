// Peer capability predicates consulted by Gate (REL19-2.1, ADR-5).

package capability

// PeerCap is a predicate over a peer (UE, gNB, NF) deciding whether the peer
// can take part in a feature. Implementations must be cheap and side-effect
// free: callers resolve peer state once (NG Setup, registration, resource
// creation) and cache it.
type PeerCap interface {
	Allows(f Feature) bool
}

// PeerUE is a UE whose NAS capability bit for a feature is looked up via
// Supports (TS 24.501 §9.11.3.1 5GMM capability and §9.11.4.1 5GSM
// capability IEs, decoded by nas.FiveGMMCapability.PeerUE and
// nas.FiveGSMCapability.PeerUE, REL19-5.4). A nil Supports means "no bit set".
type PeerUE struct {
	Supports func(Feature) bool
}

// Allows implements PeerCap.
func (p PeerUE) Allows(f Feature) bool { return p.Supports != nil && p.Supports(f) }

// PeerRAN is a gNB identified by its supported release. The zero value (and
// anything below Rel-17) is treated as Rel-17: an unknown gNB is Rel-17.
type PeerRAN struct {
	Release Release
}

// Allows implements PeerCap: the gNB release must be at least the feature's.
func (p PeerRAN) Allows(f Feature) bool {
	r := p.Release
	if r < Rel17 {
		r = Rel17
	}
	return r >= f.Release
}

// PeerNF is an NF peer whose negotiated supportedFeatures bit (TS 29.500
// §6.6.2; bitmask TS 29.571 §5.2.2) is looked up via Negotiated. A nil
// Negotiated means "bit not negotiated". Kept as a func so the
// shared/sbi/features Set can plug in without this package importing it.
type PeerNF struct {
	Negotiated func(Feature) bool
}

// Allows implements PeerCap.
func (p PeerNF) Allows(f Feature) bool { return p.Negotiated != nil && p.Negotiated(f) }
