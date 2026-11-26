package n32c

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// Roles of the local SEPP in an N32-c exchange (metric label "role").
const (
	// RoleInitiator: the local SEPP sent the exchange-capability request.
	RoleInitiator = "initiator"
	// RoleResponder: the local SEPP answered a peer's request.
	RoleResponder = "responder"
)

// peerLabelOther is the peer_plmn label for a peer that is not a configured
// roaming partner (or could not be identified), so a stray certificate cannot
// grow the label set without bound.
const peerLabelOther = "other"

var (
	// n32cHandshakeTotal counts N32-c exchange-capability outcomes per remote
	// PLMN and local role (operability counter, not a TS 28.552 KPI).
	// Ref: TS 29.573 §5.2.2.
	n32cHandshakeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_sepp_n32c_handshake_total",
		Help: "N32-c exchange-capability outcomes by remote PLMN, local role (initiator|responder) and result (OK|REJECT|FAILURE) (TS 29.573 §5.2.2).",
	}, []string{"peer_plmn", "role", "result"})

	// n32cContextEstablished is 1 while an N32 context (TLS mode) exists for
	// the remote PLMN, else 0. Ref: TS 29.573 §5.2.2 (PLMN to N32 mapping).
	n32cContextEstablished = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fivegc_sepp_n32c_context_established",
		Help: "1 while an N32 context (TLS security mode) exists for the remote PLMN, else 0 (TS 29.573 §5.2.2).",
	}, []string{"peer_plmn"})
)

// countResult increments the shared fivegc_procedure_total counter for the
// N32cSecurityCapabilityNegotiation procedure (nf=SEPP, result OK|REJECT|FAILURE),
// the same series the other NFs use for procedure completions.
// Ref: TS 29.573 §5.2.2.
func countResult(result string) {
	metrics.ProcedureTotal.WithLabelValues("SEPP", procedureName, result).Inc()
}

// peerLabel returns the bounded peer_plmn label: the canonical "mcc/mnc" of a
// configured partner, else peerLabelOther.
func (s *Service) peerLabel(p PlmnId) string {
	if p.Valid() && s.isPartner(p) {
		return p.String()
	}
	return peerLabelOther
}

// contextGauge keeps fivegc_sepp_n32c_context_established in step with the
// store. It runs as the store observer (under the store lock).
func contextGauge(e StoreEvent) {
	v := 0.0
	if e.Op == "create" {
		v = 1
	}
	n32cContextEstablished.WithLabelValues(e.PLMN.String()).Set(v)
}
