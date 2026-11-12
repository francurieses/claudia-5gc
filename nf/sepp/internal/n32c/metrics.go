package n32c

import "github.com/francurieses/claudia-5gc/shared/observability/metrics"

// countResult increments the shared fivegc_procedure_total counter for the
// N32cSecurityCapabilityNegotiation procedure (nf=SEPP, result OK|REJECT|FAILURE),
// the same series the other NFs use for procedure completions.
// Ref: TS 29.573 §5.2.2.
func countResult(result string) {
	metrics.ProcedureTotal.WithLabelValues("SEPP", procedureName, result).Inc()
}
