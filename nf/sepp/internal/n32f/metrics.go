package n32f

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// peerUnknown is the peer_plmn label of a message rejected before its remote
// PLMN was resolved (no N32 context, bad target, overload, loop).
const peerUnknown = "unknown"

var (
	// n32fMessagesTotal counts N32-f forwarded or rejected messages per
	// direction (OUT = local NF -> peer SEPP, IN = peer SEPP -> local NF),
	// remote PLMN and result. Operability counter. Ref: TS 29.573 §5.3.3.
	n32fMessagesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_sepp_n32f_messages_total",
		Help: "N32-f messages handled by the SEPP by direction (IN|OUT), remote PLMN and result (OK|REJECT|FAILURE) (TS 29.573 §5.3.3).",
	}, []string{"direction", "peer_plmn", "result"})

	// n32fDuration is the SEPP-side handling time of an N32-f message,
	// including the forwarded round trip. Ref: TS 29.573 §5.3.3.
	n32fDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "fivegc_sepp_n32f_duration_seconds",
		Help:    "SEPP handling time of an N32-f message including the forwarded round trip, by direction (TS 29.573 §5.3.3).",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 14), // 1 ms .. ~8 s
	}, []string{"direction"})
)

// observe records one handled N32-f message.
func observe(dir, peer, result string, start time.Time) {
	if peer == "" {
		peer = peerUnknown
	}
	if result == "" { // handler aborted before an outcome was set
		result = "FAILURE"
	}
	n32fMessagesTotal.WithLabelValues(dir, peer, result).Inc()
	n32fDuration.WithLabelValues(dir).Observe(time.Since(start).Seconds())
}
