// Package metrics provides the canonical Prometheus metrics registry for 5GC NFs.
// Each NF must call Register() once at startup with its name (e.g. "AMF").
// All metrics are prefixed fivegc_ to avoid collisions with host/process metrics.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// UERegistered tracks the number of UEs currently in GMMRegistered state.
	// Label: nf (always "AMF").
	UERegistered = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fivegc_ue_registered",
		Help: "Number of UEs currently in 5GMM-REGISTERED state.",
	}, []string{"nf"})

	// UEConnected tracks the number of N2 connections (gNB associations active).
	// Label: nf (always "AMF").
	UEConnected = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fivegc_ue_connected",
		Help: "Number of UEs with an active N2 (NGAP) association.",
	}, []string{"nf"})

	// ProcedureTotal counts 3GPP procedure completions.
	// Labels: nf, procedure (e.g. InitialRegistration), result (OK|REJECT|FAILURE).
	ProcedureTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_procedure_total",
		Help: "Total 3GPP procedure completions by NF, procedure name, and result.",
	}, []string{"nf", "procedure", "result"})

	// NASMessagesTotal counts NAS messages processed by the AMF.
	// Labels: nf, message_type, direction (IN|OUT), result (OK|FAILURE).
	NASMessagesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_nas_messages_total",
		Help: "Total NAS messages processed, labeled by type, direction, and result.",
	}, []string{"nf", "message_type", "direction", "result"})

	// SBIRequestsTotal counts SBI (HTTP/2) requests per NF.
	// Labels: nf, method, path_template, status_code (as string).
	SBIRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_sbi_requests_total",
		Help: "Total SBI HTTP requests handled, labeled by method, path, and HTTP status code.",
	}, []string{"nf", "method", "path", "status_code"})

	// SBIRequestDurationSeconds tracks SBI handler latency.
	// Labels: nf, method, path_template.
	SBIRequestDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "fivegc_sbi_request_duration_seconds",
		Help:    "SBI request handler latency in seconds.",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
	}, []string{"nf", "method", "path"})

	// NGAPMessagesTotal counts NGAP messages exchanged over N2.
	// Labels: nf, message_type, direction (IN|OUT), result (OK|FAILURE).
	NGAPMessagesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_ngap_messages_total",
		Help: "Total NGAP messages processed, labeled by type, direction, and result.",
	}, []string{"nf", "message_type", "direction", "result"})

	// --- Session Management (SMF) ---

	// PDUSessionsActive is the number of active PDU sessions per DNN.
	// Labels: nf, dnn.
	PDUSessionsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fivegc_pdu_sessions_active",
		Help: "Number of active PDU sessions.",
	}, []string{"nf", "dnn"})

	// PDUSessionTotal counts PDU session creation attempts.
	// Labels: nf, dnn, result (OK|FAILURE).
	PDUSessionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_pdu_session_total",
		Help: "Total PDU session creation attempts by NF, DNN, and result.",
	}, []string{"nf", "dnn", "result"})

	// --- UPF Data Plane ---

	// UPFGTPPacketsTotal counts GTP-U T-PDUs processed by the UPF.
	// Labels: direction (uplink|downlink).
	UPFGTPPacketsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_upf_gtp_packets_total",
		Help: "Total GTP-U T-PDU packets processed.",
	}, []string{"direction"})

	// UPFGTPBytesTotal counts inner IP bytes forwarded over GTP-U.
	// Labels: direction (uplink|downlink), dnn.
	UPFGTPBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_upf_gtp_bytes_total",
		Help: "Total inner IP bytes forwarded over GTP-U.",
	}, []string{"direction", "dnn"})

	// UPFPFCPSessionsActive is the number of active PFCP sessions in the UPF.
	UPFPFCPSessionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "fivegc_upf_pfcp_sessions_active",
		Help: "Number of active PFCP sessions in UPF.",
	})

	// UPFPacketDropsTotal counts GTP-U packets dropped by the UPF.
	// Labels: reason (no_session|no_route).
	UPFPacketDropsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_upf_packet_drops_total",
		Help: "Total GTP-U packets dropped.",
	}, []string{"reason"})

	// --- NRF Registry ---

	// NFInstancesRegistered tracks NF instances currently registered in the NRF.
	// Labels: nf_type.
	NFInstancesRegistered = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fivegc_nf_instances_registered",
		Help: "Number of NF instances currently registered in the NRF.",
	}, []string{"nf_type"})

	// NFDiscoveryTotal counts NF discovery requests served by the NRF.
	// Labels: target_nf_type, result (OK|EMPTY).
	NFDiscoveryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_nf_discovery_total",
		Help: "Total NF discovery requests served by NRF.",
	}, []string{"target_nf_type", "result"})

	// --- Mobility (AMF) ---

	// HandoverTotal counts handover procedures completed.
	// Labels: nf, ho_type (xn|n2), result (OK).
	HandoverTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_handover_total",
		Help: "Total handover procedures completed.",
	}, []string{"nf", "ho_type", "result"})

	// UERegisteredBySlice tracks the number of registered UEs per S-NSSAI.
	// Labels: nf, sst, sd.
	UERegisteredBySlice = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fivegc_ue_registered_by_slice",
		Help: "Number of registered UEs per network slice (S-NSSAI).",
	}, []string{"nf", "sst", "sd"})

	// --- Authentication (AUSF) ---

	// AuthenticationTotal counts 5G-AKA authentication procedure completions.
	// Labels: nf, result (OK|FAILURE).
	AuthenticationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_authentication_total",
		Help: "Total UE authentication procedure completions.",
	}, []string{"nf", "result"})

	// --- BSF Binding Support Function ---

	// BSFBindingsActive is the number of PCF bindings currently registered in the BSF.
	// A binding maps (UE IP, DNN, S-NSSAI) → serving PCF and is created by the PCF at
	// SM policy association creation and removed at deletion.
	// Ref: TS 29.521 §5, TS 23.501 §6.2.16
	BSFBindingsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "fivegc_bsf_bindings_active",
		Help: "Number of PCF bindings currently registered in the BSF (TS 29.521).",
	})

	// --- NEF Network Exposure Function ---

	// NEFSubscriptionsActive is the number of Nnef_AFsessionWithQoS subscriptions
	// currently active in the NEF. Incremented on successful Create; decremented on
	// successful Delete.
	// Ref: TS 29.522 §4.4.13, TS 23.501 §6.2.5
	NEFSubscriptionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "fivegc_nef_subscriptions_active",
		Help: "Number of active Nnef_AFsessionWithQoS subscriptions in the NEF (TS 29.522).",
	})

	// --- LMF Location Management Function ---

	// LMFLocateTotal counts Nlmf_Location DetermineLocation requests by outcome.
	// Label: result ("OK" | "REJECT" | "FAILURE"). Incremented by the LMF on every
	// DetermineLocation request: OK on a successful Cell-ID fix, REJECT on a client
	// error (missing IE / unknown UE), FAILURE on a downstream/positioning failure.
	// Ref: TS 29.572 §5.2.2.2, TS 23.273 §7.2, TS 23.501 §6.2.18
	LMFLocateTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fivegc_lmf_locate_total",
		Help: "Total Nlmf_Location DetermineLocation requests by result (TS 29.572).",
	}, []string{"result"})
)

// MetricsServer builds a standalone HTTP server for the /metrics endpoint.
// Addr is the listen address (e.g. "0.0.0.0:9101").
func MetricsServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"UP"}`))
	})
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// SBIMiddleware wraps an http.Handler and records SBI metrics for the given NF.
// pathTemplate should be a stable string (e.g. "/nausf-auth/v1/ue-authentications")
// to avoid high-cardinality label explosions from dynamic path segments.
func SBIMiddleware(nf string, pathTemplate string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		dur := time.Since(start).Seconds()
		sc := http.StatusText(rw.status)
		_ = sc

		SBIRequestsTotal.WithLabelValues(nf, r.Method, pathTemplate, statusStr(rw.status)).Inc()
		SBIRequestDurationSeconds.WithLabelValues(nf, r.Method, pathTemplate).Observe(dur)
	})
}

type captureWriter struct {
	http.ResponseWriter
	status int
}

func (w *captureWriter) WriteHeader(c int) {
	w.status = c
	w.ResponseWriter.WriteHeader(c)
}

func statusStr(code int) string {
	switch {
	case code < 300:
		return "2xx"
	case code < 400:
		return "3xx"
	case code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}
