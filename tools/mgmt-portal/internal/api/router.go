// Package api implements the REST API and WebSocket endpoints for the management portal.
package api

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/config"
	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/nrf"
	promclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/prometheus"
	"github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/store"
)

// Deps holds all backend dependencies used by the API handlers.
type Deps struct {
	Store      *store.Store
	Docker     *dockerclient.Client
	NRF        *nrf.Client
	Prometheus *promclient.Client
	Config     *config.Manager
	SMFBaseURL string
	AMFBaseURL string // for push-policies endpoint
	UDMBaseURL string // for subscription QoS lookups (Nudm_SDM sm-data)
	UDRBaseURL string // for re-deriving sm-data after a slice change (internal API)
	PCFBaseURL string // for SM policy QoS overrides (NW-triggered session flow)
	LMFBaseURL string // for Nlmf_Location DetermineLocation (UE location map)
	// MTLSClient is an HTTP client carrying the portal's mTLS client certificate.
	// Used for /healthz probes against NFs that enforce mutual TLS (NRF, AMF).
	MTLSClient *http.Client
}

// NewRouter builds the chi router for the management portal API.
// The static SPA assets are served from staticFS at the root.
func NewRouter(deps Deps, staticFS http.FileSystem) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Subscribers
		r.Get("/subscribers", deps.handleListSubscribers)
		r.Post("/subscribers", deps.handleCreateSubscriber)
		r.Get("/subscribers/{supi}", deps.handleGetSubscriber)
		r.Put("/subscribers/{supi}", deps.handleUpdateSubscriber)
		r.Delete("/subscribers/{supi}", deps.handleDeleteSubscriber)
		// Per-subscriber RFSP (Radio Frequency Selection Priority) — proxies PCF AM policy override
		r.Get("/subscribers/{supi}/rfsp", deps.handleGetSubscriberRFSP)
		r.Put("/subscribers/{supi}/rfsp", deps.handleSetSubscriberRFSP)
		r.Delete("/subscribers/{supi}/rfsp", deps.handleDeleteSubscriberRFSP)

		// Slices
		r.Get("/slices", deps.handleListSlices)
		r.Post("/slices", deps.handleAddSlice)
		r.Delete("/slices/{sst}/{sd}", deps.handleDeleteSlice)

		// DNNs
		r.Get("/dnns", deps.handleListDNNs)
		r.Post("/dnns", deps.handleAddDNN)
		r.Put("/dnns/{name}", deps.handleUpdateDNN)
		r.Delete("/dnns/{name}", deps.handleDeleteDNN)

		// Services (containers)
		r.Get("/services", deps.handleListServices)
		r.Post("/services/{name}/start", deps.handleServiceStart)
		r.Post("/services/{name}/stop", deps.handleServiceStop)
		r.Post("/services/{name}/restart", deps.handleServiceRestart)

		// NF status (NRF + healthz)
		r.Get("/nf-status", deps.handleNFStatus)

		// Sessions
		r.Get("/sessions", deps.handleListSessions)
		r.Get("/ue-contexts", deps.handleListUEContexts)

		// Metrics
		r.Get("/metrics/summary", deps.handleMetricsSummary)
		r.Get("/metrics/range", deps.handleMetricsRange)

		// PCAP
		r.Get("/pcap/status", deps.handlePCAPStatus)
		r.Post("/pcap/{nf}/start", deps.handlePCAPStart)
		r.Post("/pcap/{nf}/stop", deps.handlePCAPStop)
		r.Post("/pcap/{nf}/pause", deps.handlePCAPPause)
		r.Post("/pcap/{nf}/resume", deps.handlePCAPResume)
		r.Post("/pcap/{nf}/rotate", deps.handlePCAPRotate)
		r.Get("/pcap/{nf}/files", deps.handlePCAPFiles)
		r.Delete("/pcap/{nf}/files", deps.handlePCAPBulkDelete)
		r.Post("/pcap/{nf}/files/zip", deps.handlePCAPBulkDownload)
		r.Get("/pcap/{nf}/files/{filename}", deps.handlePCAPDownload)
		r.Delete("/pcap/{nf}/files/{filename}", deps.handlePCAPDeleteFile)

		// UERANSIM management
		r.Get("/ueransim/status", deps.handleUERANSIMStatus)
		r.Post("/ueransim/nr-cli", deps.handleNRCLI)
		r.Post("/ueransim/ping", deps.handleUERANSIMPing)
		r.Get("/ueransim/scenarios", deps.handleUERANSIMScenarios)
		r.Post("/ueransim/scenarios/{scenario}/start", deps.handleUERANSIMScenarioStart)
		r.Post("/ueransim/scenarios/{scenario}/stop", deps.handleUERANSIMScenarioStop)

		// PacketRusher mobility testing (Xn HO / N2 HO)
		r.Get("/packetrusher/status", deps.handlePacketRusherStatus)
		r.Post("/packetrusher/{scenario}/start", deps.handlePacketRusherStart)
		r.Post("/packetrusher/{scenario}/stop", deps.handlePacketRusherStop)
		r.Post("/packetrusher/{scenario}/pause", deps.handlePacketRusherPause)
		r.Post("/packetrusher/{scenario}/resume", deps.handlePacketRusherResume)

		// QoS / PDU sessions (SMF management API + UDM SDM proxies)
		r.Get("/qos/sessions", deps.handleQoSListSessions)
		r.Get("/qos/sessions/{psi}", deps.handleQoSGetSession)
		r.Post("/qos/sessions/{psi}/modify", deps.handleQoSModifySession)
		r.Get("/qos/subscription/{supi}", deps.handleQoSSubscription)
		// NW-triggered additional PDU session (URSP-based — TS 23.503 §6.6.2)
		r.Post("/qos/nw-sessions", deps.handleNWSessionTrigger)

		// Public Warning System (ETWS/CMAS — TS 38.413 §8.9, TS 23.041)
		r.Post("/pws/broadcast", deps.handlePWSBroadcast)
		r.Get("/pws/broadcast", deps.handlePWSList)
		r.Post("/pws/cancel", deps.handlePWSCancel)
		r.Post("/pws/resend", deps.handlePWSResend) // re-drive a stored warning after AMF/gNB restart

		// UE Location (Nlmf_Location DetermineLocation — TS 29.572 §5.2.2.2)
		r.Get("/location/summary", deps.handleLocationSummary)
		r.Get("/location/ue/{supi}", deps.handleGetUELocation)

		// Policies (URSP — TS 24.526 / TS 29.525)
		r.Get("/policies", deps.handleListPolicies)
		r.Post("/policies", deps.handleCreatePolicy)
		r.Get("/policies/{id}", deps.handleGetPolicy)
		r.Put("/policies/{id}", deps.handleUpdatePolicy)
		r.Delete("/policies/{id}", deps.handleDeletePolicy)
		r.Post("/policies/push/{supi}", deps.handlePushPolicies)

		// Policy Templates (portal-managed slice defaults — TS 24.526 / TS 29.525)
		r.Get("/policy-templates", deps.handleListTemplates)
		r.Post("/policy-templates", deps.handleCreateTemplate)
		r.Get("/policy-templates/{id}", deps.handleGetTemplate)
		r.Put("/policy-templates/{id}", deps.handleUpdateTemplate)
		r.Delete("/policy-templates/{id}", deps.handleDeleteTemplate)
		r.Post("/policy-templates/{id}/apply", deps.handleApplyTemplate)

		// Health
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	// WebSocket log streaming
	r.Get("/ws/logs/{container}", deps.handleLogsWS)

	// Unmatched routes: serve the React SPA shell for deep links (F5), real
	// static assets when present, JSON 404 for the API/WS namespaces.
	r.NotFound(spaFallback(staticFS))

	return r
}

// spaFallback handles every request no chi route matched — which includes
// client-side routes such as /qos (chi's NotFound is invoked for unmatched
// paths inside mounted subrouters too, so one handler covers /api/v1/…).
//
// Resolution order:
//  1. API/WebSocket namespaces → always a machine-readable JSON 404. An
//     unknown endpoint must not answer with the SPA shell (PRD problem #1 is
//     about navigation, not about hiding API mistakes).
//  2. A real asset on disk (hashed JS/CSS/fonts) → served as-is.
//  3. A GET/HEAD navigation (Accept allows HTML) → index.html, so the
//     client-side router can render the deep-linked view. `*/*` counts as
//     accepting HTML so `curl` can be used to check deep links manually.
//  4. Anything else → JSON 404.
func spaFallback(staticFS http.FileSystem) http.HandlerFunc {
	fileServer := http.FileServer(staticFS)
	return func(w http.ResponseWriter, r *http.Request) {
		if isAPIPath(r.URL.Path) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}

		if f, err := staticFS.Open(r.URL.Path); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}

		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && acceptsHTML(r) {
			serveSPAIndex(w, r, staticFS)
			return
		}

		writeError(w, http.StatusNotFound, "not found")
	}
}

// isAPIPath reports whether p is inside the namespaces that must never fall
// back to the SPA shell: the REST API and the WebSocket log stream.
func isAPIPath(p string) bool {
	return p == "/api" || strings.HasPrefix(p, "/api/") ||
		p == "/ws" || strings.HasPrefix(p, "/ws/")
}

// acceptsHTML reports whether the Accept header allows an HTML response — the
// signal a browser navigation sends and an XHR/fetch does not.
func acceptsHTML(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		mediaType := part
		if i := strings.IndexByte(mediaType, ';'); i >= 0 {
			mediaType = mediaType[:i]
		}
		switch strings.TrimSpace(mediaType) {
		case "text/html", "application/xhtml+xml", "*/*":
			return true
		}
	}
	return false
}

// serveSPAIndex writes the embedded index.html as the SPA shell. It 404s if the
// asset is missing (an unbuilt dev bundle) rather than emitting an empty 200.
func serveSPAIndex(w http.ResponseWriter, r *http.Request, staticFS http.FileSystem) {
	f, err := staticFS.Open("/index.html")
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	defer f.Close() //nolint:errcheck

	data, err := io.ReadAll(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read index.html")
		return
	}
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(data))
}
