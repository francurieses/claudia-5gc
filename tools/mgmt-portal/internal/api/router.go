// Package api implements the REST API and WebSocket endpoints for the management portal.
package api

import (
	"net/http"

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
	PCFBaseURL string // for SM policy QoS overrides (NW-triggered session flow)
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

	// Serve React SPA for all other routes
	r.NotFound(http.FileServer(staticFS).ServeHTTP)

	return r
}
