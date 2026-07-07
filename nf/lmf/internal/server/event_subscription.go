// Package server — Nlmf_Location EventSubscription handlers (LMF-003).
//
// Implements the following SBI endpoints on the existing :8012 mux:
//
//	POST   /nlmf-loc/v1/subscriptions                → 201 + Location
//	GET    /nlmf-loc/v1/subscriptions/{subId}         → 200 subscription resource
//	DELETE /nlmf-loc/v1/subscriptions/{subId}         → 204 (CancelLocation)
//	POST   /nlmf-loc/v1/ue-contexts/{id}/cancel-loc   → 204 (in-progress one-shot cancel)
//
// Each active subscription drives one goroutine that periodically calls s.locate()
// and POSTs LocationNotification bodies to the caller's notificationUri.
//
// Ref: TS 29.572 §5.2.3 (EventSubscription Create/Get/Delete).
// Ref: TS 29.572 §5.2.2.5 (CancelLocation).
// Ref: TS 29.572 §6.1.6.2.4 (LocationNotification body schema).
// Ref: TS 23.273 §7.2 step B2 (deferred location subscription).
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// locationEventSubscriptionRequest is the JSON body for POST /nlmf-loc/v1/subscriptions.
// Ref: TS 29.572 §5.2.3.2, §6.1.6.2.x.
type locationEventSubscriptionRequest struct {
	// UEContextId is the UE identity (supi, gpsi, or 5G-GUTI).
	// Mutually exclusive with Supi/Gpsi in the flat body variant; accepted as alias.
	UEContextId string `json:"ueContextId,omitempty"`
	// Supi is an alternative UE identity field (supplementary to ueContextId).
	Supi string `json:"supi,omitempty"`
	// Gpsi is an alternative UE identity field (Generic Public Subscription Id).
	Gpsi string `json:"gpsi,omitempty"`
	// EventTrigger selects the subscription mode.
	// Required: "PERIODIC_REPORTING" | "AREA_OF_INTEREST".
	EventTrigger string `json:"eventTrigger"`
	// NotificationUri is the callback URI for LocationNotification POSTs. Mandatory.
	NotificationUri string `json:"notificationUri"`
	// ReportingInterval is the periodic sample cadence in seconds (PERIODIC_REPORTING only).
	// Default: config.DefaultReportingIntervalS.
	ReportingInterval int `json:"reportingInterval,omitempty"`
	// SamplingInterval is the AOI sample cadence in seconds (AREA_OF_INTEREST only).
	// Default: config.DefaultSamplingIntervalS.
	SamplingInterval int `json:"samplingInterval,omitempty"`
	// AreaOfInterest holds the AOI polygon (AREA_OF_INTEREST only).
	AreaOfInterest *areaOfInterestInput `json:"areaOfInterest,omitempty"`
	// Duration is the subscription lifetime in seconds. 0 → MaxDurationS.
	Duration int `json:"duration,omitempty"`
}

// areaOfInterestInput holds the polygon vertices.
// Ref: TS 29.572 §6.1.6.2.2; TS 29.571 §5.4 (GeographicArea).
type areaOfInterestInput struct {
	// Shape is optional; "POLYGON" is assumed when polygon is non-empty.
	Shape string `json:"shape,omitempty"`
	// Polygon is the list of WGS84 vertices (≥3 required).
	Polygon []LatLon `json:"polygon"`
}

// subscriptionResource is the JSON body returned on 201 Create and 200 Get.
// Ref: TS 29.571 §5.2 (subscription resource schema).
type subscriptionResource struct {
	SubId             string               `json:"subId"`
	UEContextId       string               `json:"ueContextId"`
	EventTrigger      string               `json:"eventTrigger"`
	NotificationUri   string               `json:"notificationUri"`
	ReportingInterval int                  `json:"reportingInterval,omitempty"`
	SamplingInterval  int                  `json:"samplingInterval,omitempty"`
	AreaOfInterest    *areaOfInterestInput `json:"areaOfInterest,omitempty"`
	Duration          int                  `json:"duration,omitempty"`
	Created           string               `json:"created"`
	LastNotified      string               `json:"lastNotified,omitempty"`
	State             string               `json:"state,omitempty"`
}

// subscriptionToResource converts the internal subscription struct to the API response.
func subscriptionToResource(s *subscription) subscriptionResource {
	res := subscriptionResource{
		SubId:           s.SubId,
		UEContextId:     s.UEContextId,
		EventTrigger:    s.EventTrigger,
		NotificationUri: s.NotificationUri,
		Duration:        int(s.Duration.Seconds()),
		Created:         s.Created.UTC().Format(time.RFC3339),
		State:           s.State.String(),
	}
	if s.EventTrigger == EventTriggerPeriodic {
		res.ReportingInterval = int(s.ReportingInterval.Seconds())
	} else {
		res.SamplingInterval = int(s.SamplingInterval.Seconds())
		if len(s.AreaOfInterest) > 0 {
			res.AreaOfInterest = &areaOfInterestInput{Shape: "POLYGON", Polygon: s.AreaOfInterest}
		}
	}
	if !s.LastNotified.IsZero() {
		res.LastNotified = s.LastNotified.UTC().Format(time.RFC3339)
	}
	return res
}

// ---- handleCreateSubscription (POST /nlmf-loc/v1/subscriptions) ------------------

// handleCreateSubscription implements Nlmf_Location_EventSubscription Create.
//
// Validates the request, inserts the subscription into the registry, starts the
// goroutine, and returns 201 Created with a Location header.
//
// Ref: TS 29.572 §5.2.3.2.
func (s *Server) handleCreateSubscription(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)

	log := logging.NewProcedureLogger(ctx, s.logger, "LocationEventSubscription").With(
		"nf", "LMF",
		"interface", "Nlmf",
		"direction", "IN",
		"spec_ref", "TS 29.572 §5.2.3.2",
		"correlation_id", corrID,
	)
	log.Info("EventSubscription Create received")

	var req locationEventSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("EventSubscription Create: invalid JSON body",
			"result", "REJECT", "cause", "INVALID_MSG_FORMAT",
			"duration_ms", time.Since(start).Milliseconds())
		metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", "request body is not valid JSON")
		return
	}

	// Resolve UE identity: prefer ueContextId, fall back to supi/gpsi.
	ueContextId := req.UEContextId
	if ueContextId == "" {
		ueContextId = req.Supi
	}
	if ueContextId == "" {
		ueContextId = req.Gpsi
	}
	log = log.With("ue_context_id", ueContextId, "event_trigger", req.EventTrigger)

	// Validate mandatory IEs.
	// Ref: TS 29.572 §5.2.3.2; error table: MANDATORY_IE_MISSING / INVALID_MSG_FORMAT.
	if ueContextId == "" {
		log.Warn("EventSubscription Create: missing UE identity",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING",
			"duration_ms", time.Since(start).Milliseconds())
		metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"at least one of ueContextId, supi, or gpsi is required")
		return
	}
	if req.NotificationUri == "" {
		log.Warn("EventSubscription Create: missing notificationUri",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING",
			"duration_ms", time.Since(start).Milliseconds())
		metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"notificationUri is required (TS 29.572 §5.2.3.2)")
		return
	}
	if req.EventTrigger != EventTriggerPeriodic && req.EventTrigger != EventTriggerAOI {
		log.Warn("EventSubscription Create: unknown eventTrigger",
			"result", "REJECT", "cause", "INVALID_MSG_FORMAT",
			"duration_ms", time.Since(start).Milliseconds())
		metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT").Inc()
		s.problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT",
			"eventTrigger must be PERIODIC_REPORTING or AREA_OF_INTEREST")
		return
	}

	// AOI-specific validation.
	var polygon []LatLon
	if req.EventTrigger == EventTriggerAOI {
		if req.AreaOfInterest == nil || len(req.AreaOfInterest.Polygon) < 3 {
			log.Warn("EventSubscription Create: AOI polygon missing or degenerate (<3 vertices)",
				"result", "REJECT", "cause", "MANDATORY_IE_MISSING",
				"duration_ms", time.Since(start).Milliseconds())
			metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT").Inc()
			s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
				"areaOfInterest.polygon requires ≥3 WGS84 vertices (TS 29.572 §6.1.6.2.2)")
			return
		}
		polygon = req.AreaOfInterest.Polygon
	}

	// Determine interval and duration from config defaults.
	subCfg := s.cfg.LocationSubscription
	reportingInterval := time.Duration(subCfg.DefaultReportingIntervalS) * time.Second
	samplingInterval := time.Duration(subCfg.DefaultSamplingIntervalS) * time.Second
	maxDuration := time.Duration(subCfg.MaxDurationS) * time.Second
	if maxDuration <= 0 {
		maxDuration = 3600 * time.Second
	}

	if req.ReportingInterval > 0 {
		reportingInterval = time.Duration(req.ReportingInterval) * time.Second
	}
	if req.SamplingInterval > 0 {
		samplingInterval = time.Duration(req.SamplingInterval) * time.Second
	}
	duration := maxDuration
	if req.Duration > 0 {
		d := time.Duration(req.Duration) * time.Second
		if d < maxDuration {
			duration = d
		}
	}

	// Privacy check — apply once at Create, not every tick.
	// Ref: TS 23.273 §9.1; procedure doc §"Privacy gate".
	supi := req.Supi
	if supi == "" {
		supi = ueContextId
	}
	if s.cfg.PrivacyCheck && s.udmClient != nil {
		priv, err := s.udmClient.GetLcsPrivacyData(ctx, supi)
		if err != nil {
			log.Warn("EventSubscription Create: UDM lcsData fetch failed — proceeding (fail-open)",
				"error", err, "supi", supi)
		} else if priv != nil && priv.LocationPrivacy == "BLOCK_ALL" {
			log.Warn("EventSubscription Create: location blocked by subscriber privacy policy",
				"supi", supi, "result", "REJECT", "cause", "PRIVACY_EXCEPTION_DENIED",
				"spec_ref", "TS 23.273 §9.1",
				"duration_ms", time.Since(start).Milliseconds())
			metrics.LMFSubscriptionCreateTotal.WithLabelValues("REJECT").Inc()
			s.problem(w, http.StatusForbidden, "PRIVACY_EXCEPTION_DENIED",
				"location disclosure blocked by subscriber privacy settings")
			return
		}
	}

	// Generate subId as UUID (the server already imports google/uuid; procedure doc
	// prefers ULID but falls back to uuid when no shared ULID helper exists).
	subId := uuid.NewString()

	// Build the goroutine context: WithTimeout enforces duration; cancel is stored
	// on the subscription so DELETE can stop it independently.
	gctx, cancel := context.WithTimeout(context.Background(), duration)

	sub := &subscription{
		SubId:             subId,
		UEContextId:       ueContextId,
		EventTrigger:      req.EventTrigger,
		NotificationUri:   req.NotificationUri,
		ReportingInterval: reportingInterval,
		SamplingInterval:  samplingInterval,
		AreaOfInterest:    polygon,
		Duration:          duration,
		Created:           time.Now().UTC(),
		State:             aoiStateUnknown,
		cancel:            cancel,
	}

	s.registry.add(sub)
	metrics.LMFSubscriptionsActive.Set(float64(s.registry.count()))

	// Start the goroutine after inserting into the registry so that GET can see
	// the resource immediately.
	go s.runSubscription(gctx, subId, supi, corrID)

	log = log.With("sub_id", subId, "supi", supi)
	durationMs := time.Since(start).Milliseconds()
	log.Info("EventSubscription Create: subscription registered",
		"result", "OK",
		"duration_ms", durationMs,
		"spec_ref", "TS 29.572 §5.2.3.2",
	)
	metrics.LMFSubscriptionCreateTotal.WithLabelValues("OK").Inc()

	// Read snapshot for the response body (safe after add).
	snap, _ := s.registry.snapshot(subId)
	res := subscriptionToResource(snap)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/nlmf-loc/v1/subscriptions/"+subId)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(res)
}

// ---- handleGetSubscription (GET /nlmf-loc/v1/subscriptions/{subId}) ---------------

// handleGetSubscription returns the current state of a subscription resource.
// Ref: TS 29.572 §5.2.3.3.
func (s *Server) handleGetSubscription(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	subId := r.PathValue("subId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)

	log := logging.NewProcedureLogger(ctx, s.logger, "LocationEventSubscription").With(
		"nf", "LMF",
		"interface", "Nlmf",
		"direction", "IN",
		"spec_ref", "TS 29.572 §5.2.3.3",
		"correlation_id", corrID,
		"sub_id", subId,
	)

	snap, ok := s.registry.snapshot(subId)
	if !ok {
		log.Info("EventSubscription Get: subscription not found",
			"result", "FAILURE", "cause", "SUBSCRIPTION_NOT_FOUND",
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusNotFound, "SUBSCRIPTION_NOT_FOUND",
			"subscription "+subId+" not found (TS 29.572 §5.2.3.3)")
		return
	}

	log.Info("EventSubscription Get: returning subscription resource",
		"result", "OK",
		"duration_ms", time.Since(start).Milliseconds())
	res := subscriptionToResource(snap)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

// ---- handleDeleteSubscription (DELETE /nlmf-loc/v1/subscriptions/{subId}) ---------

// handleDeleteSubscription cancels and removes a subscription (CancelLocation).
// Ref: TS 29.572 §5.2.3.4 / §5.2.2.5.
func (s *Server) handleDeleteSubscription(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	subId := r.PathValue("subId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)

	log := logging.NewProcedureLogger(ctx, s.logger, "CancelLocation").With(
		"nf", "LMF",
		"interface", "Nlmf",
		"direction", "IN",
		"spec_ref", "TS 29.572 §5.2.3.4",
		"correlation_id", corrID,
		"sub_id", subId,
	)

	if !s.registry.delete(subId) {
		log.Info("CancelLocation: subscription not found",
			"result", "FAILURE", "cause", "SUBSCRIPTION_NOT_FOUND",
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusNotFound, "SUBSCRIPTION_NOT_FOUND",
			"subscription "+subId+" not found (TS 29.572 §5.2.3.4)")
		return
	}

	metrics.LMFSubscriptionsActive.Set(float64(s.registry.count()))
	log.Info("CancelLocation: subscription cancelled",
		"result", "OK",
		"duration_ms", time.Since(start).Milliseconds())
	w.WriteHeader(http.StatusNoContent)
}

// ---- handleCancelLocation (POST /nlmf-loc/v1/ue-contexts/{id}/cancel-loc) ---------

// handleCancelLocation implements the CancelLocation one-shot cancel.
// It aborts any currently blocked DetermineLocation request for the UE by
// cancelling its stored context. Returns 204 even when no request is in progress
// (idempotent). Ref: TS 29.572 §5.2.2.5.
func (s *Server) handleCancelLocation(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ueContextId := r.PathValue("ueContextId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)

	log := logging.NewProcedureLogger(ctx, s.logger, "CancelLocation").With(
		"nf", "LMF",
		"interface", "Nlmf",
		"direction", "IN",
		"spec_ref", "TS 29.572 §5.2.2.5",
		"correlation_id", corrID,
		"ue_context_id", ueContextId,
	)

	// Look up a cancel func registered by a pending DetermineLocation request.
	if v, ok := s.pendingLoc.Load(ueContextId); ok {
		cancelFn := v.(context.CancelFunc)
		cancelFn()
		s.pendingLoc.Delete(ueContextId)
		log.Info("CancelLocation: in-progress locate cancelled",
			"result", "OK",
			"duration_ms", time.Since(start).Milliseconds())
	} else {
		log.Info("CancelLocation: no in-progress locate for UE (idempotent no-op)",
			"result", "OK",
			"spec_ref", "TS 29.572 §5.2.2.5",
			"duration_ms", time.Since(start).Milliseconds())
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---- subscription goroutine ------------------------------------------------

// runSubscription is the per-subscription goroutine.
// It ticks at the configured interval, calls s.locate(), and posts notifications.
// It exits when ctx is cancelled (DELETE or duration expiry).
//
// Ref: TS 29.572 §5.2.3 (goroutine template); TS 23.273 §7.2 step B2.
func (s *Server) runSubscription(ctx context.Context, subId, supi, parentCorrID string) {
	snap, ok := s.registry.snapshot(subId)
	if !ok {
		return
	}

	interval := snap.SamplingInterval
	if snap.EventTrigger == EventTriggerPeriodic {
		interval = snap.ReportingInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// AOI state machine: start UNKNOWN; first resolved state sets the baseline
	// without firing a notification (suppress the synthetic UNKNOWN→IN/OUT transition).
	prevState := aoiStateUnknown

	for {
		select {
		case <-ctx.Done():
			// Subscription cancelled (DELETE) or duration expired.
			// Auto-remove from registry on expiry so registry stays consistent.
			s.registry.mu.Lock()
			_, stillPresent := s.registry.subs[subId]
			if stillPresent {
				// context expired naturally (timeout); DELETE already removed it
				// via registry.delete(), which also calls cancel(). We may arrive
				// here from either path — only clean up when still present.
				delete(s.registry.subs, subId)
			}
			s.registry.mu.Unlock()
			if stillPresent {
				metrics.LMFSubscriptionsActive.Set(float64(s.registry.count()))
			}
			return

		case <-ticker.C:
			// Reload snapshot to get the latest state.
			snap, ok = s.registry.snapshot(subId)
			if !ok {
				return // already deleted by another path
			}

			// Build a per-tick correlation id for traceability.
			tickCorrID := uuid.NewString()
			tickCtx := logging.WithCorrelationID(ctx, tickCorrID)

			locData, _, err := s.locate(tickCtx, snap.UEContextId, supi)
			if err != nil {
				// Transient failure — skip this tick, keep subscription alive.
				s.logger.WarnContext(tickCtx, "EventSubscription: locate failed on tick — skipping",
					"nf", "LMF",
					"procedure", "LocationEventSubscription",
					"interface", "Nlmf",
					"direction", "OUT",
					"sub_id", subId,
					"ue_context_id", snap.UEContextId,
					"supi", supi,
					"correlation_id", tickCorrID,
					"spec_ref", "TS 29.572 §5.2.3",
					"error", err,
				)
				continue
			}

			switch snap.EventTrigger {
			case EventTriggerPeriodic:
				// Post every successful sample.
				s.sendNotification(tickCtx, snap, *locData, nil, tickCorrID)

			case EventTriggerAOI:
				// Evaluate AOI state machine.
				var newState aoiState
				if locData.LocationEstimate != nil && locData.LocationEstimate.Point != nil {
					pt := locData.LocationEstimate.Point
					if pointInPolygon(pt.Lat, pt.Lon, snap.AreaOfInterest) {
						newState = aoiStateIn
					} else {
						newState = aoiStateOut
					}
				} else {
					// No coordinate — cannot evaluate; skip.
					continue
				}

				// Persist new state.
				s.registry.updateAOIState(subId, newState)

				if prevState == aoiStateUnknown {
					// First sample: establish baseline, suppress notification.
					prevState = newState
					s.logger.InfoContext(tickCtx, "EventSubscription AOI: baseline established (suppressed)",
						"nf", "LMF",
						"procedure", "LocationEventSubscription",
						"interface", "Nlmf",
						"direction", "OUT",
						"sub_id", subId,
						"aoi_state", newState.String(),
						"spec_ref", "TS 29.572 §5.2.3",
						"correlation_id", tickCorrID,
					)
					continue
				}

				if newState != prevState {
					// State transition: notify.
					event := "AREA_ENTERING"
					if newState == aoiStateOut {
						event = "AREA_LEAVING"
					}
					prevState = newState
					aei := &AreaEventInfo{Event: event}
					s.sendNotification(tickCtx, snap, *locData, aei, tickCorrID)
				}
			}
		}
	}
}

// sendNotification builds and delivers a LocationNotification to the subscriber's
// notificationUri, with one retry on 5xx or transport error.
//
// Ref: TS 29.572 §6.1.6.2.4; TS 29.572 §5.2.3 (best-effort delivery).
func (s *Server) sendNotification(ctx context.Context, snap *subscription, loc LocationData, aei *AreaEventInfo, corrID string) {
	item := NotificationItem{LocationData: loc}
	if aei != nil {
		item.AreaEventInfo = aei
	}
	notif := LocationNotification{
		SubId:             snap.SubId,
		NotificationItems: []NotificationItem{item},
	}

	log := s.logger.With(
		"nf", "LMF",
		"procedure", "LocationEventSubscription",
		"interface", "Nlmf-notify",
		"direction", "OUT",
		"spec_ref", "TS 29.572 §6.1.6.2.4",
		"sub_id", snap.SubId,
		"ue_context_id", snap.UEContextId,
		"event_trigger", snap.EventTrigger,
		"correlation_id", corrID,
	)

	maxRetries := 1 + s.cfg.LocationSubscription.NotificationRetry
	if maxRetries < 1 {
		maxRetries = 1
	}

	var err error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err = s.notifClient.PostNotification(ctx, snap.NotificationUri, notif)
		if err == nil {
			log.InfoContext(ctx, "EventSubscription: notification delivered",
				"result", resultLabel(attempt),
				"notify_attempt", attempt,
			)
			metrics.LMFNotificationsTotal.WithLabelValues(snap.EventTrigger, resultLabel(attempt)).Inc()
			s.registry.markNotified(snap.SubId)
			return
		}
		log.WarnContext(ctx, "EventSubscription: notification attempt failed",
			"result", "RETRIED",
			"notify_attempt", attempt,
			"error", err,
		)
	}
	// All attempts exhausted — drop.
	log.WarnContext(ctx, "EventSubscription: notification dropped after all retries",
		"result", "DROPPED",
		"notify_attempt", maxRetries,
		"error", err,
	)
	metrics.LMFNotificationsTotal.WithLabelValues(snap.EventTrigger, "DROPPED").Inc()
}

// resultLabel returns the metric result label for a notification delivery.
func resultLabel(attempt int) string {
	if attempt == 1 {
		return "OK"
	}
	return "RETRIED"
}

// pendingLoc is a sync.Map[ueContextId → context.CancelFunc] for in-progress
// DetermineLocation requests. Registered on entry to handleDetermineLocation,
// deregistered on return. The cancel-loc handler looks up and fires the cancel.
//
// Declared here so event_subscription.go owns the cancel-loc mechanism;
// handleDetermineLocation in server.go accesses it via s.pendingLoc.
//
// Note: this is a *field* on Server (declared below), not a package-level var.

// cancelLocRegistration is a helper returned by registerPendingLoc so the caller
// can defer the deregistration idiomatically.
type cancelLocRegistration struct {
	m   *sync.Map
	key string
}

func (c *cancelLocRegistration) done() { c.m.Delete(c.key) }
