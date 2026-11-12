// Package server — TS 29.572 deferred (periodic / area-event) location (REL19-3.5 slice D).
//
// Under the Rel-19 profile (features.SpecLiteral) a DetermineLocation request
// carrying periodicEventInfo or areaEventInfo plus hgmlcCallBackURI and
// ldrReference creates a deferred-location session on the existing
// subscription engine (subscription registry + runSubscription goroutine). The
// LMF first runs one immediate position fix and answers 200 LocationDataExt
// (successful activation, TS 29.572 §5.2.2.2.2 step 2a); every later event
// report is POSTed to hgmlcCallBackURI as EventNotifyData (the EventNotify
// callback). CancelLocation (CancelLocData with hgmlcCallBackURI +
// ldrReference) removes the session silently (TS 23.273 §6.3.3 step 5).
//
// The legacy /subscriptions API is untouched; under rel17 / no profile the
// deferred attributes of DetermineLocation are ignored (immediate location).
//
// Ref: TS 29.572 §5.2.2.2, §5.2.2.4.2, callback EventNotify;
// TS29572_Nlmf_Location.yaml (InputData, PeriodicEventInfo, AreaEventInfo,
// EventNotifyData, CancelLocData); TS 23.273 §6.3 (deferred EC-MT-LR/periodic).
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// ReportedEventType values of EventNotifyData.reportedEventType.
// Ref: TS29572_Nlmf_Location.yaml#/components/schemas/ReportedEventType; TS 29.572 Table 6.1.6.3.x.
const (
	reportedPeriodicEvent         = "PERIODIC_EVENT"
	reportedEnteringAreaEvent     = "ENTERING_AREA_EVENT"
	reportedLeavingAreaEvent      = "LEAVING_AREA_EVENT"
	reportedBeingInsideEvent      = "BEING_INSIDE_AREA_EVENT"
	reportedMaxIntervalExpiration = "MAXIMUM_INTERVAL_EXPIRATION_EVENT"
	reportedLocationCancellation  = "LOCATION_CANCELLATION_EVENT"
)

// TerminationCause values of EventNotifyData.terminationCause.
// Ref: TS29572_Nlmf_Location.yaml#/components/schemas/TerminationCause.
const (
	terminationNormal    = "NORMAL_TERMINATION"
	terminationByNetwork = "TERMINATION_BY_NETWORK"
)

// ReportingAreaType values. Ref: TS29572_Nlmf_Location.yaml#/components/schemas/ReportingAreaType.
const (
	areaTypeTai  = "5GS_TRACKING_AREA_IDENTITY"
	areaTypeNcgi = "NR_CELL_GLOBAL_IDENTITY"
	areaTypeEcgi = "E-UTRAN_CELL_GLOBAL_IDENTIFICATION"
	areaTypeEpsT = "EPS_TRACKING_AREA_IDENTITY"
)

// LdrType values of InputData.ldrType.
// Ref: TS 29.572 Table 6.1.6.3.14-1; TS29572_Nlmf_Location.yaml#/components/schemas/LdrType.
const (
	ldrTypePeriodic = "PERIODIC"
	ldrTypeEntering = "ENTERING_INTO_AREA"
	ldrTypeLeaving  = "LEAVING_FROM_AREA"
	ldrTypeInside   = "BEING_INSIDE_AREA"
	ldrTypeMotion   = "MOTION"
	// ldrTypeUEAvailable is the LdrType value for UE availability reporting;
	// known, but selects neither periodic nor area reporting.
	ldrTypeUEAvailable = "UE_AVAILABLE"
)

// occurrenceOneTime is OccurrenceInfo ONE_TIME_EVENT (report once, then end).
// Ref: TS29572_Nlmf_Location.yaml#/components/schemas/OccurrenceInfo.
const occurrenceOneTime = "ONE_TIME_EVENT"

// Schema bounds. Ref: TS29572_Nlmf_Location.yaml (ReportingAmount, ReportingInterval,
// ReportingIntervalMs, MinimumInterval, MaximumInterval, SamplingInterval,
// ReportingDuration, AreaEventInfo.areaDefinition maxItems).
const (
	maxReportingAmount     = 8639999
	maxReportingIntervalS  = 8639999
	maxReportingIntervalMs = 999
	maxMinimumInterval     = 32767
	maxMaximumInterval     = 86400
	maxSamplingInterval    = 3600
	maxReportingDuration   = 8640000
	maxAreaDefinitions     = 250
	// maxReportingProduct is the limit of reportingAmount x reportingInterval
	// (Table 6.1.6.2.24-1 NOTE).
	maxReportingProduct = 8639999
)

// maxConsecutiveLocateFailures ends a deferred session (TERMINATION_BY_NETWORK)
// after this many positioning failures in a row. Own bound, not a spec value.
const maxConsecutiveLocateFailures = 5

// defaultMaxDuration caps a deferred session when LocationSubscription.MaxDurationS
// is not configured. Own bound, not a spec value.
const defaultMaxDuration = 3600 * time.Second

// maxDeferredSessions bounds the number of concurrent deferred-location
// sessions (one goroutine each); beyond it a request gets 503. Own bound, not
// a spec value.
const maxDeferredSessions = 1000

// deferredNotifyTimeout bounds the termination notification sent when a
// session ends outside a tick (cancel / expiry). Own bound, not a spec value.
const deferredNotifyTimeout = 5 * time.Second

// ldrReferencePattern is the LdrReference schema pattern.
// Ref: TS29572_Nlmf_Location.yaml#/components/schemas/LdrReference.
var ldrReferencePattern = regexp.MustCompile(`^([0-9a-fA-F]{2}){1,255}$`)

// deferredInputData is the subset of InputData the deferred-location path
// needs. It is decoded from the same body as nlmfRequest, only under the
// Rel-19 profile.
//
// oapi: TS29572_Nlmf_Location.yaml#/components/schemas/InputData
type deferredInputData struct {
	Supi              string                     `json:"supi,omitempty"`
	Gpsi              string                     `json:"gpsi,omitempty"`
	LdrType           string                     `json:"ldrType,omitempty"`
	HgmlcCallBackURI  string                     `json:"hgmlcCallBackURI,omitempty"`
	LdrReference      string                     `json:"ldrReference,omitempty"`
	PeriodicEventInfo *periodicEventInfo         `json:"periodicEventInfo,omitempty"`
	AreaEventInfo     *areaEventInfoIn           `json:"areaEventInfo,omitempty"`
	MotionEventInfo   map[string]json.RawMessage `json:"motionEventInfo,omitempty"`
}

// isDeferred reports whether the request asks for a deferred location: any
// periodic / area / motion event information, or an ldrType naming one of the
// event types (UE_AVAILABLE and unknown values alone stay immediate).
func (d *deferredInputData) isDeferred() bool {
	if d.PeriodicEventInfo != nil || d.AreaEventInfo != nil || d.MotionEventInfo != nil {
		return true
	}
	switch d.LdrType {
	case ldrTypePeriodic, ldrTypeEntering, ldrTypeLeaving, ldrTypeInside, ldrTypeMotion:
		return true
	}
	return false
}

// unsupportedEvent reports whether the request asks for an event type the LMF
// does not implement (motion events): 501 UNSUPPORTED_EVENT_TYPE.
//
// Ref: TS 29.572 Table 6.1.4.2.2-2 (501), Table 6.1.7.3-1.
func (d *deferredInputData) unsupportedEvent() bool {
	return d.LdrType == ldrTypeMotion || d.MotionEventInfo != nil
}

// periodicEventInfo requests periodic event reporting.
//
// oapi: TS29572_Nlmf_Location.yaml#/components/schemas/PeriodicEventInfo
type periodicEventInfo struct {
	ReportingAmount      int  `json:"reportingAmount"`
	ReportingInterval    int  `json:"reportingInterval"`
	ReportingInfiniteInd bool `json:"reportingInfiniteInd,omitempty"`
	ReportingIntervalMs  int  `json:"reportingIntervalMs,omitempty"`
}

// areaEventInfoIn requests area based event reporting.
//
// oapi: TS29572_Nlmf_Location.yaml#/components/schemas/AreaEventInfo
type areaEventInfoIn struct {
	AreaDefinition       []reportingArea `json:"areaDefinition"`
	OccurrenceInfo       string          `json:"occurrenceInfo,omitempty"`
	MinimumInterval      int             `json:"minimumInterval,omitempty"`
	MaximumInterval      int             `json:"maximumInterval,omitempty"`
	SamplingInterval     int             `json:"samplingInterval,omitempty"`
	ReportingDuration    int             `json:"reportingDuration,omitempty"`
	ReportingLocationReq *bool           `json:"reportingLocationReq,omitempty"`
}

// reportingArea is one area of an area event request.
//
// oapi: TS29572_Nlmf_Location.yaml#/components/schemas/ReportingArea
type reportingArea struct {
	AreaType string    `json:"areaType"`
	Tai      *TaiLoc   `json:"tai,omitempty"`
	Ecgi     *ecgiArea `json:"ecgi,omitempty"`
	Ncgi     *ncgiArea `json:"ncgi,omitempty"`
}

// ncgiArea is an NR cell global identity.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/Ncgi
type ncgiArea struct {
	PlmnId   PlmnID `json:"plmnId"`
	NrCellId string `json:"nrCellId"`
	Nid      string `json:"nid,omitempty"`
}

// ecgiArea is an E-UTRAN cell global identity (accepted, never matched: the
// LMF positions NR cells only).
//
// oapi: TS29571_CommonData.yaml#/components/schemas/Ecgi
type ecgiArea struct {
	PlmnId      PlmnID `json:"plmnId"`
	EutraCellId string `json:"eutraCellId"`
	Nid         string `json:"nid,omitempty"`
}

// locationDataExt is the 200 answer of an accepted deferred DetermineLocation:
// the LocationData of the activation fix plus the optional LocationDataExt
// attributes the LMF fills.
//
// Ref: TS 29.572 §5.2.2.2.2 step 2a, Table 6.1.6.2.3 (LocationDataExt).
//
// oapi: TS29572_Nlmf_Location.yaml#/components/schemas/LocationDataExt
type locationDataExt struct {
	LocationData
	TimestampOfLocationEstimate string             `json:"timestampOfLocationEstimate,omitempty"`
	AcceptedPeriodicEventInfo   *periodicEventInfo `json:"acceptedPeriodicEventInfo,omitempty"`
}

// extTail is the locationDataExt part that follows the embedded LocationData.
type extTail struct {
	TimestampOfLocationEstimate string             `json:"timestampOfLocationEstimate,omitempty"`
	AcceptedPeriodicEventInfo   *periodicEventInfo `json:"acceptedPeriodicEventInfo,omitempty"`
}

// MarshalJSON is declared explicitly because the embedded LocationData has its
// own MarshalJSON, which would otherwise be promoted and drop the tail fields.
// The LocationData object is followed by the tail members (same order as the
// pre-change struct encoding).
func (e locationDataExt) MarshalJSON() ([]byte, error) {
	head, err := json.Marshal(e.LocationData)
	if err != nil {
		return nil, fmt.Errorf("lmf: marshal locationDataExt: %w", err)
	}
	tail, err := json.Marshal(extTail{e.TimestampOfLocationEstimate, e.AcceptedPeriodicEventInfo})
	if err != nil {
		return nil, fmt.Errorf("lmf: marshal locationDataExt: %w", err)
	}
	if string(tail) == "{}" {
		return head, nil
	}
	if string(head) == "{}" {
		return tail, nil
	}
	out := make([]byte, 0, len(head)+len(tail))
	out = append(out, head[:len(head)-1]...)
	out = append(out, ',')
	out = append(out, tail[1:]...)
	return out, nil
}

// UnmarshalJSON decodes the LocationData (both wire shapes) and the tail.
func (e *locationDataExt) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &e.LocationData); err != nil {
		return fmt.Errorf("lmf: decode locationDataExt: %w", err)
	}
	var t extTail
	if err := json.Unmarshal(b, &t); err != nil {
		return fmt.Errorf("lmf: decode locationDataExt: %w", err)
	}
	e.TimestampOfLocationEstimate, e.AcceptedPeriodicEventInfo = t.TimestampOfLocationEstimate, t.AcceptedPeriodicEventInfo
	return nil
}

// deferredSession is the deferred-location part of a subscription. Immutable
// after the session is added to the registry.
type deferredSession struct {
	HgmlcCallBackURI string
	LdrReference     string
	Supi             string
	Gpsi             string

	// ExpiryCause is the terminationCause sent when the session ends because
	// its duration elapsed: NORMAL_TERMINATION for the requested
	// reportingDuration, TERMINATION_BY_NETWORK for an LMF cap.
	ExpiryCause string

	// Periodic.
	ReportingAmount int
	Infinite        bool

	// Area.
	Areas          []reportingArea
	OccurrenceOne  bool
	MinInterval    time.Duration
	MaxInterval    time.Duration
	LocationInRept bool // reportingLocationReq (default true)
	WantEntering   bool // report ENTERING_AREA_EVENT
	WantLeaving    bool // report LEAVING_AREA_EVENT
	ReportInside   bool // report BEING_INSIDE_AREA_EVENT while inside
	InitInside     bool // inside state at the activation fix (baseline)
}

// invalidParam is one ProblemDetails invalidParams entry.
// Ref: TS 29.571 §5.2.4.6 (InvalidParam).
//
// oapi: TS29571_CommonData.yaml#/components/schemas/InvalidParam
type invalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason,omitempty"`
}

// problemInvalid writes a 400 ProblemDetails with invalidParams.
func (s *Server) problemInvalid(w http.ResponseWriter, cause, detail string, params ...invalidParam) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        http.StatusBadRequest,
		"cause":         cause,
		"detail":        detail,
		"invalidParams": params,
	})
}

// validateCallback checks hgmlcCallBackURI / ldrReference (both mandatory for
// the deferred path and for CancelLocData). The callback must be an absolute
// https URI (SBA is always TLS) without userinfo or fragment.
func validateCallback(uri, ldr string) []invalidParam {
	var bad []invalidParam
	if uri == "" {
		bad = append(bad, invalidParam{"/hgmlcCallBackURI", "mandatory attribute missing"})
	} else if reason := callbackURIProblem(uri); reason != "" {
		bad = append(bad, invalidParam{"/hgmlcCallBackURI", reason})
	}
	if ldr == "" {
		bad = append(bad, invalidParam{"/ldrReference", "mandatory attribute missing"})
	} else if !ldrReferencePattern.MatchString(ldr) {
		bad = append(bad, invalidParam{"/ldrReference", "does not match ^([0-9a-fA-F]{2}){1,255}$"})
	}
	return bad
}

// callbackURIProblem returns why uri is not an acceptable callback URI, or "".
func callbackURIProblem(uri string) string {
	u, err := url.Parse(uri)
	switch {
	case err != nil || u.Host == "" || u.Scheme == "":
		return "not an absolute URI"
	case u.Scheme != "https":
		return "scheme must be https"
	case u.User != nil:
		return "userinfo is not allowed"
	case u.Fragment != "" || strings.Contains(uri, "#"):
		return "fragment is not allowed"
	}
	return ""
}

func inRange(v, lo, hi int) bool { return v >= lo && v <= hi }

// validateDeferred checks the deferred request attributes against the YAML and
// the InputData presence conditions (ldrType <-> periodic/area information).
func validateDeferred(d *deferredInputData) []invalidParam {
	// An ldrType value outside the LdrType enumeration is ignored (treated as
	// absent). Ref: TS 29.500 §6.6.2 "Unknown attributes and values shall be ignored".
	switch d.LdrType {
	case "", ldrTypePeriodic, ldrTypeEntering, ldrTypeLeaving, ldrTypeInside, ldrTypeMotion, ldrTypeUEAvailable:
	default:
		d.LdrType = ""
	}
	bad := validateCallback(d.HgmlcCallBackURI, d.LdrReference)
	if d.PeriodicEventInfo != nil && d.AreaEventInfo != nil {
		bad = append(bad, invalidParam{"/areaEventInfo", "periodicEventInfo and areaEventInfo are mutually exclusive"})
		return bad
	}
	// InputData: periodicEventInfo is present iff ldrType is PERIODIC;
	// areaEventInfo iff ldrType is an area type. Without ldrType the
	// information present selects the type.
	// Ref: TS 29.572 Table 6.1.6.2.2-1.
	switch d.LdrType {
	case "":
	case ldrTypePeriodic:
		if d.PeriodicEventInfo == nil {
			bad = append(bad, invalidParam{"/periodicEventInfo", "mandatory when ldrType is PERIODIC"})
		}
	case ldrTypeEntering, ldrTypeLeaving, ldrTypeInside:
		if d.AreaEventInfo == nil {
			bad = append(bad, invalidParam{"/areaEventInfo", "mandatory when ldrType is " + d.LdrType})
		}
	default: // UE_AVAILABLE (MOTION is rejected earlier as unsupported)
		bad = append(bad, invalidParam{"/ldrType", "does not select periodic or area event reporting"})
		return bad
	}
	if d.LdrType == ldrTypePeriodic && d.AreaEventInfo != nil {
		bad = append(bad, invalidParam{"/areaEventInfo", "not allowed when ldrType is PERIODIC"})
	}
	if d.PeriodicEventInfo != nil && d.LdrType != "" && d.LdrType != ldrTypePeriodic {
		bad = append(bad, invalidParam{"/periodicEventInfo", "not allowed when ldrType is " + d.LdrType})
	}
	if p := d.PeriodicEventInfo; p != nil {
		if !inRange(p.ReportingAmount, 1, maxReportingAmount) {
			bad = append(bad, invalidParam{"/periodicEventInfo/reportingAmount", "required, 1..8639999"})
		}
		if !inRange(p.ReportingInterval, 1, maxReportingIntervalS) {
			bad = append(bad, invalidParam{"/periodicEventInfo/reportingInterval", "required, 1..8639999"})
		}
		if p.ReportingIntervalMs != 0 && !inRange(p.ReportingIntervalMs, 1, maxReportingIntervalMs) {
			bad = append(bad, invalidParam{"/periodicEventInfo/reportingIntervalMs", "1..999"})
		}
		// reportingAmount x reportingInterval <= 8639999 (Table 6.1.6.2.24-1
		// NOTE). The amount is ignored with reportingInfiniteInd and the
		// interval with reportingIntervalMs.
		if !p.ReportingInfiniteInd && p.ReportingIntervalMs == 0 &&
			int64(p.ReportingAmount)*int64(p.ReportingInterval) > maxReportingProduct {
			bad = append(bad, invalidParam{"/periodicEventInfo/reportingAmount",
				"reportingAmount x reportingInterval shall not exceed 8639999"})
		}
	}
	if a := d.AreaEventInfo; a != nil {
		if !inRange(len(a.AreaDefinition), 1, maxAreaDefinitions) {
			bad = append(bad, invalidParam{"/areaEventInfo/areaDefinition", "required, 1..250 items"})
		}
		for i, ar := range a.AreaDefinition {
			if ar.AreaType == "" {
				bad = append(bad, invalidParam{fmt.Sprintf("/areaEventInfo/areaDefinition/%d/areaType", i), "mandatory attribute missing"})
			}
		}
		for _, c := range []struct {
			name   string
			v, max int
		}{
			{"minimumInterval", a.MinimumInterval, maxMinimumInterval},
			{"maximumInterval", a.MaximumInterval, maxMaximumInterval},
			{"samplingInterval", a.SamplingInterval, maxSamplingInterval},
			{"reportingDuration", a.ReportingDuration, maxReportingDuration},
		} {
			if c.v != 0 && !inRange(c.v, 1, c.max) {
				bad = append(bad, invalidParam{"/areaEventInfo/" + c.name, fmt.Sprintf("1..%d", c.max)})
			}
		}
		if a.OccurrenceInfo == occurrenceOneTime && (a.MinimumInterval != 0 || a.MaximumInterval != 0) {
			bad = append(bad, invalidParam{"/areaEventInfo/minimumInterval",
				"minimumInterval / maximumInterval shall not be included with ONE_TIME_EVENT"})
		}
	}
	return bad
}

// sessionLimit returns the bound on concurrent deferred-location sessions.
func (s *Server) sessionLimit() int {
	if s.deferredLimit > 0 {
		return s.deferredLimit
	}
	return maxDeferredSessions
}

// unit returns the duration of one "second" of a deferred-location parameter
// (time.Second in production; shortened by tests).
func (s *Server) unit() time.Duration {
	if s.timeUnit > 0 {
		return s.timeUnit
	}
	return time.Second
}

// mulDur returns n*d saturating at the maximum Duration (no int64 overflow).
func mulDur(n int64, d time.Duration) time.Duration {
	if n <= 0 || d <= 0 {
		return 0
	}
	if n > math.MaxInt64/int64(d) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(n) * d
}

// goBG runs f on a tracked goroutine; it reports false (f not run) once the
// server is draining.
func (s *Server) goBG(f func()) bool {
	s.bgMu.Lock()
	defer s.bgMu.Unlock()
	if s.bgClosed {
		return false
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		f()
	}()
	return true
}

// drainBG stops accepting tracked goroutines and waits for the running ones
// (or ctx).
func (s *Server) drainBG(ctx context.Context) {
	s.bgMu.Lock()
	s.bgClosed = true
	s.bgMu.Unlock()
	done := make(chan struct{})
	go func() { s.bg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// procDeferred increments the shared fivegc_procedure_total counter for the
// DeferredLocation procedure (activation, rejection or CancelLocation).
// result is OK, REJECT or FAILURE.
func procDeferred(result string) {
	metrics.ProcedureTotal.WithLabelValues("LMF", "DeferredLocation", result).Inc()
}

// startDeferredLocation implements the deferred branch of DetermineLocation:
// one immediate position fix, then the session on the subscription engine, and
// the 200 LocationDataExt answer. d has been validated. It returns true when
// the session was created and answered.
//
// Ref: TS 29.572 §5.2.2.2.2 step 2a; TS 23.273 §6.3.
func (s *Server) startDeferredLocation(ctx context.Context, w http.ResponseWriter, d *deferredInputData, ueContextID, supi, sfAnswer string) bool {
	start := time.Now()
	corrID := logging.CorrelationID(ctx)
	log := logging.NewProcedureLogger(ctx, s.logger, "DeferredLocation").With(
		"nf", "LMF",
		"interface", "Nlmf",
		"direction", "IN",
		"spec_ref", "TS 29.572 §5.2.2.2.2",
		"correlation_id", corrID,
		"supi", supi,
	)
	reject503 := func() {
		log.Warn("DeferredLocation: session limit reached",
			"result", "REJECT", "cause", "NF_CONGESTION", "spec_ref", "TS 29.500 §5.2.7.2")
		metrics.LMFLocateTotal.WithLabelValues("REJECT").Inc()
		procDeferred("REJECT")
		s.problem(w, http.StatusServiceUnavailable, "NF_CONGESTION", "too many deferred location sessions")
	}
	// Cheap early check; the authoritative one is atomic with the insert.
	if _, replacing := s.registry.findDeferred(d.LdrReference, d.HgmlcCallBackURI); !replacing &&
		s.registry.countDeferred() >= s.sessionLimit() {
		reject503()
		return false
	}

	// Immediate fix: locationEstimate is mandatory in the 200 answer. A failure
	// is answered as the immediate path does and creates no session.
	loc, cause, err := s.locate(ctx, ueContextID, supi)
	if err != nil {
		procDeferred("FAILURE")
		s.locateFailed(log, w, err, cause, start)
		return false
	}
	fixedAt := time.Now().UTC()

	unit := s.unit()
	maxDuration := time.Duration(s.cfg.LocationSubscription.MaxDurationS) * unit
	if maxDuration <= 0 {
		maxDuration = defaultMaxDuration
	}
	ds := &deferredSession{
		HgmlcCallBackURI: d.HgmlcCallBackURI,
		LdrReference:     d.LdrReference,
		Supi:             d.Supi,
		Gpsi:             d.Gpsi,
		LocationInRept:   true,
		ExpiryCause:      terminationByNetwork,
	}
	sub := &subscription{
		SubId:       uuid.NewString(),
		UEContextId: ueContextID,
		Created:     time.Now().UTC(),
		State:       aoiStateUnknown,
		deferred:    ds,
	}
	duration := maxDuration
	var accepted *periodicEventInfo
	if p := d.PeriodicEventInfo; p != nil {
		sub.EventTrigger = EventTriggerPeriodic
		// reportingIntervalMs, when present, replaces reportingInterval
		// (Table 6.1.6.2.24-1).
		if p.ReportingIntervalMs > 0 {
			sub.ReportingInterval = time.Duration(p.ReportingIntervalMs) * time.Millisecond
		} else {
			sub.ReportingInterval = mulDur(int64(p.ReportingInterval), unit)
		}
		ds.ReportingAmount = p.ReportingAmount
		ds.Infinite = p.ReportingInfiniteInd
		if !p.ReportingInfiniteInd {
			// Run long enough for reportingAmount reports (+ one interval of slack).
			if want := mulDur(int64(p.ReportingAmount)+1, sub.ReportingInterval); want > 0 && want < duration {
				duration = want
			}
		}
		if p.ReportingInfiniteInd || p.ReportingIntervalMs > 0 {
			cp := *p
			accepted = &cp
		}
	} else {
		a := d.AreaEventInfo
		sub.EventTrigger = EventTriggerAOI
		sub.SamplingInterval = time.Duration(s.cfg.LocationSubscription.DefaultSamplingIntervalS) * unit
		if a.SamplingInterval > 0 {
			sub.SamplingInterval = mulDur(int64(a.SamplingInterval), unit)
		}
		ds.Areas = a.AreaDefinition
		ds.OccurrenceOne = a.OccurrenceInfo == occurrenceOneTime
		ds.MinInterval = mulDur(int64(a.MinimumInterval), unit)
		ds.MaxInterval = mulDur(int64(a.MaximumInterval), unit)
		if a.ReportingLocationReq != nil {
			ds.LocationInRept = *a.ReportingLocationReq
		}
		switch d.LdrType {
		case ldrTypeEntering:
			ds.WantEntering = true
		case ldrTypeLeaving:
			ds.WantLeaving = true
		case ldrTypeInside:
			ds.ReportInside = true
		default: // ldrType absent: the legacy "crossing" behaviour
			ds.WantEntering, ds.WantLeaving = true, true
		}
		ds.InitInside = areaContains(ds.Areas, loc)
		if a.ReportingDuration > 0 {
			if rd := mulDur(int64(a.ReportingDuration), unit); rd <= duration {
				duration = rd
				ds.ExpiryCause = terminationNormal
			}
		}
	}
	if sub.ReportingInterval <= 0 && sub.SamplingInterval <= 0 {
		// Misconfigured defaults (zero config): keep the ticker valid.
		sub.SamplingInterval = unit
	}
	sub.Duration = duration
	gctx, cancel := context.WithTimeout(context.Background(), duration)
	sub.cancel = cancel

	replaced, ok := s.registry.addDeferred(sub, s.sessionLimit())
	if !ok {
		cancel()
		reject503()
		return false
	}
	if replaced != nil {
		log.Info("DeferredLocation: session replaced by a re-sent request",
			"ldr_reference", d.LdrReference, "replaced_sub_id", replaced.SubId, "sub_id", sub.SubId,
			"spec_ref", "TS 29.572 §5.2.2.2.2")
	}
	if !s.goBG(func() { s.runSubscription(gctx, sub.SubId, supi, corrID) }) {
		s.registry.delete(sub.SubId)
		metrics.LMFSubscriptionsActive.Set(float64(s.registry.count()))
		log.Warn("DeferredLocation: server is shutting down",
			"result", "REJECT", "cause", "NF_CONGESTION", "spec_ref", "TS 29.500 §5.2.7.2")
		metrics.LMFLocateTotal.WithLabelValues("REJECT").Inc()
		procDeferred("REJECT")
		s.problem(w, http.StatusServiceUnavailable, "NF_CONGESTION", "LMF is shutting down")
		return false
	}
	metrics.LMFSubscriptionsActive.Set(float64(s.registry.count()))

	log.Info("DeferredLocation: session created",
		"result", "OK",
		"sub_id", sub.SubId,
		"ldr_reference", d.LdrReference,
		"event_trigger", sub.EventTrigger,
		"ldr_type", d.LdrType,
		"duration_ms", time.Since(start).Milliseconds(),
		"spec_ref", "TS 29.572 §5.2.2.2.2",
	)
	metrics.LMFLocateTotal.WithLabelValues("OK").Inc()
	procDeferred("OK")

	// 200 LocationDataExt: successful activation of periodic or triggered
	// location (Table 6.1.4.2.2-2); reports follow as EventNotify callbacks.
	out := locationDataExt{
		LocationData:                loc.wireFor(features.SpecLiteral(s.profile)),
		TimestampOfLocationEstimate: fixedAt.Format(time.RFC3339),
		AcceptedPeriodicEventInfo:   accepted,
	}
	out.SupportedFeatures = sfAnswer
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(&out)
	return true
}

// deferredState is the per-goroutine state of a deferred session.
type deferredState struct {
	inside     bool
	reports    int
	failures   int // consecutive positioning failures
	lastReport time.Time
}

// newDeferredState seeds the state from the activation fix.
func newDeferredState(snap *subscription) deferredState {
	return deferredState{inside: snap.deferred.InitInside, lastReport: snap.Created}
}

// deferredTick evaluates one location sample for a deferred session and sends
// the due event report. It returns true when the session has ended and must be
// removed (reportingAmount reached / one-time event).
//
// Ref: TS 29.572 callback EventNotify; TS 23.273 §6.3.
func (s *Server) deferredTick(ctx context.Context, snap *subscription, loc *LocationData, fixedAt time.Time, st *deferredState, corrID string) bool {
	ds := snap.deferred
	now := time.Now()

	if snap.EventTrigger == EventTriggerPeriodic {
		st.reports++
		last := !ds.Infinite && st.reports >= ds.ReportingAmount
		cause := ""
		if last {
			cause = terminationNormal
		}
		s.sendEventNotify(ctx, snap, loc, fixedAt, reportedPeriodicEvent, cause, corrID)
		st.lastReport = now
		return last
	}

	inside := areaContains(ds.Areas, loc)
	event := ""
	switch {
	case ds.ReportInside:
		// BEING_INSIDE_AREA: report every sample taken while inside, no more
		// often than minimumInterval.
		due := st.reports == 0 || ds.MinInterval <= 0 || now.Sub(st.lastReport) >= ds.MinInterval
		if inside && due {
			event = reportedBeingInsideEvent
		}
	case inside != st.inside:
		wanted := (inside && ds.WantEntering) || (!inside && ds.WantLeaving)
		if !wanted {
			st.inside = inside // transition of a type that was not requested
			break
		}
		if ds.MinInterval > 0 && now.Sub(st.lastReport) < ds.MinInterval {
			return false // minimumInterval: hold the transition, state not advanced
		}
		st.inside = inside
		event = reportedEnteringAreaEvent
		if !inside {
			event = reportedLeavingAreaEvent
		}
	}
	if event == "" && ds.MaxInterval > 0 && now.Sub(st.lastReport) >= ds.MaxInterval {
		event = reportedMaxIntervalExpiration
	}
	if event == "" {
		return false
	}
	cause := ""
	if ds.OccurrenceOne {
		cause = terminationNormal
	}
	s.sendEventNotify(ctx, snap, loc, fixedAt, event, cause, corrID)
	st.reports++
	st.lastReport = now
	return ds.OccurrenceOne
}

// areaContains reports whether the located cell/TAI matches any reporting area.
func areaContains(areas []reportingArea, loc *LocationData) bool {
	for _, a := range areas {
		switch a.AreaType {
		case areaTypeTai:
			if a.Tai != nil && loc.Tai != nil && a.Tai.PlmnId == loc.Tai.PlmnId &&
				trimHex(a.Tai.Tac) == trimHex(loc.Tai.Tac) {
				return true
			}
		case areaTypeNcgi:
			if a.Ncgi != nil && loc.NRCellId != "" && trimHex(a.Ncgi.NrCellId) == trimHex(loc.NRCellId) {
				return true
			}
		case areaTypeEcgi, areaTypeEpsT:
			// EPS areas are never matched: the LMF positions NR cells only.
		}
	}
	return false
}

// trimHex normalises a hex identifier: lower case, leading zeros removed.
func trimHex(h string) string { return strings.TrimLeft(strings.ToLower(h), "0") }

// sendEventNotify builds and delivers an EventNotifyData to the session's
// hgmlcCallBackURI, with the configured retry on error. fixedAt is the time of
// the position fix in loc.
//
// Ref: TS 29.572 callback EventNotify (204 expected).
func (s *Server) sendEventNotify(ctx context.Context, snap *subscription, loc *LocationData, fixedAt time.Time, eventType, termination, corrID string) {
	ds := snap.deferred
	n := EventNotifyData{
		ReportedEventType: eventType,
		Supi:              ds.Supi,
		Gpsi:              ds.Gpsi,
		HgmlcCallBackURI:  ds.HgmlcCallBackURI,
		LdrReference:      ds.LdrReference,
		TerminationCause:  termination,
	}
	if loc != nil && ds.LocationInRept {
		age := loc.AgeOfLocationEstimate
		n.LocationEstimate = loc.LocationEstimate
		n.AgeOfLocationEstimate = &age
		n.TimestampOfLocationEstimate = fixedAt.UTC().Format(time.RFC3339)
	}
	log := s.logger.With(
		"nf", "LMF",
		"procedure", "DeferredLocation",
		"interface", "Nlmf-notify",
		"direction", "OUT",
		"spec_ref", "TS 29.572 callback EventNotify",
		"sub_id", snap.SubId,
		"ldr_reference", ds.LdrReference,
		"reported_event_type", eventType,
		"correlation_id", corrID,
	)
	en, ok := s.notifClient.(EventNotifier)
	if !ok {
		log.WarnContext(ctx, "DeferredLocation: notification client cannot deliver EventNotify",
			"result", "DROPPED")
		return
	}
	attempts := 1 + s.cfg.LocationSubscription.NotificationRetry
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 1; i <= attempts; i++ {
		if err = en.PostEventNotify(ctx, ds.HgmlcCallBackURI, n); err == nil {
			log.InfoContext(ctx, "DeferredLocation: EventNotify delivered",
				"result", resultLabel(i), "notify_attempt", i, "termination_cause", termination)
			metrics.LMFNotificationsTotal.WithLabelValues(snap.EventTrigger, resultLabel(i)).Inc()
			s.registry.markNotified(snap.SubId)
			return
		}
		log.WarnContext(ctx, "DeferredLocation: EventNotify attempt failed",
			"result", "RETRIED", "notify_attempt", i, "error", err)
	}
	log.WarnContext(ctx, "DeferredLocation: EventNotify dropped after all retries",
		"result", "DROPPED", "notify_attempt", attempts, "error", err)
	metrics.LMFNotificationsTotal.WithLabelValues(snap.EventTrigger, "DROPPED").Inc()
}

// sendTermination sends the final LOCATION_CANCELLATION_EVENT of a session the
// LMF itself ended outside a tick (duration expiry, repeated positioning
// failure), on a fresh bounded context. It is never used for a GMLC-initiated
// CancelLocation (TS 23.273 §6.3.3 step 5) nor on server shutdown.
func (s *Server) sendTermination(snap *subscription, cause string) {
	ctx, cancel := context.WithTimeout(context.Background(), deferredNotifyTimeout)
	defer cancel()
	corrID := uuid.NewString()
	s.sendEventNotify(logging.WithCorrelationID(ctx, corrID), snap, nil, time.Time{}, reportedLocationCancellation, cause, corrID)
}

// cancelDeferred implements CancelLocation for a deferred session identified
// by (ldrReference, hgmlcCallBackURI): the session is removed atomically and
// no EventNotify is sent (the GMLC initiated the release). It reports whether a
// session existed.
//
// Ref: TS 29.572 §5.2.2.4.2; TS 23.273 §6.3.3 step 5.
func (s *Server) cancelDeferred(ldr, uri string) bool {
	if _, ok := s.registry.deleteDeferred(ldr, uri); !ok {
		return false
	}
	metrics.LMFSubscriptionsActive.Set(float64(s.registry.count()))
	return true
}

// decodeDeferred extracts the deferred attributes from the request body with a
// Decoder on the first JSON value, exactly as the main decoder reads it. A
// type error on them is returned; syntax errors are left to the main decoder
// (which already rejected or tolerated the same bytes).
func decodeDeferred(body []byte) (*deferredInputData, error) {
	var d deferredInputData
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&d); err != nil {
		var ute *json.UnmarshalTypeError
		if errors.As(err, &ute) {
			return nil, err
		}
		return nil, nil
	}
	return &d, nil
}
