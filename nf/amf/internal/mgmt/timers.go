package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/timercfg"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// Bounds of the runtime-changeable UE lifecycle timers. They are lab limits
// chosen by the project; the network chooses these values (TS 24.501 §5.3.7).
const (
	// minT3512Secs is the lowest T3512 accepted. TS 24.501 §10.2 Table 10.2.1
	// default is 54 min; 60 s is a lab-only minimum.
	minT3512Secs = 60
	// maxT3512Secs is a conservative 24 h cap (GPRS timer 3 reaches 31 x 320 h).
	maxT3512Secs = 86400
	// minMobileReachableGuardSecs: 0 is allowed as a lab convenience. This is a
	// lab-only deviation: with guard 0 the mobile reachable timer equals T3512
	// rather than being "longer than" it (TS 24.501 §5.3.7). The implicit
	// de-registration timer (>= 60 s) still gives margin. Keep guard >= 1 in
	// operation (TS default: 4 minutes greater than T3512).
	minMobileReachableGuardSecs = 0
	// maxMobileReachableGuardSecs is a lab sanity cap. TS 24.501 §5.3.7 default
	// guard is 4 min.
	maxMobileReachableGuardSecs = 3600
	// minImplicitDetachSecs / maxImplicitDetachSecs bound the implicit
	// de-registration timer, whose value is network dependent (TS 24.501 §5.3.7).
	minImplicitDetachSecs = 60
	maxImplicitDetachSecs = 86400

	// timerConfigMaxBody is the PUT body size limit in bytes.
	timerConfigMaxBody = 4096

	timerConfigProcedure = "TimerConfigChange"
	// timerConfigSpecRef is the spec_ref of the canonical log line.
	timerConfigSpecRef = "TS 24.501 §5.3.7"
	// timerConfigRespSpecRef is echoed in the response body.
	timerConfigRespSpecRef = "TS 24.501 §5.3.7, §10.2; TS 23.501 §5.4.1.1"
	// timerConfigPath is the mgmt route.
	timerConfigPath = "/amf/v1/config/timers"

	problemContentType = "application/problem+json"
)

// Problem causes of the timer config API (project-defined, HTTP 400).
const (
	causeT3512OutOfRange     = "T3512_OUT_OF_RANGE"
	causeT3512NotRepresent   = "T3512_NOT_REPRESENTABLE"
	causeGuardOutOfRange     = "GUARD_OUT_OF_RANGE"
	causeImplicitOutOfRange  = "IMPLICIT_DETACH_OUT_OF_RANGE"
	causeReadOnlyField       = "READ_ONLY_FIELD"
	causeUnknownField        = "UNKNOWN_FIELD"
	causeMalformedRequest    = "MALFORMED_REQUEST"
	causeResetExclusive      = "RESET_EXCLUSIVE"
	causeNoChange            = "NO_CHANGE"
	timerFieldT3512          = "t3512_secs"
	timerFieldGuard          = "mobile_reachable_guard_secs"
	timerFieldImplicitDetach = "implicit_detach_secs"
	timerFieldMobileReach    = "mobile_reachable_secs"
	timerFieldReset          = "reset"
)

// TimerValues is the JSON shape of one set of timer values.
type TimerValues struct {
	T3512Secs            int `json:"t3512_secs"`
	MobileReachableGuard int `json:"mobile_reachable_guard_secs"`
	MobileReachableSecs  int `json:"mobile_reachable_secs"`
	ImplicitDetachSecs   int `json:"implicit_detach_secs"`
}

// TimerConfigResponse is the 200 body of GET and PUT /amf/v1/config/timers.
type TimerConfigResponse struct {
	Effective TimerValues `json:"effective"`
	Base      TimerValues `json:"base"`
	Persisted bool        `json:"persisted"`
	SpecRef   string      `json:"spec_ref"`
}

// TimerProblem is the 400 body (ProblemDetails-like).
type TimerProblem struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Cause  string `json:"cause"`
}

func toTimerValues(v timercfg.Values) TimerValues {
	return TimerValues{
		T3512Secs:            v.T3512Secs,
		MobileReachableGuard: v.GuardSecs,
		MobileReachableSecs:  v.MobileReachableSecs(),
		ImplicitDetachSecs:   v.ImplicitDetachSecs,
	}
}

// gprsTimer3Secs decodes a GPRS timer 3 octet (TS 24.008 §10.5.7.4a) to
// seconds; ok is false for the "deactivated" unit.
func gprsTimer3Secs(b byte) (secs int, ok bool) {
	val := int(b & 0x1F)
	switch b >> 5 {
	case 0:
		return val * 600, true
	case 1:
		return val * 3600, true
	case 2:
		return val * 36000, true
	case 3:
		return val * 2, true
	case 4:
		return val * 30, true
	case 5:
		return val * 60, true
	case 6:
		return val * 1152000, true
	}
	return 0, false
}

// t3512Representable reports whether secs survives nas.EncodeGPRSTimer3
// unchanged (the encoder otherwise silently floors to minutes).
func t3512Representable(secs int) bool {
	got, ok := gprsTimer3Secs(nas.EncodeGPRSTimer3(secs))
	return ok && got == secs
}

// nearestRepresentable returns the closest representable T3512 below and above
// secs inside the accepted bounds (0 when none).
func nearestRepresentable(secs int) (lower, higher int) {
	var all []int
	for _, mul := range []int{600, 3600, 2, 30, 60} {
		for v := 1; v <= 31; v++ {
			if x := v * mul; x >= minT3512Secs && x <= maxT3512Secs && t3512Representable(x) {
				all = append(all, x)
			}
		}
	}
	sort.Ints(all)
	for _, x := range all {
		if x < secs {
			lower = x
		} else if x > secs && higher == 0 {
			higher = x
		}
	}
	return lower, higher
}

type timerRequest struct {
	t3512, guard, implicit *int
	reset                  bool
}

type timerReject struct {
	cause, detail string
}

func (r *timerReject) Error() string { return r.cause + ": " + r.detail }

// parseTimerRequest decodes and validates the PUT body, all-or-nothing.
func parseTimerRequest(body []byte) (*timerRequest, *timerReject) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, &timerReject{causeNoChange, "empty body: nothing to change"}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil || raw == nil {
		return nil, &timerReject{causeMalformedRequest, "body is not a valid JSON object"}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, &timerReject{causeMalformedRequest, "trailing data after JSON object"}
	}
	req := &timerRequest{}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch k {
		case timerFieldT3512, timerFieldGuard, timerFieldImplicitDetach:
			var n int
			if err := json.Unmarshal(raw[k], &n); err != nil || bytes.Equal(bytes.TrimSpace(raw[k]), []byte("null")) {
				return nil, &timerReject{causeMalformedRequest, k + " must be an integer"}
			}
			switch k {
			case timerFieldT3512:
				req.t3512 = &n
			case timerFieldGuard:
				req.guard = &n
			default:
				req.implicit = &n
			}
		case timerFieldReset:
			if err := json.Unmarshal(raw[k], &req.reset); err != nil {
				return nil, &timerReject{causeMalformedRequest, "reset must be a boolean"}
			}
		case timerFieldMobileReach:
			return nil, &timerReject{causeReadOnlyField, "mobile_reachable_secs is derived (t3512_secs + mobile_reachable_guard_secs) and read-only"}
		default:
			return nil, &timerReject{causeUnknownField, fmt.Sprintf("unknown field %q", k)}
		}
	}
	hasValue := req.t3512 != nil || req.guard != nil || req.implicit != nil
	if req.reset && hasValue {
		return nil, &timerReject{causeResetExclusive, "reset:true cannot be combined with value fields"}
	}
	if !req.reset && !hasValue {
		return nil, &timerReject{causeNoChange, "no value field and reset is not true: nothing to change"}
	}
	if v := req.t3512; v != nil {
		if *v < minT3512Secs || *v > maxT3512Secs {
			return nil, &timerReject{causeT3512OutOfRange, fmt.Sprintf("t3512_secs must be within %d..%d", minT3512Secs, maxT3512Secs)}
		}
		if !t3512Representable(*v) {
			lo, hi := nearestRepresentable(*v)
			return nil, &timerReject{causeT3512NotRepresent, fmt.Sprintf(
				"t3512_secs %d is not exactly representable in GPRS timer 3 (TS 24.008 §10.5.7.4a); nearest lower %d, nearest higher %d", *v, lo, hi)}
		}
	}
	if v := req.guard; v != nil && (*v < minMobileReachableGuardSecs || *v > maxMobileReachableGuardSecs) {
		return nil, &timerReject{causeGuardOutOfRange, fmt.Sprintf("mobile_reachable_guard_secs must be within %d..%d", minMobileReachableGuardSecs, maxMobileReachableGuardSecs)}
	}
	if v := req.implicit; v != nil && (*v < minImplicitDetachSecs || *v > maxImplicitDetachSecs) {
		return nil, &timerReject{causeImplicitOutOfRange, fmt.Sprintf("implicit_detach_secs must be within %d..%d", minImplicitDetachSecs, maxImplicitDetachSecs)}
	}
	return req, nil
}

// TimerConfigHandler serves GET and PUT /amf/v1/config/timers on the plain-HTTP
// mgmt port: read or change T3512, the mobile reachable guard and the implicit
// de-registration timer at runtime (not persisted; reset:true restores the
// startup values). Mobile reachable is always T3512 + guard. Method-less
// registration is done by RegisterTimerConfig; other methods answer 405.
// Ref: TS 24.501 §5.3.7, §10.2 Table 10.2.1; TS 23.501 §5.4.1.1.
func TimerConfigHandler(store *timercfg.Store, logger *slog.Logger) http.Handler {
	var mu sync.Mutex // serialises read-modify-write of partial PUTs
	respond := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TimerConfigResponse{
			Effective: toTimerValues(store.Effective()),
			Base:      toTimerValues(store.Base()),
			Persisted: false,
			SpecRef:   timerConfigRespSpecRef,
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := logging.WithCorrelationID(r.Context(), r.Header.Get(correlationHeader))
		l := logging.NewProcedureLogger(ctx, logger, timerConfigProcedure)
		switch r.Method {
		case http.MethodGet:
			l.DebugContext(ctx, "timer configuration read",
				"interface", "OAM", "direction", "IN", "spec_ref", timerConfigSpecRef, "result", "OK")
			respond(w)
		case http.MethodPut:
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, timerConfigMaxBody))
			var rej *timerReject
			var req *timerRequest
			if err != nil {
				rej = &timerReject{causeMalformedRequest, "request body unreadable or too large"}
			} else {
				req, rej = parseTimerRequest(body)
			}
			if rej != nil {
				metrics.ProcedureTotal.WithLabelValues(anReleaseNF, timerConfigProcedure, "REJECT").Inc()
				l.WarnContext(ctx, "timer configuration change rejected",
					"interface", "OAM", "direction", "IN", "spec_ref", timerConfigSpecRef,
					"result", "REJECT", "cause", rej.cause, "detail", rej.detail)
				w.Header().Set("Content-Type", problemContentType)
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(TimerProblem{
					Status: http.StatusBadRequest, Title: "Invalid timer configuration",
					Detail: rej.detail, Cause: rej.cause,
				})
				return
			}
			mu.Lock()
			old := store.Effective()
			cur := old
			switch {
			case req.reset:
				store.Reset()
				cur = store.Effective()
			default:
				if req.t3512 != nil {
					cur.T3512Secs = *req.t3512
				}
				if req.guard != nil {
					cur.GuardSecs = *req.guard
				}
				if req.implicit != nil {
					cur.ImplicitDetachSecs = *req.implicit
				}
				store.Set(cur)
			}
			mu.Unlock()
			metrics.ProcedureTotal.WithLabelValues(anReleaseNF, timerConfigProcedure, "OK").Inc()
			l.InfoContext(ctx, "timer configuration changed",
				"interface", "OAM", "direction", "IN", "spec_ref", timerConfigSpecRef, "result", "OK",
				"reset", req.reset,
				"t3512_secs_old", old.T3512Secs, "t3512_secs_new", cur.T3512Secs,
				"mobile_reachable_secs_old", old.MobileReachableSecs(), "mobile_reachable_secs_new", cur.MobileReachableSecs(),
				"implicit_detach_secs_old", old.ImplicitDetachSecs, "implicit_detach_secs_new", cur.ImplicitDetachSecs)
			respond(w)
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// RegisterTimerConfig wires GET/PUT /amf/v1/config/timers on mux. The route is
// method-less so every other method reaches the handler's 405 (Allow: GET, PUT).
func RegisterTimerConfig(mux *http.ServeMux, store *timercfg.Store, logger *slog.Logger) {
	mux.Handle(timerConfigPath, TimerConfigHandler(store, logger))
}
