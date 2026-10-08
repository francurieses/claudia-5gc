package server

// slice_qos.go — internal (NON-3GPP) per (S-NSSAI, DNN) Session-AMBR endpoints
// under /nudr-internal/v1/slice-dnn-qos (UDR-003).
//
// The only 3GPP-visible effect is the sessionAmbr value in sm-data
// (TS 29.503 §6.1.6.2.9); BitRate strings follow TS 29.571 §5.5.2.
// Design contract: docs/procedures/SliceSessionAmbrConfig.md.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/francurieses/claudia-5gc/nf/udr/internal/qos"
	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	sliceQoSProcedure = "SliceSessionAmbrConfig"
	sliceQoSInterface = "Nudr-internal"
	// specRefSessionAMBR: subscribed Session-AMBR is a subscription parameter.
	specRefSessionAMBR = "TS 23.501 §5.7.2.6"
	// specRefDnnConfig: DnnConfiguration.sessionAmbr in sm-data.
	specRefDnnConfig = "TS 29.503 §6.1.6.2.9"
	// maxDNNLen bounds the DNN path parameter. (TS 23.003 §9.1: a DNN is at most 100 octets).
	maxDNNLen = 100
	// maxSliceQoSBody bounds the PUT body.
	maxSliceQoSBody = 4096
	// noSDPathToken is the path token meaning "slice without SD".
	noSDPathToken = "-"
)

// invalidParam is a TS 29.571 InvalidParam (ProblemDetails.invalidParams).
type invalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason,omitempty"`
}

// sliceQoSView is the SliceDnnQos JSON object of the internal API.
type sliceQoSView struct {
	Snssai             sliceQoSSnssai `json:"snssai"`
	DNN                string         `json:"dnn"`
	SessionAMBR        store.AMBR     `json:"sessionAmbr"`
	Source             string         `json:"source"`
	DefaultSessionAMBR store.AMBR     `json:"defaultSessionAmbr"`
	DefaultSource      string         `json:"defaultSource"`
	UpdatedAt          time.Time      `json:"updatedAt"`
}

type sliceQoSSnssai struct {
	SST uint8  `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

func toSliceQoSView(q store.SliceDNNQoS) sliceQoSView {
	return sliceQoSView{
		Snssai: sliceQoSSnssai{SST: q.SST, SD: q.SD}, DNN: q.DNN,
		SessionAMBR: q.SessionAMBR, Source: q.Source,
		DefaultSessionAMBR: q.SeedAMBR, DefaultSource: q.SeedSource,
		UpdatedAt: q.UpdatedAt.UTC(),
	}
}

type resyncView struct {
	AffectedSubscribers int                   `json:"affectedSubscribers"`
	Synced              int                   `json:"synced"`
	Failed              []store.ResyncFailure `json:"failed"`
}

type sliceQoSWriteResponse struct {
	Item    sliceQoSView `json:"item"`
	Changed bool         `json:"changed"`
	Resync  resyncView   `json:"resync"`
}

// SetSliceQoSSeed gives the server the validated operator.yaml seed entries so a
// PUT on an unseeded key computes the same revert target as the startup seed.
func (s *Server) SetSliceQoSSeed(entries []store.OperatorSeedEntry) {
	m := make(map[store.SliceKey]store.AMBR, len(entries))
	for _, e := range entries {
		m[e.Key] = e.AMBR
	}
	s.operatorSeed = m
}

// SetKnownDNNs restricts the DNNs accepted by PUT to the operator.yaml dnns[]
// list (case-insensitive). An empty list disables the check (syntax only).
func (s *Server) SetKnownDNNs(dnns []string) {
	m := make(map[string]struct{}, len(dnns))
	for _, d := range dnns {
		m[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}
	s.knownDNNs = m
}

// seedRowFor returns the seed row of a key: operator entry, else the default.
func (s *Server) seedRowFor(k store.SliceKey) store.SliceDNNQoS {
	row := store.DefaultSliceDNNQoS(k)
	if a, ok := s.operatorSeed[k]; ok {
		row.SeedAMBR, row.SeedSource = a, store.SourceOperator
		row.SessionAMBR, row.Source = a, store.SourceOperator
	}
	return row
}

func (s *Server) registerSliceQoS(mux *http.ServeMux) {
	mux.HandleFunc("GET /nudr-internal/v1/slice-dnn-qos", s.handleListSliceQoS)
	mux.HandleFunc("GET /nudr-internal/v1/slice-dnn-qos/{sst}/{sd}/{dnn}", s.handleGetSliceQoS)
	mux.HandleFunc("PUT /nudr-internal/v1/slice-dnn-qos/{sst}/{sd}/{dnn}", countSliceQoSProcedure(s.handlePutSliceQoS))
	mux.HandleFunc("DELETE /nudr-internal/v1/slice-dnn-qos/{sst}/{sd}/{dnn}", countSliceQoSProcedure(s.handleDeleteSliceQoS))
}

// statusRecorder captures the status code written by a handler.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// countSliceQoSProcedure increments fivegc_procedure_total for a PUT/DELETE
// exit path: 2xx -> OK, 4xx -> REJECT, 5xx -> FAILURE.
func countSliceQoSProcedure(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		result := "OK"
		switch {
		case rec.status >= 500:
			result = "FAILURE"
		case rec.status >= 400:
			result = "REJECT"
		}
		metrics.ProcedureTotal.WithLabelValues("UDR", sliceQoSProcedure, result).Inc()
	}
}

// sliceQoSLog returns a logger carrying the canonical SliceSessionAmbrConfig fields.
func (s *Server) sliceQoSLog(w http.ResponseWriter, r *http.Request, specRef string) *slog.Logger {
	corr := r.Header.Get("X-Correlation-Id")
	if corr == "" {
		corr = w.Header().Get("X-Correlation-Id")
	}
	return s.logger.With(
		"procedure", sliceQoSProcedure,
		"interface", sliceQoSInterface,
		"correlation_id", corr,
		"spec_ref", specRef,
	)
}

// parseSliceKeyPath validates {sst}/{sd}/{dnn}. "-" in {sd} means no SD.
func parseSliceKeyPath(sstS, sdS, dnn string) (store.SliceKey, []invalidParam) {
	var bad []invalidParam
	var sst uint8
	if n, err := strconv.ParseUint(sstS, 10, 16); err != nil || n > 255 {
		bad = append(bad, invalidParam{"sst", "must be a decimal integer 0-255"})
	} else {
		sst = uint8(n)
	}
	sd := ""
	if sdS != noSDPathToken {
		if sdS == "" || !store.ValidSD(sdS) {
			bad = append(bad, invalidParam{"sd", `must be six hex digits, or "-" for no SD`})
		} else {
			sd = sdS
		}
	}
	if !validDNN(dnn) {
		bad = append(bad, invalidParam{"dnn", "must be 1-100 printable characters without spaces"})
	}
	if len(bad) > 0 {
		return store.SliceKey{}, bad
	}
	return store.NewSliceKey(sst, sd, dnn), nil
}

func validDNN(dnn string) bool {
	if dnn == "" || len(dnn) > maxDNNLen {
		return false
	}
	for _, c := range dnn {
		if c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

func (s *Server) handleListSliceQoS(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	log := s.sliceQoSLog(w, r, specRefSessionAMBR)
	q := r.URL.Query()
	var bad []invalidParam
	var fSST *uint8
	if v := q.Get("sst"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 16); err != nil || n > 255 {
			bad = append(bad, invalidParam{"sst", "must be a decimal integer 0-255"})
		} else {
			u := uint8(n)
			fSST = &u
		}
	}
	var fSD *string
	if q.Has("sd") {
		v := q.Get("sd")
		if v == noSDPathToken {
			v = ""
		}
		if !store.ValidSD(v) {
			bad = append(bad, invalidParam{"sd", `must be six hex digits, or "-" for no SD`})
		} else {
			v = strings.ToLower(v)
			fSD = &v
		}
	}
	fDNN := strings.ToLower(q.Get("dnn"))
	if len(bad) > 0 {
		s.rejectSliceQoS(r.Context(), w, log, http.StatusBadRequest, "INVALID_QUERY_PARAM", "invalid query parameter", bad)
		return
	}
	rows, err := s.store.ListSliceDNNQoS(r.Context())
	if err != nil {
		s.failSliceQoS(w, log, "list slice-dnn-qos", err)
		return
	}
	items := make([]sliceQoSView, 0, len(rows))
	for _, row := range rows {
		if (fSST != nil && row.SST != *fSST) || (fSD != nil && row.SD != *fSD) || (fDNN != "" && row.DNN != fDNN) {
			continue
		}
		items = append(items, toSliceQoSView(row))
	}
	log.Info("slice-dnn-qos listed", "direction", "OUT", "result", "OK", "count", len(items),
		"duration_ms", time.Since(start).Milliseconds())
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleGetSliceQoS(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	log := s.sliceQoSLog(w, r, specRefSessionAMBR)
	k, bad := parseSliceKeyPath(r.PathValue("sst"), r.PathValue("sd"), r.PathValue("dnn"))
	if bad != nil {
		s.rejectSliceQoS(r.Context(), w, log, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid path parameter", bad)
		return
	}
	row, err := s.store.GetSliceDNNQoS(r.Context(), k.SST, k.SD, k.DNN)
	if err != nil {
		s.failSliceQoS(w, log, "get slice-dnn-qos", err, "sst", k.SST, "sd", k.SD, "dnn", k.DNN)
		return
	}
	if row == nil {
		s.rejectSliceQoS(r.Context(), w, log, http.StatusNotFound, "DATA_NOT_FOUND", "no slice-dnn-qos for "+k.String(), nil,
			"sst", k.SST, "sd", k.SD, "dnn", k.DNN)
		return
	}
	log.Info("slice-dnn-qos returned", "direction", "OUT", "result", "OK",
		"sst", k.SST, "sd", k.SD, "dnn", k.DNN, "source", row.Source,
		"session_ambr_ul", row.SessionAMBR.Uplink, "session_ambr_dl", row.SessionAMBR.Downlink,
		"duration_ms", time.Since(start).Milliseconds())
	writeJSON(w, http.StatusOK, toSliceQoSView(*row))
}

func (s *Server) handlePutSliceQoS(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	log := s.sliceQoSLog(w, r, specRefSessionAMBR)
	ctx := r.Context()
	k, bad := parseSliceKeyPath(r.PathValue("sst"), r.PathValue("sd"), r.PathValue("dnn"))
	if bad != nil {
		s.rejectSliceQoS(r.Context(), w, log, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid path parameter", bad)
		return
	}
	logKey := []any{"sst", k.SST, "sd", k.SD, "dnn", k.DNN}
	if len(s.knownDNNs) > 0 {
		if _, ok := s.knownDNNs[k.DNN]; !ok {
			s.rejectSliceQoS(r.Context(), w, log, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "unknown DNN "+k.DNN,
				[]invalidParam{{"dnn", "unknown DNN"}}, logKey...)
			return
		}
	}

	var body struct {
		SessionAMBR *struct {
			Uplink   *string `json:"uplink"`
			Downlink *string `json:"downlink"`
		} `json:"sessionAmbr"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxSliceQoSBody+1))
	if err != nil || len(raw) > maxSliceQoSBody || json.Unmarshal(raw, &body) != nil {
		s.rejectSliceQoS(r.Context(), w, log, http.StatusBadRequest, "INVALID_MSG_FORMAT", "request body is not a valid SliceDnnQos JSON object", nil, logKey...)
		return
	}
	if body.SessionAMBR == nil {
		s.rejectSliceQoS(r.Context(), w, log, http.StatusBadRequest, "MANDATORY_IE_MISSING", "sessionAmbr is missing",
			[]invalidParam{{"sessionAmbr", "missing"}}, logKey...)
		return
	}
	var missing, incorrect []invalidParam
	var ambr store.AMBR
	check := func(param string, v *string, dst *string) {
		if v == nil || strings.TrimSpace(*v) == "" {
			missing = append(missing, invalidParam{param, "missing or empty"})
			return
		}
		canon, _, err := qos.ValidateBitRate(*v)
		if err != nil {
			incorrect = append(incorrect, invalidParam{param, err.Error()})
			return
		}
		*dst = canon
	}
	check("sessionAmbr.uplink", body.SessionAMBR.Uplink, &ambr.Uplink)
	check("sessionAmbr.downlink", body.SessionAMBR.Downlink, &ambr.Downlink)
	if len(missing) > 0 {
		s.rejectSliceQoS(r.Context(), w, log, http.StatusBadRequest, "MANDATORY_IE_MISSING", "sessionAmbr uplink/downlink missing",
			append(missing, incorrect...), logKey...)
		return
	}
	if len(incorrect) > 0 {
		s.rejectSliceQoS(r.Context(), w, log, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid BitRate (TS 29.571 §5.5.2)",
			incorrect, logKey...)
		return
	}

	log.Info("slice-dnn-qos edit", append(logKey, "direction", "IN", "session_ambr_ul", ambr.Uplink,
		"session_ambr_dl", ambr.Downlink)...)
	created, changed, err := s.store.PutSliceDNNQoSEdited(ctx, k.SST, k.SD, k.DNN, ambr, s.seedRowFor(k))
	if err != nil {
		s.failSliceQoS(w, log, "put slice-dnn-qos", err, logKey...)
		return
	}
	row, err := s.store.GetSliceDNNQoS(ctx, k.SST, k.SD, k.DNN)
	if err != nil || row == nil {
		s.failSliceQoS(w, log, "read back slice-dnn-qos", errOrMissing(err), logKey...)
		return
	}
	rv, err := s.resync(ctx, w, r, k)
	if err != nil {
		s.failSliceQoS(w, log, "resync sm-data (edit committed)", err, logKey...)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	log.Info("slice-dnn-qos stored", append(logKey, "direction", "OUT", "result", "OK", "source", row.Source,
		"session_ambr_ul", row.SessionAMBR.Uplink, "session_ambr_dl", row.SessionAMBR.Downlink,
		"created", created, "changed", changed, "affected_subscribers", rv.AffectedSubscribers,
		"synced", rv.Synced, "failed", len(rv.Failed), "duration_ms", time.Since(start).Milliseconds())...)
	writeJSON(w, status, sliceQoSWriteResponse{Item: toSliceQoSView(*row), Changed: changed, Resync: rv})
}

func (s *Server) handleDeleteSliceQoS(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	log := s.sliceQoSLog(w, r, specRefSessionAMBR)
	ctx := r.Context()
	k, bad := parseSliceKeyPath(r.PathValue("sst"), r.PathValue("sd"), r.PathValue("dnn"))
	if bad != nil {
		s.rejectSliceQoS(r.Context(), w, log, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid path parameter", bad)
		return
	}
	logKey := []any{"sst", k.SST, "sd", k.SD, "dnn", k.DNN}
	row, changed, err := s.store.RevertSliceDNNQoS(ctx, k.SST, k.SD, k.DNN)
	if errors.Is(err, store.ErrNotFound) {
		s.rejectSliceQoS(r.Context(), w, log, http.StatusNotFound, "DATA_NOT_FOUND", "no slice-dnn-qos for "+k.String(), nil, logKey...)
		return
	}
	if err != nil {
		s.failSliceQoS(w, log, "revert slice-dnn-qos", err, logKey...)
		return
	}
	rv := resyncView{Failed: []store.ResyncFailure{}}
	if changed {
		if rv, err = s.resync(ctx, w, r, k); err != nil {
			s.failSliceQoS(w, log, "resync sm-data (revert committed)", err, logKey...)
			return
		}
	}
	log.Info("slice-dnn-qos reverted", append(logKey, "direction", "OUT", "result", "OK", "source", row.Source,
		"session_ambr_ul", row.SessionAMBR.Uplink, "session_ambr_dl", row.SessionAMBR.Downlink,
		"changed", changed, "affected_subscribers", rv.AffectedSubscribers, "synced", rv.Synced,
		"failed", len(rv.Failed), "duration_ms", time.Since(start).Milliseconds())...)
	writeJSON(w, http.StatusOK, sliceQoSWriteResponse{Item: toSliceQoSView(*row), Changed: changed, Resync: rv})
}

// resync re-derives sm-data of the subscribers on k and logs each failure.
func (s *Server) resync(ctx context.Context, w http.ResponseWriter, r *http.Request, k store.SliceKey) (resyncView, error) {
	log := s.sliceQoSLog(w, r, specRefDnnConfig)
	res, err := store.ResyncSliceDNN(ctx, s.store, k)
	if err != nil {
		return resyncView{}, err
	}
	for _, f := range res.Failed {
		log.Warn("sm-data resync failed", "direction", "OUT", "result", "FAILURE", "supi", f.SUPI,
			"sst", k.SST, "sd", k.SD, "dnn", k.DNN, "cause", f.Error)
	}
	return resyncView{AffectedSubscribers: res.Affected, Synced: res.Synced, Failed: res.Failed}, nil
}

func errOrMissing(err error) error {
	if err != nil {
		return err
	}
	return errors.New("udr: row vanished after upsert")
}

func (s *Server) rejectSliceQoS(ctx context.Context, w http.ResponseWriter, log *slog.Logger, status int, cause, detail string, params []invalidParam, kv ...any) {
	level := slog.LevelWarn
	log.Log(ctx, level, "slice-dnn-qos request rejected",
		append(kv, "direction", "OUT", "result", "REJECT", "cause", cause, "detail", detail)...)
	s.problemParams(w, status, cause, detail, params)
}

func (s *Server) failSliceQoS(w http.ResponseWriter, log *slog.Logger, op string, err error, kv ...any) {
	log.Error("slice-dnn-qos "+op+" failed",
		append(kv, "direction", "OUT", "result", "FAILURE", "cause", "SYSTEM_FAILURE", "error", err.Error())...)
	s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", op+" failed")
}

// problemParams writes a ProblemDetails with optional invalidParams
// (TS 29.571 §5.2.4.1).
func (s *Server) problemParams(w http.ResponseWriter, status int, cause, detail string, params []invalidParam) {
	body := map[string]any{"status": status, "cause": cause, "detail": detail}
	if len(params) > 0 {
		body["invalidParams"] = params
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
