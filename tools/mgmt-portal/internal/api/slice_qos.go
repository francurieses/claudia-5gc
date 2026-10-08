package api

// slice_qos.go — per (S-NSSAI, DNN) subscribed Session-AMBR management (UDR-003).
//
// NON-3GPP management API. The portal proxies the UDR internal endpoints
//
//	/nudr-internal/v1/slice-dnn-qos[/{sst}/{sd}/{dnn}]
//
// (store of record for the subscribed Session-AMBR, TS 23.501 §5.7.2.6 /
// TS 29.503 §6.1.6.2.9 sessionAmbr) and orchestrates "Apply to active sessions"
// by reusing the SMF NW-initiated QoS modification trigger
// (POST /nsmf-management/v1/sessions/{psi}/qos → TS 23.502 §4.3.3.2, Update QER 1).
// BitRate strings follow TS 29.571 §5.5.2. Design: docs/procedures/SliceSessionAmbrConfig.md.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	// sliceQoSApplyTimeout bounds each per-session SMF modification during Apply.
	sliceQoSApplyTimeout = 10 * time.Second
	// maxBitRateKbps is the upper bound for a Session-AMBR (1 Pbps), same as the
	// SMF maxBitRateKbps.
	maxBitRateKbps = 1_000_000_000_000
	// maxDNNLen is the maximum DNN length accepted in the path.
	maxDNNLen = 100
	// sliceQoSReason is the reason sent to the SMF mgmt QoS API on Apply.
	sliceQoSReason = "SliceSessionAmbrConfig apply"
	// noSDPathSegment is the path literal meaning "S-NSSAI without SD".
	noSDPathSegment = "-"
)

// bitRatePattern is the TS 29.571 §5.5.2 BitRate pattern (Table 5.5.2-1).
var bitRatePattern = regexp.MustCompile(`^\d+(\.\d+)? (bps|Kbps|Mbps|Gbps|Tbps)$`)

var (
	sdPattern  = regexp.MustCompile(`^[0-9a-fA-F]{6}$`)
	dnnPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// higherPrecedenceSources are session QoS sources that outrank the UDM
// subscription (this table); Apply skips them unless include_overridden.
var higherPrecedenceSources = map[string]bool{
	"PCF_OVERRIDE":    true,
	"UDR_POLICY_DATA": true,
	"MANUAL_OVERRIDE": true,
	"NW_MODIFICATION": true,
}

// sessionAmbr is the Ambr structured type {uplink, downlink} (BitRate strings).
type sessionAmbr struct {
	Uplink   string `json:"uplink"`
	Downlink string `json:"downlink"`
}

type putSliceQoSRequest struct {
	SessionAmbr *sessionAmbr `json:"sessionAmbr"`
}

type applySliceQoSRequest struct {
	IncludeOverridden bool `json:"include_overridden"`
}

// sliceKey is a validated, normalised (S-NSSAI, DNN) key.
type sliceKey struct {
	SST uint8
	SD  string // lower-case hex, "" = no SD
	DNN string
}

// pathSD returns the SD as used in the UDR/portal path ("-" = none).
func (k sliceKey) pathSD() string {
	if k.SD == "" {
		return noSDPathSegment
	}
	return k.SD
}

// udrPath returns the UDR item path for the key.
func (k sliceKey) udrPath() string {
	return fmt.Sprintf("/nudr-internal/v1/slice-dnn-qos/%d/%s/%s", k.SST, k.pathSD(), url.PathEscape(k.DNN))
}

// parseSliceKey validates the {sst}/{sd}/{dnn} path parameters.
func parseSliceKey(sst, sd, dnn string) (sliceKey, error) {
	var k sliceKey
	n, err := strconv.ParseUint(sst, 10, 8)
	if err != nil {
		return k, errors.New("sst must be a decimal integer 0-255")
	}
	k.SST = uint8(n)
	switch {
	case sd == noSDPathSegment:
	case sdPattern.MatchString(sd):
		k.SD = strings.ToLower(sd)
	default:
		return k, errors.New(`sd must be 6 hex digits or "-" (no SD)`)
	}
	if u, err := url.PathUnescape(dnn); err == nil {
		dnn = u
	}
	if dnn == "" || len(dnn) > maxDNNLen || !dnnPattern.MatchString(dnn) {
		return k, fmt.Errorf("dnn must be 1-%d characters of [A-Za-z0-9._-]", maxDNNLen)
	}
	k.DNN = dnn
	return k, nil
}

// bitRateToKbps validates a BitRate string (TS 29.571 §5.5.2) and converts it
// to kbps rounded up. The value must be > 0 and <= 1 Pbps.
func bitRateToKbps(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if !bitRatePattern.MatchString(s) {
		return 0, fmt.Errorf(`%q is not a valid BitRate (e.g. "20 Mbps"; units bps|Kbps|Mbps|Gbps|Tbps)`, s)
	}
	num, unit, _ := strings.Cut(s, " ")
	v, ok := new(big.Rat).SetString(num)
	if !ok {
		return 0, fmt.Errorf("%q is not a valid BitRate", s)
	}
	var mult *big.Rat
	switch unit {
	case "bps":
		mult = big.NewRat(1, 1000)
	case "Kbps":
		mult = big.NewRat(1, 1)
	case "Mbps":
		mult = big.NewRat(1000, 1)
	case "Gbps":
		mult = big.NewRat(1000000, 1)
	default: // Tbps
		mult = big.NewRat(1000000000, 1)
	}
	v.Mul(v, mult)
	// ceil(v)
	q, r := new(big.Int).QuoRem(v.Num(), v.Denom(), new(big.Int))
	if r.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	if q.Sign() <= 0 {
		return 0, fmt.Errorf("%q must be greater than 0", s)
	}
	if !q.IsUint64() || q.Uint64() > maxBitRateKbps {
		return 0, fmt.Errorf("%q exceeds the maximum of 1 Pbps", s)
	}
	return q.Uint64(), nil
}

// kbpsToMbpsCeil converts kbps to whole Mbps, rounded up, minimum 1.
func kbpsToMbpsCeil(kbps uint64) int {
	m := (kbps + 999) / 1000
	if m < 1 {
		m = 1
	}
	return int(m)
}

// validateSessionAmbr checks both directions of a PUT body.
func validateSessionAmbr(a *sessionAmbr) error {
	if a == nil {
		return errors.New("sessionAmbr is required")
	}
	if strings.TrimSpace(a.Uplink) == "" {
		return errors.New("sessionAmbr.uplink is required")
	}
	if strings.TrimSpace(a.Downlink) == "" {
		return errors.New("sessionAmbr.downlink is required")
	}
	if _, err := bitRateToKbps(a.Uplink); err != nil {
		return fmt.Errorf("sessionAmbr.uplink: %w", err)
	}
	if _, err := bitRateToKbps(a.Downlink); err != nil {
		return fmt.Errorf("sessionAmbr.downlink: %w", err)
	}
	return nil
}

func (d Deps) sliceQoSLog(r *http.Request, procStep, specRef string) *slog.Logger {
	return slog.With(
		"nf", "PORTAL",
		"procedure", "SliceSessionAmbrConfig",
		"correlation_id", r.Header.Get("X-Correlation-Id"),
		"interface", "Nudr-internal",
		"step", procStep,
		"spec_ref", specRef,
	)
}

// upstreamDo sends a request to the UDR/SMF and returns status + body. A transport
// error (or an unwired client/URL) yields err; callers map it to 502.
func (d Deps) upstreamDo(ctx context.Context, r *http.Request, method, target string, body []byte) (int, []byte, error) {
	if d.MTLSClient == nil {
		return 0, nil, errors.New("mTLS client not configured")
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cid := r.Header.Get("X-Correlation-Id"); cid != "" {
		req.Header.Set("X-Correlation-Id", cid)
	}
	resp, err := d.MTLSClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, b, nil
}

func (d Deps) udrURL(path string) string {
	return strings.TrimRight(d.UDRBaseURL, "/") + path
}

func (d Deps) smfURL(path string) string {
	return strings.TrimRight(d.SMFBaseURL, "/") + path
}

func relay(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeUDRUnreachable(w http.ResponseWriter, err error) {
	writeError(w, http.StatusBadGateway, fmt.Sprintf("UDR unreachable: %v", err))
}

// GET /api/v1/slices/qos → UDR GET /nudr-internal/v1/slice-dnn-qos
func (d Deps) handleListSliceQoS(w http.ResponseWriter, r *http.Request) {
	status, body, err := d.upstreamDo(r.Context(), r, http.MethodGet, d.udrURL("/nudr-internal/v1/slice-dnn-qos"), nil)
	if err != nil {
		writeUDRUnreachable(w, err)
		return
	}
	relay(w, status, body)
}

// PUT /api/v1/slices/qos/{sst}/{sd}/{dnn} → UDR PUT …/{sst}/{sd}/{dnn}
// Body {"sessionAmbr":{"uplink":"20 Mbps","downlink":"30 Mbps"}}; validated first (400).
func (d Deps) handlePutSliceQoS(w http.ResponseWriter, r *http.Request) {
	key, err := parseSliceKey(chi.URLParam(r, "sst"), chi.URLParam(r, "sd"), chi.URLParam(r, "dnn"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req putSliceQoSRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if err := validateSessionAmbr(req.SessionAmbr); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload, _ := json.Marshal(putSliceQoSRequest{SessionAmbr: &sessionAmbr{
		Uplink:   strings.TrimSpace(req.SessionAmbr.Uplink),
		Downlink: strings.TrimSpace(req.SessionAmbr.Downlink),
	}})
	d.sliceQoSLog(r, "B5", "TS 23.501 §5.7.2.6").InfoContext(r.Context(), "slice session-ambr edit",
		"direction", "OUT", "sst", key.SST, "sd", key.SD, "dnn", key.DNN,
		"session_ambr_ul", req.SessionAmbr.Uplink, "session_ambr_dl", req.SessionAmbr.Downlink)
	status, body, err := d.upstreamDo(r.Context(), r, http.MethodPut, d.udrURL(key.udrPath()), payload)
	if err != nil {
		writeUDRUnreachable(w, err)
		return
	}
	relay(w, status, body)
}

// DELETE /api/v1/slices/qos/{sst}/{sd}/{dnn} → UDR DELETE (revert to seed value).
func (d Deps) handleDeleteSliceQoS(w http.ResponseWriter, r *http.Request) {
	key, err := parseSliceKey(chi.URLParam(r, "sst"), chi.URLParam(r, "sd"), chi.URLParam(r, "dnn"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status, body, err := d.upstreamDo(r.Context(), r, http.MethodDelete, d.udrURL(key.udrPath()), nil)
	if err != nil {
		writeUDRUnreachable(w, err)
		return
	}
	relay(w, status, body)
}

// smfSession is the subset of the SMF sessionView used by Apply.
type smfSession struct {
	SUPI         string `json:"supi"`
	PDUSessionID int    `json:"pduSessionId"`
	DNN          string `json:"dnn"`
	SNSSAI       struct {
		SST int    `json:"sst"`
		SD  string `json:"sd"`
	} `json:"sNssai"`
	Current5QI int    `json:"current5qi"`
	QoSSource  string `json:"qosSource"`
}

type applyRef struct {
	SUPI         string `json:"supi"`
	PDUSessionID int    `json:"pduSessionId"`
}

type applySkipped struct {
	applyRef
	QoSSource string `json:"qosSource,omitempty"`
	Reason    string `json:"reason"`
}

type applyFailed struct {
	applyRef
	Status int    `json:"status"`
	Cause  string `json:"cause,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type applyMbps struct {
	UL int `json:"ul"`
	DL int `json:"dl"`
}

type applyResponse struct {
	SessionAmbr sessionAmbr    `json:"sessionAmbr"`
	AppliedMbps applyMbps      `json:"applied_mbps"`
	Matched     int            `json:"matched"`
	Applied     []applyRef     `json:"applied"`
	Skipped     []applySkipped `json:"skipped"`
	Failed      []applyFailed  `json:"failed"`
}

// POST /api/v1/slices/qos/{sst}/{sd}/{dnn}/apply
//
// Pushes the current effective Session-AMBR of the key to the matching active
// PDU sessions through the SMF NW-initiated QoS modification trigger
// (TS 23.502 §4.3.3.2). Non-fatal per-session failures are collected.
func (d Deps) handleApplySliceQoS(w http.ResponseWriter, r *http.Request) {
	key, err := parseSliceKey(chi.URLParam(r, "sst"), chi.URLParam(r, "sd"), chi.URLParam(r, "dnn"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req applySliceQoSRequest
	if r.Body != nil {
		if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
	}
	ctx := r.Context()
	log := d.sliceQoSLog(r, "D1", "TS 23.502 §4.3.3.2")

	// D2: effective value from the UDR.
	status, body, err := d.upstreamDo(ctx, r, http.MethodGet, d.udrURL(key.udrPath()), nil)
	if err != nil {
		writeUDRUnreachable(w, err)
		return
	}
	if status != http.StatusOK {
		relay(w, status, body)
		return
	}
	var item struct {
		SessionAmbr sessionAmbr `json:"sessionAmbr"`
	}
	if err := json.Unmarshal(body, &item); err != nil {
		writeError(w, http.StatusBadGateway, "UDR returned an unparsable item: "+err.Error())
		return
	}
	ulKbps, err := bitRateToKbps(item.SessionAmbr.Uplink)
	if err != nil {
		writeError(w, http.StatusBadGateway, "UDR item sessionAmbr.uplink: "+err.Error())
		return
	}
	dlKbps, err := bitRateToKbps(item.SessionAmbr.Downlink)
	if err != nil {
		writeError(w, http.StatusBadGateway, "UDR item sessionAmbr.downlink: "+err.Error())
		return
	}
	ulMbps, dlMbps := kbpsToMbpsCeil(ulKbps), kbpsToMbpsCeil(dlKbps)

	// D3: live sessions from the SMF.
	status, body, err = d.upstreamDo(ctx, r, http.MethodGet, d.smfURL("/nsmf-management/v1/sessions"), nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SMF unreachable: %v", err))
		return
	}
	if status != http.StatusOK {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SMF session list failed: HTTP %d", status))
		return
	}
	var list struct {
		Sessions []smfSession `json:"sessions"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		writeError(w, http.StatusBadGateway, "SMF returned an unparsable session list: "+err.Error())
		return
	}

	resp := applyResponse{
		SessionAmbr: item.SessionAmbr,
		AppliedMbps: applyMbps{UL: ulMbps, DL: dlMbps},
		Applied:     []applyRef{},
		Skipped:     []applySkipped{},
		Failed:      []applyFailed{},
	}

	// D4/D5: filter, then modify sequentially.
	for _, s := range list.Sessions {
		if s.SNSSAI.SST != int(key.SST) || !strings.EqualFold(s.SNSSAI.SD, key.SD) || !strings.EqualFold(s.DNN, key.DNN) {
			continue
		}
		resp.Matched++
		ref := applyRef{SUPI: s.SUPI, PDUSessionID: s.PDUSessionID}
		if higherPrecedenceSources[s.QoSSource] && !req.IncludeOverridden {
			resp.Skipped = append(resp.Skipped, applySkipped{applyRef: ref, QoSSource: s.QoSSource, Reason: "higher-precedence source"})
			continue
		}
		st, cause, detail, perr := d.applyOneSession(ctx, r, s, ulMbps, dlMbps)
		switch {
		case perr != nil:
			resp.Failed = append(resp.Failed, applyFailed{applyRef: ref, Status: http.StatusBadGateway, Cause: "PEER_NOT_RESPONDING", Detail: perr.Error()})
		case st == http.StatusOK:
			resp.Applied = append(resp.Applied, ref)
		case st == http.StatusNotFound:
			resp.Skipped = append(resp.Skipped, applySkipped{applyRef: ref, QoSSource: s.QoSSource, Reason: "gone"})
		default:
			resp.Failed = append(resp.Failed, applyFailed{applyRef: ref, Status: st, Cause: cause, Detail: detail})
		}
	}
	log.InfoContext(ctx, "slice session-ambr applied to active sessions", "direction", "OUT",
		"sst", key.SST, "sd", key.SD, "dnn", key.DNN, "matched", resp.Matched,
		"applied", len(resp.Applied), "skipped", len(resp.Skipped), "failed", len(resp.Failed))
	writeJSON(w, http.StatusOK, resp)
}

// applyOneSession POSTs the QoS modification for a single session with a
// per-session timeout. It returns the SMF status and ProblemDetails fields.
func (d Deps) applyOneSession(parent context.Context, r *http.Request, s smfSession, ulMbps, dlMbps int) (int, string, string, error) {
	ctx, cancel := context.WithTimeout(parent, sliceQoSApplyTimeout)
	defer cancel()
	payload, _ := json.Marshal(map[string]any{
		"5qi":          s.Current5QI,
		"reason":       sliceQoSReason,
		"supi":         s.SUPI,
		"ambr_ul_mbps": ulMbps,
		"ambr_dl_mbps": dlMbps,
	})
	u := d.smfURL("/nsmf-management/v1/sessions/" + strconv.Itoa(s.PDUSessionID) + "/qos")
	st, body, err := d.upstreamDo(ctx, r, http.MethodPost, u, payload)
	if err != nil {
		return 0, "", "", err
	}
	if st == http.StatusOK {
		return st, "", "", nil
	}
	var prob struct {
		Cause  string `json:"cause"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(body, &prob)
	if prob.Detail == "" && prob.Cause == "" {
		prob.Detail = strings.TrimSpace(string(body))
	}
	return st, prob.Cause, prob.Detail, nil
}
