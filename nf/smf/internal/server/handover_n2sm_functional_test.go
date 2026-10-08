//go:build functional

// godog step definitions for handover_n2sm_responses.feature (AMF-012 companion):
// Nsmf_PDUSession_UpdateSMContext responses for PATH_SWITCH_REQ, HANDOVER_REQ_ACK and
// PATH_SWITCH_SETUP_FAIL. The real handleUpdateSMContext runs in-process behind an
// httptest.ResponseRecorder; the fake UPF is a UDP listener at cfg.Peers.UPF whose
// received datagrams are the PFCP sends (same approach as handover_n2sm_test.go).
// Run with: go test -tags=functional ./nf/smf/...
// Ref: TS 23.502 §4.9.1.2.2 steps 2-6, §4.9.1.3.2 steps 9-12; TS 29.502 §5.2.2.3.3, §5.2.2.3.4.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
)

// ---- recording slog handler ------------------------------------------------------------

type hoRec struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

type hoLogStore struct {
	mu   sync.Mutex
	recs []hoRec
}

// hoLogHandler records every record with its attributes (handler-level attrs from
// logger.With included).
type hoLogHandler struct {
	store *hoLogStore
	pre   []slog.Attr
}

func (h hoLogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h hoLogHandler) Handle(_ context.Context, r slog.Record) error {
	rec := hoRec{level: r.Level, msg: r.Message, attrs: map[string]string{}}
	for _, a := range h.pre {
		rec.attrs[a.Key] = a.Value.String()
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	h.store.mu.Lock()
	h.store.recs = append(h.store.recs, rec)
	h.store.mu.Unlock()
	return nil
}
func (h hoLogHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return hoLogHandler{store: h.store, pre: append(append([]slog.Attr(nil), h.pre...), as...)}
}
func (h hoLogHandler) WithGroup(string) slog.Handler { return h }

func (s *hoLogStore) levelOf(substr string) (slog.Level, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		if strings.Contains(r.msg, substr) {
			return r.level, true
		}
	}
	return 0, false
}

// find returns the first record matching pred.
func (s *hoLogStore) find(pred func(r hoRec) bool) (hoRec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		if pred(r) {
			return r, true
		}
	}
	return hoRec{}, false
}

// ---- world ----------------------------------------------------------------------------------

const (
	hoSteps = "sm-ctx-1"
	// Session parameters the PREPARING transfer must reflect (UL tunnel unchanged, QFI 1, 5QI, AMBR).
	hoStepsUPFN3  = "10.0.0.250"
	hoStepsULTEID = uint32(0x1001)
	hoStepsFiveQI = uint8(9)
)

type hoStepsWorld struct {
	srv  *Server
	sess *Session
	upf  *hoStepsUPF
	amf  *hoStepsAMF
	logs *hoLogStore

	stateBefore string
	// SMF-005: timing of the last UpdateSMContext call and the Cause relayed by the last
	// HANDOVER_RES_ALLOC_FAIL request (for the "same Cause" assertion).
	postStart, postEnd time.Time
	relayedCause       ngapType.Cause
	rec                *httptest.ResponseRecorder
	resp               map[string]interface{}
	sentIP             [4]byte
	sentTEID           uint32
}

func (w *hoStepsWorld) close() {
	if w.srv != nil {
		w.srv.WaitHandoverTasks() // no detached PFCP / AMF call may outlive its scenario
	}
	if w.upf != nil {
		w.upf.close()
		w.upf = nil
	}
	if w.amf != nil {
		w.amf.close()
		w.amf = nil
	}
}

func hoStepsGTP(ip [4]byte, teid uint32) ngapType.UPTransportLayerInformation {
	return ngapType.UPTransportLayerInformation{
		Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
		GTPTunnel: &ngapType.GTPTunnel{
			TransportLayerAddress: ngapType.TransportLayerAddress{Value: aper.BitString{Bytes: ip[:], BitLength: 32}},
			GTPTEID:               ngapType.GTPTEID{Value: aper.OctetString{byte(teid >> 24), byte(teid >> 16), byte(teid >> 8), byte(teid)}},
		},
	}
}

func hoStepsMarshal(v interface{}) ([]byte, error) {
	b, err := aper.MarshalWithParams(v, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("marshal %T: %w", v, err)
	}
	return b, nil
}

func (w *hoStepsWorld) anActiveSession(ref string, psi int) error {
	w.close()
	upf, err := newHOStepsUPF()
	if err != nil {
		return err
	}
	w.upf = upf
	w.amf = newHOStepsAMF(http.StatusNoContent)
	w.logs = &hoLogStore{}
	cfg := &config.Config{UEIPPool: "10.60.0.0/24", UPFN3Addr: hoStepsUPFN3}
	cfg.Peers.UPF = upf.addr()
	cfg.Peers.AMFMgmt = w.amf.host()
	srv, err := New(cfg, slog.New(hoLogHandler{store: w.logs}), nil)
	if err != nil {
		return fmt.Errorf("new SMF server: %w", err)
	}
	w.srv = srv
	// Default T1 (3 s) and N1: only the first transmission fits the 1.5 s handover N4 budget,
	// so a silent UPF sees exactly one request (pinned here, independent of config defaults).
	w.srv.pfcpTimers.t1, w.srv.pfcpTimers.n1 = 3*time.Second, 1
	w.sess = &Session{SUPI: "imsi-001010000000001", PDUSessionID: uint8(psi), DNN: "internet", SEID: 42, State: "ACTIVE",
		ULTEID: hoStepsULTEID, FiveQI: hoStepsFiveQI, AMBRULMbps: 100, AMBRDLMbps: 200}
	w.srv.sessionMu.Lock()
	w.srv.sessions[ref] = w.sess
	w.srv.sessionMu.Unlock()
	w.stateBefore = w.sess.State
	return nil
}

func (w *hoStepsWorld) pfcpFakeRecording() error {
	if w.upf == nil {
		return fmt.Errorf("fake UPF not started")
	}
	return nil
}

// post sends the UpdateSMContext body to the real handler.
func (w *hoStepsWorld) post(ref string, body map[string]interface{}) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/"+ref+"/modify", strings.NewReader(string(b)))
	r.SetPathValue("smContextRef", ref)
	w.rec = httptest.NewRecorder()
	w.postStart = time.Now()
	w.srv.handleUpdateSMContext(w.rec, r)
	w.postEnd = time.Now()
	w.resp = nil
	var m map[string]interface{}
	if json.Unmarshal(w.rec.Body.Bytes(), &m) == nil {
		w.resp = m
	}
	return nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// ---- Whens ---------------------------------------------------------------------------------

func (w *hoStepsWorld) pathSwitchReq(ref string) error {
	w.sentIP, w.sentTEID = [4]byte{10, 0, 0, 9}, 0x1234
	tr, err := hoStepsMarshal(ngapType.PathSwitchRequestTransfer{
		DLNGUUPTNLInformation: hoStepsGTP(w.sentIP, w.sentTEID),
		QosFlowAcceptedList: ngapType.QosFlowAcceptedList{List: []ngapType.QosFlowAcceptedItem{
			{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}}}},
	})
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{
		"toBeSwitched": true, "n2SmInfoType": "PATH_SWITCH_REQ", "n2SmInfo": b64(tr)})
}

func (w *hoStepsWorld) handoverReqAckValid(ref string) error {
	w.sentIP, w.sentTEID = [4]byte{10, 0, 0, 7}, 0xABCD
	tr, err := hoStepsMarshal(ngapType.HandoverRequestAcknowledgeTransfer{
		DLNGUUPTNLInformation: hoStepsGTP(w.sentIP, w.sentTEID),
		QosFlowSetupResponseList: ngapType.QosFlowListWithDataForwarding{List: []ngapType.QosFlowItemWithDataForwarding{
			{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}}}},
	})
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{
		"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_REQ_ACK", "n2SmInfo": b64(tr)})
}

func (w *hoStepsWorld) handoverReqAckBytes(ref, hexStr string) error {
	raw, err := decodeHex(hexStr)
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{
		"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_REQ_ACK", "n2SmInfo": b64(raw)})
}

func (w *hoStepsWorld) setupFail(ref string) error {
	tr, err := hoStepsMarshal(ngapType.PathSwitchRequestSetupFailedTransfer{Cause: ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable},
	}})
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{
		"failedToBeSwitched": true, "n2SmInfoType": "PATH_SWITCH_SETUP_FAIL", "n2SmInfo": b64(tr)})
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length %q", s)
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		var v byte
		if _, err := fmt.Sscanf(s[2*i:2*i+2], "%02x", &v); err != nil {
			return nil, fmt.Errorf("bad hex %q: %w", s, err)
		}
		out[i] = v
	}
	return out, nil
}

// ---- Thens -----------------------------------------------------------------------------------

func (w *hoStepsWorld) respondsStatus(code int) error {
	if w.rec == nil {
		return fmt.Errorf("no response recorded")
	}
	if w.rec.Code != code {
		return fmt.Errorf("SMF responded %d (%s), want %d", w.rec.Code, w.rec.Body.String(), code)
	}
	return nil
}

func (w *hoStepsWorld) respondsJSON(code int) error {
	if err := w.respondsStatus(code); err != nil {
		return err
	}
	if ct := w.rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return fmt.Errorf("content-type = %q, want application/json", ct)
	}
	if w.resp == nil {
		return fmt.Errorf("body %q is not a JSON object", w.rec.Body.String())
	}
	return nil
}

func (w *hoStepsWorld) respondsProblem(code int, cause string) error {
	if err := w.respondsStatus(code); err != nil {
		return err
	}
	if w.resp == nil {
		return fmt.Errorf("body %q is not a JSON object", w.rec.Body.String())
	}
	// SmContextUpdateError (TS 29.502 §6.1.6.2) nests the ProblemDetails under
	// "error"; other branches use a flat ProblemDetails.
	got := w.resp["cause"]
	if e, ok := w.resp["error"].(map[string]any); ok {
		got = e["cause"]
	}
	if got != cause {
		return fmt.Errorf("ProblemDetails cause = %v, want %q (body %s)", got, cause, w.rec.Body.String())
	}
	return nil
}

func (w *hoStepsWorld) respField(name, want string) error {
	if got, _ := w.resp[name].(string); got != want {
		return fmt.Errorf("response %s = %q, want %q", name, got, want)
	}
	return nil
}

func (w *hoStepsWorld) respTransfer() ([]byte, error) {
	s, _ := w.resp["n2SmInfo"].(string)
	if s == "" {
		return nil, fmt.Errorf("response has no n2SmInfo (body %s)", w.rec.Body.String())
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("n2SmInfo is not base64: %w", err)
	}
	return b, nil
}

func (w *hoStepsWorld) respAckTransferDecodes() error {
	b, err := w.respTransfer()
	if err != nil {
		return err
	}
	var ack ngapType.PathSwitchRequestAcknowledgeTransfer
	if err := aper.UnmarshalWithParams(b, &ack, "valueExt"); err != nil {
		return fmt.Errorf("PathSwitchRequestAcknowledgeTransfer does not decode: %w", err)
	}
	return nil
}

func (w *hoStepsWorld) respCmdTransferDecodes() error {
	b, err := w.respTransfer()
	if err != nil {
		return err
	}
	var cmd ngapType.HandoverCommandTransfer
	if err := aper.UnmarshalWithParams(b, &cmd, "valueExt"); err != nil {
		return fmt.Errorf("HandoverCommandTransfer does not decode: %w", err)
	}
	return nil
}

func (w *hoStepsWorld) oneModification() error {
	if err := w.exactlyOneWithin(2 * time.Second); err != nil {
		return err
	}
	req, err := w.upf.modification(0)
	if err != nil {
		return err
	}
	ohc, err := dlOuterHeader(req)
	if err != nil {
		return err
	}
	if ohc.TEID != w.sentTEID || !ohc.IPv4Address.Equal(net.IP(w.sentIP[:])) {
		return fmt.Errorf("Outer Header Creation = %s/%#x, want %v/%#x", ohc.IPv4Address, ohc.TEID, net.IP(w.sentIP[:]), w.sentTEID)
	}
	return nil
}

// zeroPFCP asserts the SMF sent no PFCP message. Detached release / deactivation goroutines
// are drained first (WaitHandoverTasks), so a late send cannot slip past the assertion.
func (w *hoStepsWorld) zeroPFCP() error {
	if err := w.drain(); err != nil {
		return err
	}
	if n := w.upf.count(); n != 0 {
		return fmt.Errorf("PFCP sends = %d, want 0", n)
	}
	return nil
}

func (w *hoStepsWorld) tunnelStored() error {
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	if !w.sess.HOTargetGNBIP.Equal(net.IP(w.sentIP[:])) || w.sess.HOTargetDLTEID != w.sentTEID {
		return fmt.Errorf("stored tunnel = %v/%#x, want %v/%#x", w.sess.HOTargetGNBIP, w.sess.HOTargetDLTEID, net.IP(w.sentIP[:]), w.sentTEID)
	}
	return nil
}

func (w *hoStepsWorld) noTunnelStored() error {
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	if w.sess.HOTargetGNBIP != nil || w.sess.HOTargetDLTEID != 0 {
		return fmt.Errorf("target tunnel stored on failure: %v/%#x", w.sess.HOTargetGNBIP, w.sess.HOTargetDLTEID)
	}
	return nil
}

func (w *hoStepsWorld) stateUnchanged() error {
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	if w.sess.State != w.stateBefore {
		return fmt.Errorf("session state %q, want unchanged %q", w.sess.State, w.stateBefore)
	}
	return nil
}

func (w *hoStepsWorld) causeLoggedAtInfo() error {
	lvl, ok := w.logs.levelOf("failed-to-setup PSI relayed")
	if !ok {
		return fmt.Errorf("relayed Cause log record not found")
	}
	if lvl != slog.LevelInfo {
		return fmt.Errorf("relayed Cause logged at %v, want INFO", lvl)
	}
	return nil
}

// ---- AMF-012 follow-up: PREPARING / data forwarding / RES_ALLOC_FAIL / COMPLETED ---------------

const hoStepsQFI = 1

func (w *hoStepsWorld) requiredTransfer(direct bool) ([]byte, error) {
	tr := ngapType.HandoverRequiredTransfer{}
	if direct {
		tr.DirectForwardingPathAvailability = &ngapType.DirectForwardingPathAvailability{
			Value: ngapType.DirectForwardingPathAvailabilityPresentDirectPathAvailable}
	}
	return hoStepsMarshal(tr)
}

func hoStepsTargetID() map[string]interface{} {
	return map[string]interface{}{
		"ranNodeId": map[string]interface{}{
			"plmnId": map[string]interface{}{"mcc": "001", "mnc": "01"},
			"gNbId":  map[string]interface{}{"bitLength": 24, "gNBValue": "123456"},
		},
		"tai": map[string]interface{}{"plmnId": map[string]interface{}{"mcc": "001", "mnc": "01"}, "tac": "000001"},
	}
}

func (w *hoStepsWorld) postPreparing(ref string, direct bool, withTarget bool) error {
	tr, err := w.requiredTransfer(direct)
	if err != nil {
		return err
	}
	body := map[string]interface{}{"hoState": "PREPARING", "n2SmInfoType": "HANDOVER_REQUIRED", "n2SmInfo": b64(tr)}
	if withTarget {
		body["targetId"] = hoStepsTargetID()
	}
	return w.post(ref, body)
}

func (w *hoStepsWorld) preparingDirectWithTarget(ref string) error {
	return w.postPreparing(ref, true, true)
}
func (w *hoStepsWorld) preparingValid(ref string) error { return w.postPreparing(ref, false, true) }

func (w *hoStepsWorld) preparingVariant(ref, request string) error {
	if request == "no n2SmInfo" {
		return w.post(ref, map[string]interface{}{"hoState": "PREPARING", "targetId": hoStepsTargetID()})
	}
	return w.postPreparing(ref, false, true)
}

func (w *hoStepsWorld) preparingBytes(ref, hexStr string) error {
	raw, err := decodeHex(hexStr)
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{"hoState": "PREPARING", "n2SmInfoType": "HANDOVER_REQUIRED", "n2SmInfo": b64(raw)})
}

func (w *hoStepsWorld) wasPrepared(ref, direct string) error {
	if err := w.postPreparing(ref, direct == "and DirectForwardingPathAvailability", true); err != nil {
		return err
	}
	return w.respondsStatus(200)
}

// reqAckWithForwarding posts a valid HandoverRequestAcknowledgeTransfer carrying a DL
// forwarding tunnel and QFI 1 with or without DataForwardingAccepted.
func (w *hoStepsWorld) reqAckWithForwarding(ref, fwdIP string, fwdTEID int64, accepted string) error {
	w.sentIP, w.sentTEID = [4]byte{10, 0, 0, 7}, 0xABCD
	ip := net.ParseIP(fwdIP).To4()
	if ip == nil {
		return fmt.Errorf("bad forwarding IP %q", fwdIP)
	}
	var fip [4]byte
	copy(fip[:], ip)
	fwd := hoStepsGTP(fip, uint32(fwdTEID))
	item := ngapType.QosFlowItemWithDataForwarding{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: hoStepsQFI}}
	if accepted == "with" {
		item.DataForwardingAccepted = &ngapType.DataForwardingAccepted{Value: ngapType.DataForwardingAcceptedPresentDataForwardingAccepted}
	}
	tr, err := hoStepsMarshal(ngapType.HandoverRequestAcknowledgeTransfer{
		DLNGUUPTNLInformation:        hoStepsGTP(w.sentIP, w.sentTEID),
		DLForwardingUPTNLInformation: &fwd,
		QosFlowSetupResponseList:     ngapType.QosFlowListWithDataForwarding{List: []ngapType.QosFlowItemWithDataForwarding{item}},
	})
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{
		"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_REQ_ACK", "n2SmInfo": b64(tr)})
}

func (w *hoStepsWorld) resAllocFailValid(ref string) error {
	w.relayedCause = ngapCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnspecified)
	tr, err := hoStepsMarshal(ngapType.HandoverResourceAllocationUnsuccessfulTransfer{Cause: ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentUnspecified},
	}})
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{
		"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_RES_ALLOC_FAIL", "n2SmInfo": b64(tr)})
}

func (w *hoStepsWorld) resAllocFailBytes(ref, hexStr string) error {
	raw, err := decodeHex(hexStr)
	if err != nil {
		return err
	}
	return w.post(ref, map[string]interface{}{
		"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_RES_ALLOC_FAIL", "n2SmInfo": b64(raw)})
}

func (w *hoStepsWorld) completedNoN2(ref string) error {
	return w.post(ref, map[string]interface{}{"hoState": "COMPLETED"})
}

// preparedWithTunnel drives a valid HANDOVER_REQ_ACK so the session holds hoState PREPARED and
// a target DL tunnel, then clears the recorded response.
func (w *hoStepsWorld) preparedWithTunnel(ref string) error {
	if err := w.handoverReqAckValid(ref); err != nil {
		return err
	}
	if err := w.respondsStatus(200); err != nil {
		return fmt.Errorf("precondition HANDOVER_REQ_ACK: %w", err)
	}
	w.rec, w.resp = nil, nil
	return nil
}

// ---- Thens (follow-up) --------------------------------------------------------------------------

func (w *hoStepsWorld) respondsUpdateError(code int, cause string) error {
	if err := w.respondsStatus(code); err != nil {
		return err
	}
	if ct := w.rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return fmt.Errorf("content-type = %q, want application/json (not problem+json)", ct)
	}
	e, ok := w.resp["error"].(map[string]any)
	if !ok {
		return fmt.Errorf("body %s is not a SmContextUpdateError (no \"error\" object)", w.rec.Body.String())
	}
	if st, _ := e["status"].(float64); int(st) != code {
		return fmt.Errorf("error.status = %v, want %d", e["status"], code)
	}
	if cause != "" && e["cause"] != cause {
		return fmt.Errorf("error.cause = %v, want %q", e["cause"], cause)
	}
	return nil
}

func (w *hoStepsWorld) noN2SmInfo() error {
	if w.resp == nil {
		return fmt.Errorf("body %q is not a JSON object", w.rec.Body.String())
	}
	if _, ok := w.resp["n2SmInfo"]; ok {
		return fmt.Errorf("response carries n2SmInfo, want none (body %s)", w.rec.Body.String())
	}
	if _, ok := w.resp["n2SmInfoType"]; ok {
		return fmt.Errorf("response carries n2SmInfoType, want none (body %s)", w.rec.Body.String())
	}
	return nil
}

// hoStepsRadioNetwork maps the TS 38.413 §9.3.1.2 radioNetwork cause names used by the features.
var hoStepsRadioNetwork = map[string]aper.Enumerated{
	"unspecified":                                          ngapType.CauseRadioNetworkPresentUnspecified,
	"radio-resources-not-available":                        ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable,
	"unknown-PDU-session-ID":                               ngapType.CauseRadioNetworkPresentUnknownPDUSessionID,
	"up-integrity-protection-not-possible":                 ngapType.CauseRadioNetworkPresentUpIntegrityProtectionNotPossible,
	"up-confidentiality-protection-not-possible":           ngapType.CauseRadioNetworkPresentUpConfidentialityProtectionNotPossible,
	"ho-failure-in-target-5GC-ngran-node-or-target-system": ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem,
}

func hoStepsCauseIs(c ngapType.Cause, group, name string) error {
	switch group {
	case "protocol":
		if name != "semantic-error" {
			return fmt.Errorf("feature uses unmapped protocol cause %q", name)
		}
		if c.Present != ngapType.CausePresentProtocol || c.Protocol == nil || c.Protocol.Value != ngapType.CauseProtocolPresentSemanticError {
			return fmt.Errorf("cause = %+v, want protocol semantic-error", c)
		}
	case "radioNetwork":
		want, ok := hoStepsRadioNetwork[name]
		if !ok {
			return fmt.Errorf("feature uses unmapped radioNetwork cause %q", name)
		}
		if c.Present != ngapType.CausePresentRadioNetwork || c.RadioNetwork == nil || c.RadioNetwork.Value != want {
			return fmt.Errorf("cause = %+v, want radioNetwork %s (%d)", c, name, want)
		}
	default:
		return fmt.Errorf("unknown cause group %q", group)
	}
	return nil
}

func (w *hoStepsWorld) prepFailTransfer() (ngapType.HandoverPreparationUnsuccessfulTransfer, error) {
	var tr ngapType.HandoverPreparationUnsuccessfulTransfer
	b, err := w.respTransfer()
	if err != nil {
		return tr, err
	}
	if err := aper.UnmarshalWithParams(b, &tr, "valueExt"); err != nil {
		return tr, fmt.Errorf("HandoverPreparationUnsuccessfulTransfer does not decode: %w", err)
	}
	return tr, nil
}

func (w *hoStepsWorld) prepFailDecodes() error {
	_, err := w.prepFailTransfer()
	return err
}

func (w *hoStepsWorld) prepFailCauseProtocol(group, name string) error {
	tr, err := w.prepFailTransfer()
	if err != nil {
		return err
	}
	return hoStepsCauseIs(tr.Cause, group, name)
}

func (w *hoStepsWorld) prepFailCauseNumeric(group, name string, num int) error {
	if want, ok := hoStepsRadioNetwork[name]; group == "radioNetwork" && ok && int(want) != num {
		return fmt.Errorf("feature maps %q to %d, TS 38.413 has %d", name, num, want)
	}
	return w.prepFailCauseProtocol(group, name)
}

// prepFailCauseText parses the outline cell `radioNetwork "unknown-PDU-session-ID" (26)` / `protocol "semantic-error"`.
func (w *hoStepsWorld) prepFailCauseText(text string) error {
	parts := strings.Fields(text)
	if len(parts) < 2 {
		return fmt.Errorf("unrecognised cause %q", text)
	}
	group, name := parts[0], strings.Trim(parts[1], `"`)
	if len(parts) == 3 {
		var num int
		if _, err := fmt.Sscanf(strings.Trim(parts[2], "()"), "%d", &num); err != nil {
			return fmt.Errorf("bad cause number in %q: %w", text, err)
		}
		return w.prepFailCauseNumeric(group, name, num)
	}
	return w.prepFailCauseProtocol(group, name)
}

func (w *hoStepsWorld) setupTransfer() (ngapType.PDUSessionResourceSetupRequestTransfer, error) {
	var tr ngapType.PDUSessionResourceSetupRequestTransfer
	b, err := w.respTransfer()
	if err != nil {
		return tr, err
	}
	if err := aper.UnmarshalWithParams(b, &tr, "valueExt"); err != nil {
		return tr, fmt.Errorf("PDUSessionResourceSetupRequestTransfer does not decode: %w", err)
	}
	return tr, nil
}

func (w *hoStepsWorld) setupTransferDecodes() error {
	_, err := w.setupTransfer()
	return err
}

func (w *hoStepsWorld) setupULTunnel() error {
	tr, err := w.setupTransfer()
	if err != nil {
		return err
	}
	for _, ie := range tr.ProtocolIEs.List {
		if ie.Value.ULNGUUPTNLInformation == nil {
			continue
		}
		g := ie.Value.ULNGUUPTNLInformation.GTPTunnel
		if g == nil {
			return fmt.Errorf("UL NG-U UP TNL Information is not a GTP tunnel")
		}
		wantIP := net.ParseIP(hoStepsUPFN3).To4()
		if !net.IP(g.TransportLayerAddress.Value.Bytes).Equal(wantIP) {
			return fmt.Errorf("UL transport layer address = %v, want UPF N3 %v", net.IP(g.TransportLayerAddress.Value.Bytes), wantIP)
		}
		ul := hoStepsULTEID
		want := []byte{byte(ul >> 24), byte(ul >> 16), byte(ul >> 8), byte(ul)}
		if got := []byte(g.GTPTEID.Value); string(got) != string(want) {
			return fmt.Errorf("UL TEID = %x, want %x", got, want)
		}
		return nil
	}
	return fmt.Errorf("transfer has no UL NG-U UP TNL Information IE")
}

func (w *hoStepsWorld) setupHasNoDFNP() error {
	tr, err := w.setupTransfer()
	if err != nil {
		return err
	}
	for _, ie := range tr.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDDataForwardingNotPossible {
			return fmt.Errorf("transfer contains IE DataForwardingNotPossible (id 127)")
		}
	}
	return nil
}

func (w *hoStepsWorld) setupHasDFNP() error {
	tr, err := w.setupTransfer()
	if err != nil {
		return err
	}
	for _, ie := range tr.ProtocolIEs.List {
		if ie.Id.Value != ngapType.ProtocolIEIDDataForwardingNotPossible {
			continue
		}
		if ie.Value.DataForwardingNotPossible == nil || ie.Value.DataForwardingNotPossible.Value != 0 {
			return fmt.Errorf("DataForwardingNotPossible value = %+v, want data-forwarding-not-possible (0)", ie.Value.DataForwardingNotPossible)
		}
		if ie.Criticality.Value != ngapType.CriticalityPresentReject {
			return fmt.Errorf("DataForwardingNotPossible criticality = %d, want reject", ie.Criticality.Value)
		}
		return nil
	}
	return fmt.Errorf("transfer lacks IE DataForwardingNotPossible (id 127)")
}

func (w *hoStepsWorld) setupQoS() error {
	tr, err := w.setupTransfer()
	if err != nil {
		return err
	}
	var gotAMBR, gotQFI bool
	for _, ie := range tr.ProtocolIEs.List {
		if a := ie.Value.PDUSessionAggregateMaximumBitRate; a != nil {
			gotAMBR = true
			if a.PDUSessionAggregateMaximumBitRateUL.Value != int64(w.sess.AMBRULMbps)*1_000_000 ||
				a.PDUSessionAggregateMaximumBitRateDL.Value != int64(w.sess.AMBRDLMbps)*1_000_000 {
				return fmt.Errorf("session AMBR UL/DL = %d/%d bit/s, want %d/%d Mbps",
					a.PDUSessionAggregateMaximumBitRateUL.Value, a.PDUSessionAggregateMaximumBitRateDL.Value,
					w.sess.AMBRULMbps, w.sess.AMBRDLMbps)
			}
		}
		if l := ie.Value.QosFlowSetupRequestList; l != nil {
			if len(l.List) != 1 || l.List[0].QosFlowIdentifier.Value != hoStepsQFI {
				return fmt.Errorf("QosFlowSetupRequestList does not carry exactly QFI %d", hoStepsQFI)
			}
			gotQFI = true
			nd := l.List[0].QosFlowLevelQosParameters.QosCharacteristics.NonDynamic5QI
			if nd == nil || nd.FiveQI.Value != int64(w.sess.FiveQI) {
				return fmt.Errorf("QFI %d 5QI = %+v, want %d", hoStepsQFI, nd, w.sess.FiveQI)
			}
		}
	}
	if !gotAMBR || !gotQFI {
		return fmt.Errorf("transfer lacks the session AMBR (%v) or the QosFlowSetupRequestList (%v)", gotAMBR, gotQFI)
	}
	return nil
}

func (w *hoStepsWorld) setupIEOrder(t *godog.Table) error {
	names := map[string]int64{
		"PDUSessionAggregateMaximumBitRate": ngapType.ProtocolIEIDPDUSessionAggregateMaximumBitRate,
		"ULNGUUPTNLInformation":             ngapType.ProtocolIEIDULNGUUPTNLInformation,
		"DataForwardingNotPossible":         ngapType.ProtocolIEIDDataForwardingNotPossible,
		"PDUSessionType":                    ngapType.ProtocolIEIDPDUSessionType,
		"QosFlowSetupRequestList":           ngapType.ProtocolIEIDQosFlowSetupRequestList,
	}
	tr, err := w.setupTransfer()
	if err != nil {
		return err
	}
	var want, got []int64
	for _, row := range t.Rows[1:] {
		id, err := strconv.ParseInt(strings.TrimSpace(row.Cells[1].Value), 10, 64)
		if err != nil {
			return err
		}
		n := strings.TrimSpace(row.Cells[0].Value)
		if names[n] != id {
			return fmt.Errorf("table maps %q to id %d, TS 38.413 has %d", n, id, names[n])
		}
		want = append(want, id)
	}
	for _, ie := range tr.ProtocolIEs.List {
		got = append(got, ie.Id.Value)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Errorf("transfer IE order = %v, want %v", got, want)
	}
	return nil
}

func (w *hoStepsWorld) sessionHO(state string, direct string) error {
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	if w.sess.HOState != state {
		return fmt.Errorf("session HOState = %q, want %q", w.sess.HOState, state)
	}
	if direct != "" && w.sess.HODirectForwarding != (direct == "true") {
		return fmt.Errorf("session HODirectForwarding = %v, want %s", w.sess.HODirectForwarding, direct)
	}
	return nil
}

func (w *hoStepsWorld) sessionHONot(state string) error {
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	if w.sess.HOState == state {
		return fmt.Errorf("session HOState = %q, want anything else", state)
	}
	return nil
}

func (w *hoStepsWorld) tunnelCleared() error { return w.noTunnelStored() }

func (w *hoStepsWorld) logDirRef(inRef, outRef, fwd string) error {
	for _, c := range []struct{ dir, ref string }{{"IN", inRef}, {"OUT", outRef}} {
		rec, ok := w.logs.find(func(r hoRec) bool {
			return r.attrs["interface"] == "Nsmf" && r.attrs["direction"] == c.dir && r.attrs["spec_ref"] == c.ref
		})
		if !ok {
			return fmt.Errorf("no log record with interface Nsmf, direction %s and spec_ref %q", c.dir, c.ref)
		}
		if c.dir == "OUT" && rec.attrs["data_forwarding"] != fwd {
			return fmt.Errorf("OUT log data_forwarding = %q, want %q", rec.attrs["data_forwarding"], fwd)
		}
	}
	return nil
}

func (w *hoStepsWorld) logDataForwarding(val string, withReason bool) error {
	rec, ok := w.logs.find(func(r hoRec) bool { return r.attrs["data_forwarding"] == val })
	if !ok {
		return fmt.Errorf("no log record with data_forwarding %q", val)
	}
	if withReason {
		for _, k := range []string{"reason", "data_forwarding_reason"} {
			if rec.attrs[k] != "" {
				return nil
			}
		}
		return fmt.Errorf("log record %q has data_forwarding=%q but no reason attribute (attrs %v)", rec.msg, val, rec.attrs)
	}
	return nil
}

func (w *hoStepsWorld) cmdTransfer() (ngapType.HandoverCommandTransfer, error) {
	var cmd ngapType.HandoverCommandTransfer
	b, err := w.respTransfer()
	if err != nil {
		return cmd, err
	}
	if err := aper.UnmarshalWithParams(b, &cmd, "valueExt"); err != nil {
		return cmd, fmt.Errorf("HandoverCommandTransfer does not decode: %w", err)
	}
	return cmd, nil
}

func (w *hoStepsWorld) cmdForwardingTunnel(ip string, teid int64) error {
	cmd, err := w.cmdTransfer()
	if err != nil {
		return err
	}
	if cmd.DLForwardingUPTNLInformation == nil || cmd.DLForwardingUPTNLInformation.GTPTunnel == nil {
		return fmt.Errorf("HandoverCommandTransfer carries no DLForwardingUPTNLInformation GTP tunnel")
	}
	g := cmd.DLForwardingUPTNLInformation.GTPTunnel
	if !net.IP(g.TransportLayerAddress.Value.Bytes).Equal(net.ParseIP(ip).To4()) {
		return fmt.Errorf("forwarding address = %v, want %s", net.IP(g.TransportLayerAddress.Value.Bytes), ip)
	}
	want := []byte{byte(teid >> 24), byte(teid >> 16), byte(teid >> 8), byte(teid)}
	if got := []byte(g.GTPTEID.Value); string(got) != string(want) {
		return fmt.Errorf("forwarding TEID = %x, want %x", got, want)
	}
	return nil
}

func (w *hoStepsWorld) cmdForwardedQFI(qfi int64) error {
	cmd, err := w.cmdTransfer()
	if err != nil {
		return err
	}
	if cmd.QosFlowToBeForwardedList == nil || len(cmd.QosFlowToBeForwardedList.List) != 1 ||
		cmd.QosFlowToBeForwardedList.List[0].QosFlowIdentifier.Value != qfi {
		return fmt.Errorf("QosFlowToBeForwardedList = %+v, want exactly QFI %d", cmd.QosFlowToBeForwardedList, qfi)
	}
	return nil
}

func (w *hoStepsWorld) cmdEmpty() error {
	cmd, err := w.cmdTransfer()
	if err != nil {
		return err
	}
	if cmd.DLForwardingUPTNLInformation != nil || cmd.QosFlowToBeForwardedList != nil {
		return fmt.Errorf("HandoverCommandTransfer is not empty: DLForwarding=%v QosFlowToBeForwardedList=%v",
			cmd.DLForwardingUPTNLInformation != nil, cmd.QosFlowToBeForwardedList != nil)
	}
	return nil
}

func (w *hoStepsWorld) logWarnAttr(key, val string) error {
	if _, ok := w.logs.find(func(r hoRec) bool { return r.level == slog.LevelWarn && r.attrs[key] == val }); !ok {
		return fmt.Errorf("no WARN log record with %s=%q", key, val)
	}
	return nil
}

func (w *hoStepsWorld) logUndecodableWarn() error {
	if _, ok := w.logs.find(func(r hoRec) bool {
		return r.level == slog.LevelWarn && strings.Contains(r.msg, "transfer undecodable")
	}); !ok {
		return fmt.Errorf("no WARN log record for the undecodable transfer")
	}
	return nil
}

func (w *hoStepsWorld) logDLSwitchPending() error {
	rec, ok := w.logs.find(func(r hoRec) bool {
		return r.level == slog.LevelWarn && r.attrs["dl_switch"] == "pending-human-approval"
	})
	if !ok {
		return fmt.Errorf("no WARN log record with dl_switch=pending-human-approval")
	}
	if got, want := rec.attrs["target_gnb_ip"], net.IP(w.sentIP[:]).String(); got != want {
		return fmt.Errorf("logged target tunnel address %q, want %q", got, want)
	}
	if got, want := rec.attrs["target_dl_teid"], strconv.FormatUint(uint64(w.sentTEID), 10); got != want {
		return fmt.Errorf("logged target tunnel TEID %q, want %q", got, want)
	}
	return nil
}

func (w *hoStepsWorld) logPrevStateNotPrepared(want string) error {
	rec, ok := w.logs.find(func(r hoRec) bool {
		return r.level == slog.LevelWarn && strings.Contains(r.msg, "HOState was not "+want)
	})
	if !ok {
		return fmt.Errorf("no WARN log record that HOState was not %q", want)
	}
	if rec.attrs["previous_ho_state"] == want {
		return fmt.Errorf("previous_ho_state = %q, want anything but %q", rec.attrs["previous_ho_state"], want)
	}
	return nil
}

// InitializeHandoverN2SMScenario wires handover_n2sm_responses.feature.
func InitializeHandoverN2SMScenario(ctx *godog.ScenarioContext) {
	w := &hoStepsWorld{}
	ctx.After(func(c context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.close()
		return c, nil
	})

	ctx.Step(`^an SMF with an active PDU session "([^"]+)" with PDU session id (\d+) and a stored UPF PFCP session$`, w.anActiveSession)
	ctx.Step(`^the PFCP client towards the UPF is a recording fake$`, w.pfcpFakeRecording)

	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with toBeSwitched true, n2SmInfoType "PATH_SWITCH_REQ" and a valid PathSwitchRequestTransfer$`, w.pathSwitchReq)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "PREPARED", n2SmInfoType "HANDOVER_REQ_ACK" and a valid HandoverRequestAcknowledgeTransfer$`, w.handoverReqAckValid)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "PREPARED", n2SmInfoType "HANDOVER_REQ_ACK" and the n2SmInfo bytes "([0-9a-f]+)"$`, w.handoverReqAckBytes)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with failedToBeSwitched true, n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and a valid PathSwitchRequestSetupFailedTransfer$`, w.setupFail)

	ctx.Step(`^the SMF responds 200 with a JSON SmContextUpdatedData$`, func() error { return w.respondsJSON(200) })
	ctx.Step(`^the SMF responds 200$`, func() error { return w.respondsStatus(200) })
	ctx.Step(`^the SMF responds 422$`, func() error { return w.respondsStatus(422) })
	ctx.Step(`^the SMF responds 404 with a ProblemDetails cause "([^"]+)"$`, func(c string) error { return w.respondsProblem(404, c) })
	ctx.Step(`^the response n2SmInfoType is "([^"]+)"$`, func(v string) error { return w.respField("n2SmInfoType", v) })
	ctx.Step(`^the response hoState is "([^"]+)"$`, func(v string) error { return w.respField("hoState", v) })
	ctx.Step(`^the response n2SmInfo is the base64 of a PathSwitchRequestAcknowledgeTransfer that decodes with free5gc/ngap using valueExt$`, w.respAckTransferDecodes)
	ctx.Step(`^the response n2SmInfo is the base64 of a HandoverCommandTransfer that decodes with free5gc/ngap using valueExt$`, w.respCmdTransferDecodes)
	ctx.Step(`^exactly one PFCP Session Modification Request is sent to the UPF with the target DL F-TEID(?:, as before this change)?$`, w.oneModification)
	ctx.Step(`^the SMF sends zero PFCP messages to the UPF$`, w.zeroPFCP)
	ctx.Step(`^the target DL NG-U tunnel \(GTP-U address and TEID\) of the transfer is stored on the session$`, w.tunnelStored)
	ctx.Step(`^no target tunnel is stored on the session$`, w.noTunnelStored)
	ctx.Step(`^the session state is unchanged$`, w.stateUnchanged)
	ctx.Step(`^the relayed Cause is logged at INFO$`, w.causeLoggedAtInfo)

	// ---- AMF-012 follow-up
	ctx.Step(`^the session "([^"]+)" was prepared with hoState "PREPARING" and (DirectForwardingPathAvailability|no DirectForwardingPathAvailability)$`,
		func(ref, d string) error {
			if d == "no DirectForwardingPathAvailability" {
				return w.wasPrepared(ref, "none")
			}
			return w.wasPrepared(ref, "and DirectForwardingPathAvailability")
		})
	ctx.Step(`^the session "([^"]+)" has a stored target DL NG-U tunnel from an earlier HANDOVER_REQ_ACK$`, w.preparedWithTunnel)
	ctx.Step(`^the session "([^"]+)" has hoState "(PREPARED|NONE)" and a stored target DL NG-U tunnel$`, w.hasHOStateAndTunnel)

	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "PREPARING", n2SmInfoType "HANDOVER_REQUIRED", a valid HandoverRequiredTransfer carrying DirectForwardingPathAvailability and a targetId$`, w.preparingDirectWithTarget)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "PREPARING" and (n2SmInfoType "HANDOVER_REQUIRED" and a valid HandoverRequiredTransfer without DirectForwardingPathAvailability|no n2SmInfo)$`, w.preparingVariant)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "PREPARING", n2SmInfoType "HANDOVER_REQUIRED" and a valid HandoverRequiredTransfer$`, w.preparingValid)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "PREPARING", n2SmInfoType "HANDOVER_REQUIRED" and the n2SmInfo bytes "([0-9a-f]+)"$`, w.preparingBytes)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "PREPARED", n2SmInfoType "HANDOVER_REQ_ACK" and a valid HandoverRequestAcknowledgeTransfer with DL Forwarding UP TNL Information "([0-9.]+)"/TEID 0x([0-9a-fA-F]+) and QFI 1 (with|without) DataForwardingAccepted$`,
		func(ref, ip, teid, acc string) error {
			v, err := strconv.ParseInt(teid, 16, 64)
			if err != nil {
				return err
			}
			return w.reqAckWithForwarding(ref, ip, v, acc)
		})
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a valid HandoverResourceAllocationUnsuccessfulTransfer$`, w.resAllocFailValid)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and the n2SmInfo bytes "([0-9a-f]+)"$`, w.resAllocFailBytes)
	ctx.Step(`^the AMF sends UpdateSMContext for "([^"]+)" with hoState "COMPLETED" and no n2SmInfo$`, w.completedNoN2)

	ctx.Step(`^the SMF responds (\d+) with Content-Type "application/json" and a SmContextUpdateError(?: with error\.cause "([^"]+)")?$`,
		func(code int, cause string) error { return w.respondsUpdateError(code, cause) })
	ctx.Step(`^the response has no n2SmInfo$`, w.noN2SmInfo)
	ctx.Step(`^the response n2SmInfo is the base64 of a HandoverPreparationUnsuccessfulTransfer with Cause "(protocol)" "([^"]+)"$`, w.prepFailCauseProtocol)
	ctx.Step(`^the response n2SmInfo is the base64 of a HandoverPreparationUnsuccessfulTransfer with (radioNetwork) Cause "([^"]+)" \((\d+)\)$`, w.prepFailCauseNumeric)
	ctx.Step(`^the response n2SmInfo is the base64 of a HandoverPreparationUnsuccessfulTransfer that decodes with free5gc/ngap using valueExt$`, w.prepFailDecodes)
	ctx.Step(`^that transfer carries Cause (.+)$`, w.prepFailCauseText)
	ctx.Step(`^the response n2SmInfo is the base64 of a PDUSessionResourceSetupRequestTransfer that decodes with free5gc/ngap using valueExt$`, w.setupTransferDecodes)
	ctx.Step(`^the transfer UL NG-U UP TNL Information carries the UPF N3 address and the UL TEID of the session$`, w.setupULTunnel)
	ctx.Step(`^the transfer does not contain the IE DataForwardingNotPossible \(id 127\)$`, w.setupHasNoDFNP)
	ctx.Step(`^the transfer contains the IE DataForwardingNotPossible \(id 127\) with value data-forwarding-not-possible \(0\) and criticality reject$`, w.setupHasDFNP)
	ctx.Step(`^the transfer carries QFI 1 with the session 5QI and the session AMBR$`, w.setupQoS)
	ctx.Step(`^the transfer IEs appear in this order:$`, w.setupIEOrder)
	ctx.Step(`^the session HOState is "([^"]*)" and HODirectForwarding is (true|false)$`, w.sessionHO)
	ctx.Step(`^the session HOState is "([^"]*)"$`, func(state string) error { return w.sessionHO(state, "") })
	ctx.Step(`^the session HOState is not "([^"]*)"$`, w.sessionHONot)
	ctx.Step(`^the session HOTargetGNBIP and HOTargetDLTEID are cleared$`, w.tunnelCleared)
	ctx.Step(`^the SMF logs interface "Nsmf" direction "IN" spec_ref "([^"]+)" and direction "OUT" spec_ref "([^"]+)" with data_forwarding "([^"]+)"$`, w.logDirRef)
	ctx.Step(`^the SMF logs data_forwarding "not-possible"$`, func() error { return w.logDataForwarding("not-possible", false) })
	ctx.Step(`^the SMF logs data_forwarding "none" with the reason$`, func() error { return w.logDataForwarding("none", true) })
	ctx.Step(`^the HandoverCommandTransfer DLForwardingUPTNLInformation equals the GTP tunnel "([0-9.]+)"/TEID 0x([0-9a-fA-F]+)$`,
		func(ip, teid string) error {
			v, err := strconv.ParseInt(teid, 16, 64)
			if err != nil {
				return err
			}
			return w.cmdForwardingTunnel(ip, v)
		})
	ctx.Step(`^the HandoverCommandTransfer QosFlowToBeForwardedList contains exactly QFI (\d+)$`, func(q int) error { return w.cmdForwardedQFI(int64(q)) })
	ctx.Step(`^the HandoverCommandTransfer carries neither DLForwardingUPTNLInformation nor QosFlowToBeForwardedList$`, w.cmdEmpty)
	ctx.Step(`^the SMF logs a WARN with (followup|detail) "([^"]+)"$`, w.logWarnAttr)
	ctx.Step(`^the undecodable transfer is logged with level WARN$`, w.logUndecodableWarn)
	ctx.Step(`^the SMF logs a WARN with dl_switch "pending-human-approval" and the stored target tunnel$`, w.logDLSwitchPending)
	ctx.Step(`^the SMF logs a WARN that the previous HOState was not "([^"]+)"$`, w.logPrevStateNotPrepared)

	registerUserPlaneSteps(ctx, w)
}

// TestHandoverN2SMFeatures runs handover_n2sm_responses.feature against the real
// handleUpdateSMContext handler.
func TestHandoverN2SMFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeHandoverN2SMScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/handover_n2sm_responses.feature"},
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
