package server

// handover_n2sm_test.go — UpdateSMContext responses for handover N2 SM info
// (AMF-012 companion). Mirrors tests/features/handover_n2sm_responses.feature.
// Fake UPF = a UDP listener at cfg.Peers.UPF whose received datagrams are the
// PFCP sends. Ref: TS 23.502 §4.9.1.2.2 steps 2-6, §4.9.1.3.2 steps 9-12.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
)

const hoTestRef = "sm-ctx-1"

func hoGTPTunnel(ip [4]byte, teid uint32) ngapType.UPTransportLayerInformation {
	return ngapType.UPTransportLayerInformation{
		Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
		GTPTunnel: &ngapType.GTPTunnel{
			TransportLayerAddress: ngapType.TransportLayerAddress{Value: aper.BitString{Bytes: ip[:], BitLength: 32}},
			GTPTEID:               ngapType.GTPTEID{Value: aper.OctetString{byte(teid >> 24), byte(teid >> 16), byte(teid >> 8), byte(teid)}},
		},
	}
}

func hoPathSwitchTransfer(ip [4]byte, teid uint32) ngapType.PathSwitchRequestTransfer {
	return ngapType.PathSwitchRequestTransfer{
		DLNGUUPTNLInformation: hoGTPTunnel(ip, teid),
		QosFlowAcceptedList: ngapType.QosFlowAcceptedList{List: []ngapType.QosFlowAcceptedItem{
			{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}}}},
	}
}

func hoMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := aper.MarshalWithParams(v, "valueExt")
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return b
}

// hoFixture returns a server with one ACTIVE session and a fake UPF socket.
func hoFixture(t *testing.T) (*Server, *Session, *net.UDPConn) {
	t.Helper()
	upf, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen fake UPF: %v", err)
	}
	t.Cleanup(func() { _ = upf.Close() })
	s := newTestSMFServer(t)
	s.cfg.Peers.UPF = upf.LocalAddr().String()
	sess := &Session{SUPI: "imsi-001010000000001", PDUSessionID: 1, DNN: "internet", SEID: 42, State: "ACTIVE"}
	s.sessions[hoTestRef] = sess
	return s, sess, upf
}

func hoPost(s *Server, ref string, body map[string]interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/"+ref+"/modify", strings.NewReader(string(b)))
	r.SetPathValue("smContextRef", ref)
	w := httptest.NewRecorder()
	s.handleUpdateSMContext(w, r)
	return w
}

// pfcpCount drains the fake UPF for up to wait and returns the datagram count.
func pfcpCount(upf *net.UDPConn, wait time.Duration, want int) int {
	n := 0
	buf := make([]byte, 4096)
	deadline := time.Now().Add(wait)
	for n < want || time.Now().Before(deadline) {
		_ = upf.SetReadDeadline(deadline)
		if _, _, err := upf.ReadFromUDP(buf); err != nil {
			break
		}
		n++
	}
	return n
}

func hoDecodeResp(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return m
}

func hoRespTransfer(t *testing.T, m map[string]interface{}) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(m["n2SmInfo"].(string))
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}

func TestUpdateSMContext_PathSwitchReqAck(t *testing.T) {
	s, sess, upf := hoRespFixture(t)
	tr := hoPathSwitchTransfer([4]byte{10, 0, 0, 9}, 0x1234)
	w := hoPost(s, hoTestRef, map[string]interface{}{
		"toBeSwitched": true, "n2SmInfoType": "PATH_SWITCH_REQ",
		"n2SmInfo": base64.StdEncoding.EncodeToString(hoMarshal(t, tr)),
	})
	if w.Code != 200 {
		t.Fatalf("code = %d: %s", w.Code, w.Body.String())
	}
	m := hoDecodeResp(t, w)
	if m["n2SmInfoType"] != "PATH_SWITCH_REQ_ACK" {
		t.Fatalf("n2SmInfoType = %v", m["n2SmInfoType"])
	}
	var ack ngapType.PathSwitchRequestAcknowledgeTransfer
	if err := aper.UnmarshalWithParams(hoRespTransfer(t, m), &ack, "valueExt"); err != nil {
		t.Fatalf("decode ack transfer: %v", err)
	}
	// The answer is only written after the Session Modification Response, so the request
	// has been recorded by now.
	reqs := upf.requests()
	if len(reqs) != 1 {
		t.Fatalf("PFCP sends = %d, want exactly 1", len(reqs))
	}
	if !bytes.Equal(reqs[0].far, legacyDLSwitchFAR(0x1234, net.IPv4(10, 0, 0, 9))) {
		t.Fatalf("Update FAR differs from the pre-SMF-005 encoding: %x", reqs[0].far)
	}
	if sess.State != "ACTIVE" {
		t.Fatalf("state = %q", sess.State)
	}
}

func TestUpdateSMContext_HandoverReqAck(t *testing.T) {
	s, sess, upf := hoFixture(t)
	tr := ngapType.HandoverRequestAcknowledgeTransfer{
		DLNGUUPTNLInformation: hoGTPTunnel([4]byte{10, 0, 0, 7}, 0xABCD),
		QosFlowSetupResponseList: ngapType.QosFlowListWithDataForwarding{List: []ngapType.QosFlowItemWithDataForwarding{
			{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}}}},
	}
	w := hoPost(s, hoTestRef, map[string]interface{}{
		"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_REQ_ACK",
		"n2SmInfo": base64.StdEncoding.EncodeToString(hoMarshal(t, tr)),
	})
	if w.Code != 200 {
		t.Fatalf("code = %d: %s", w.Code, w.Body.String())
	}
	m := hoDecodeResp(t, w)
	if m["hoState"] != "PREPARED" || m["n2SmInfoType"] != "HANDOVER_CMD" {
		t.Fatalf("resp = %v", m)
	}
	var cmd ngapType.HandoverCommandTransfer
	if err := aper.UnmarshalWithParams(hoRespTransfer(t, m), &cmd, "valueExt"); err != nil {
		t.Fatalf("decode HandoverCommandTransfer: %v", err)
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if !sess.HOTargetGNBIP.Equal(net.IPv4(10, 0, 0, 7)) || sess.HOTargetDLTEID != 0xABCD {
		t.Fatalf("stored tunnel = %v / %#x", sess.HOTargetGNBIP, sess.HOTargetDLTEID)
	}
	if sess.State != "ACTIVE" {
		t.Fatalf("state changed to %q", sess.State)
	}
	if got := pfcpCount(upf, 300*time.Millisecond, 0); got != 0 {
		t.Fatalf("PFCP sends = %d, want 0", got)
	}
}

func TestUpdateSMContext_HandoverReqAckStateIndependent(t *testing.T) {
	s, sess, _ := hoFixture(t)
	sess.State = "IDLE"
	tr := ngapType.HandoverRequestAcknowledgeTransfer{
		DLNGUUPTNLInformation: hoGTPTunnel([4]byte{10, 0, 0, 7}, 1),
		QosFlowSetupResponseList: ngapType.QosFlowListWithDataForwarding{List: []ngapType.QosFlowItemWithDataForwarding{
			{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}}}},
	}
	w := hoPost(s, hoTestRef, map[string]interface{}{
		"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_REQ_ACK",
		"n2SmInfo": base64.StdEncoding.EncodeToString(hoMarshal(t, tr)),
	})
	if w.Code != 200 || sess.State != "IDLE" {
		t.Fatalf("code=%d state=%q", w.Code, sess.State)
	}
}

func TestUpdateSMContext_PathSwitchSetupFail(t *testing.T) {
	s, sess, upf := hoRespFixture(t)
	tr := ngapType.PathSwitchRequestSetupFailedTransfer{Cause: ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable},
	}}
	w := hoPost(s, hoTestRef, map[string]interface{}{
		"failedToBeSwitched": true, "n2SmInfoType": "PATH_SWITCH_SETUP_FAIL",
		"n2SmInfo": base64.StdEncoding.EncodeToString(hoMarshal(t, tr)),
	})
	if w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("code = %d body %q, want 204 empty", w.Code, w.Body.String())
	}
	s.WaitHandoverTasks()
	reqs := upf.requests()
	if len(reqs) != 1 || !bytes.Equal(reqs[0].far, farBytes(t, buildDLDropFAR())) {
		t.Fatalf("PFCP = %+v, want one Update FAR DROP", reqs)
	}
	if st := hoState(s, sess); st != "IDLE" {
		t.Fatalf("state = %q, want IDLE", st)
	}
}

func TestUpdateSMContext_HandoverReqAckUndecodable422(t *testing.T) {
	s, sess, upf := hoFixture(t)
	w := hoPost(s, hoTestRef, map[string]interface{}{
		"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_REQ_ACK",
		"n2SmInfo": base64.StdEncoding.EncodeToString([]byte{0xff, 0xff, 0xff, 0xff}),
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code = %d", w.Code)
	}
	if sess.HOTargetGNBIP != nil || sess.HOTargetDLTEID != 0 {
		t.Fatalf("tunnel stored on failure")
	}
	if got := pfcpCount(upf, 300*time.Millisecond, 0); got != 0 {
		t.Fatalf("PFCP sends = %d", got)
	}
}

func TestUpdateSMContext_UnknownContext404(t *testing.T) {
	ok := hoMarshal(t, ngapType.HandoverRequestAcknowledgeTransfer{
		DLNGUUPTNLInformation: hoGTPTunnel([4]byte{10, 0, 0, 7}, 1),
		QosFlowSetupResponseList: ngapType.QosFlowListWithDataForwarding{List: []ngapType.QosFlowItemWithDataForwarding{
			{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}}}},
	})
	ps := hoMarshal(t, hoPathSwitchTransfer([4]byte{10, 0, 0, 9}, 5))
	sf := hoMarshal(t, ngapType.PathSwitchRequestSetupFailedTransfer{Cause: ngapType.Cause{
		Present: ngapType.CausePresentRadioNetwork, RadioNetwork: &ngapType.CauseRadioNetwork{Value: 1}}})
	cases := []struct {
		name, typ string
		n2        []byte
		failType  string
	}{
		{"HANDOVER_REQ_ACK", "HANDOVER_REQ_ACK", ok, "HANDOVER_PREP_FAIL"},
		{"PATH_SWITCH_REQ", "PATH_SWITCH_REQ", ps, "PATH_SWITCH_REQ_FAIL"},
		{"PATH_SWITCH_SETUP_FAIL", "PATH_SWITCH_SETUP_FAIL", sf, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, upf := hoFixture(t)
			w := hoPost(s, "sm-ctx-unknown", map[string]interface{}{
				"n2SmInfoType": c.typ, "n2SmInfo": base64.StdEncoding.EncodeToString(c.n2),
			})
			if w.Code != http.StatusNotFound {
				t.Fatalf("code = %d", w.Code)
			}
			// Every handover error is an SmContextUpdateError (TS 29.502 §6.1.6.2).
			m := hoDecodeResp(t, w)
			e, _ := m["error"].(map[string]interface{})
			if e == nil || e["cause"] != "CONTEXT_NOT_FOUND" {
				t.Fatalf("error.cause = %v (body %s)", e, w.Body.String())
			}
			switch c.failType {
			case "":
				if _, has := m["n2SmInfo"]; has {
					t.Fatalf("unexpected n2SmInfo: %s", w.Body.String())
				}
			case "HANDOVER_PREP_FAIL":
				if m["n2SmInfoType"] != c.failType {
					t.Fatalf("n2SmInfoType = %v", m["n2SmInfoType"])
				}
				var u ngapType.HandoverPreparationUnsuccessfulTransfer
				if err := aper.UnmarshalWithParams(hoRespTransfer(t, m), &u, "valueExt"); err != nil {
					t.Fatalf("decode prep-fail transfer: %v", err)
				}
				if u.Cause.Present != ngapType.CausePresentRadioNetwork || u.Cause.RadioNetwork.Value != ngapType.CauseRadioNetworkPresentUnknownPDUSessionID {
					t.Fatalf("cause = %+v", u.Cause)
				}
			default:
				if m["n2SmInfoType"] != c.failType {
					t.Fatalf("n2SmInfoType = %v", m["n2SmInfoType"])
				}
				var u ngapType.PathSwitchRequestUnsuccessfulTransfer
				if err := aper.UnmarshalWithParams(hoRespTransfer(t, m), &u, "valueExt"); err != nil {
					t.Fatalf("decode unsuccessful transfer: %v", err)
				}
			}
			if got := pfcpCount(upf, 300*time.Millisecond, 0); got != 0 {
				t.Fatalf("PFCP sends = %d", got)
			}
		})
	}
}

// TestHandoverLogs_SingleProcedureAndCorrelation checks that the handover branches log
// exactly one `procedure` key and carry the X-Correlation-Id of the request.
func TestHandoverLogs_SingleProcedureAndCorrelation(t *testing.T) {
	s, _, _ := hoRespFixture(t)
	buf := &lockedBuf{}
	s.logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sf := hoMarshal(t, ngapType.PathSwitchRequestSetupFailedTransfer{Cause: ngapType.Cause{
		Present: ngapType.CausePresentRadioNetwork, RadioNetwork: &ngapType.CauseRadioNetwork{Value: 1}}})
	b, _ := json.Marshal(map[string]interface{}{
		"n2SmInfoType": "PATH_SWITCH_SETUP_FAIL", "n2SmInfo": base64.StdEncoding.EncodeToString(sf)})
	r := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(b))
	r.SetPathValue("smContextRef", hoTestRef)
	r.Header.Set("X-Correlation-Id", "01TESTCORR")
	s.handleUpdateSMContext(httptest.NewRecorder(), r)
	s.WaitHandoverTasks()
	buf.mu.Lock()
	out := buf.b.String()
	buf.mu.Unlock()
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if n := strings.Count(line, "procedure="); n != 1 {
			t.Fatalf("procedure keys = %d, want 1: %s", n, line)
		}
		if !strings.Contains(line, "procedure=XnHandover") || !strings.Contains(line, "correlation_id=01TESTCORR") {
			t.Fatalf("missing XnHandover / correlation_id: %s", line)
		}
	}
	if !strings.Contains(out, "TS 23.502 §4.9.1.2.2 step 2") {
		t.Fatalf("spec_ref not step 2: %s", out)
	}
}

// TestPathSwitchAckEncodeFailure asserts the SmContextUpdateError shape for a failed
// PathSwitchRequestAcknowledgeTransfer encode. Ref: TS 29.502 §5.2.2.3.3, §6.1.6.2.
func TestPathSwitchAckEncodeFailure(t *testing.T) {
	rec := httptest.NewRecorder()
	pathSwitchAckEncodeFailure(rec, errors.New("boom"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var body struct {
		Error struct {
			Status int    `json:"status"`
			Cause  string `json:"cause"`
		} `json:"error"`
		N2SmInfo     string `json:"n2SmInfo"`
		N2SmInfoType string `json:"n2SmInfoType"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Error.Status != 500 || body.Error.Cause != "SYSTEM_FAILURE" {
		t.Errorf("error = %+v", body.Error)
	}
	if body.N2SmInfoType != "PATH_SWITCH_REQ_FAIL" {
		t.Errorf("n2SmInfoType = %q", body.N2SmInfoType)
	}
	raw, err := base64.StdEncoding.DecodeString(body.N2SmInfo)
	if err != nil || len(raw) == 0 {
		t.Fatalf("n2SmInfo decode: %v len=%d", err, len(raw))
	}
	var tr ngapType.PathSwitchRequestUnsuccessfulTransfer
	if err := aper.UnmarshalWithParams(raw, &tr, "valueExt"); err != nil {
		t.Fatalf("decode transfer: %v", err)
	}
	if tr.Cause.Present != ngapType.CausePresentRadioNetwork || tr.Cause.RadioNetwork == nil ||
		tr.Cause.RadioNetwork.Value != ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem {
		t.Errorf("cause = %+v", tr.Cause)
	}
}
