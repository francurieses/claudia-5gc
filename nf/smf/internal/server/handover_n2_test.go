package server

// handover_n2_test.go — unit tests for the N2 handover SMF branches (hoState PREPARING /
// COMPLETED, HANDOVER_RES_ALLOC_FAIL, direct data forwarding, SmContextUpdateError shapes).
// Tests of the no-PFCP legs assert zero PFCP messages (silent fake UPF socket from hoFixture);
// the N4 legs are in handover_n2_pfcp_test.go.
// Ref: TS 23.502 §4.9.1.3.2, §4.9.1.3.3; TS 29.502 §5.2.2.3.4, §6.1.6.2.

import (
	"bytes"
	"encoding/base64"
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

func hoN2Fixture(t *testing.T) (*Server, *Session, *net.UDPConn) {
	t.Helper()
	s, sess, upf := hoFixture(t)
	s.cfg.UPFN3Addr = "10.0.0.1"
	sess.ULTEID = 0x1001
	sess.FiveQI = 9
	sess.AMBRULMbps, sess.AMBRDLMbps = 100, 200
	return s, sess, upf
}

func noPFCP(t *testing.T, upf *net.UDPConn) {
	t.Helper()
	if got := pfcpCount(upf, 300*time.Millisecond, 0); got != 0 {
		t.Fatalf("PFCP sends = %d, want 0", got)
	}
}

func b64s(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeSetupTransfer(t *testing.T, b []byte) (ngapType.PDUSessionResourceSetupRequestTransfer, []int64) {
	t.Helper()
	var tr ngapType.PDUSessionResourceSetupRequestTransfer
	if err := aper.UnmarshalWithParams(b, &tr, "valueExt"); err != nil {
		t.Fatalf("decode PDUSessionResourceSetupRequestTransfer: %v", err)
	}
	var ids []int64
	for _, ie := range tr.ProtocolIEs.List {
		ids = append(ids, ie.Id.Value)
	}
	return tr, ids
}

func equalIDs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestHandoverPreparing(t *testing.T) {
	direct := hoMarshal(t, ngapType.HandoverRequiredTransfer{
		DirectForwardingPathAvailability: &ngapType.DirectForwardingPathAvailability{
			Value: 0}})
	cases := []struct {
		name     string
		n2       []byte // nil = omit n2SmInfo
		typ      string
		wantIDs  []int64
		wantDirc bool
	}{
		{"no direct path", hoMarshal(t, ngapType.HandoverRequiredTransfer{}), "HANDOVER_REQUIRED", []int64{130, 139, 127, 134, 136}, false},
		{"direct path", direct, "HANDOVER_REQUIRED", []int64{130, 139, 134, 136}, true},
		{"no n2SmInfo", nil, "", []int64{130, 139, 127, 134, 136}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, sess, upf := hoN2Fixture(t)
			body := map[string]interface{}{"hoState": "PREPARING",
				"targetId": map[string]interface{}{"tai": map[string]interface{}{"tac": "000001"}}}
			if c.typ != "" {
				body["n2SmInfoType"] = c.typ
			}
			if c.n2 != nil {
				body["n2SmInfo"] = b64s(c.n2)
			}
			w := hoPost(s, hoTestRef, body)
			if w.Code != http.StatusOK {
				t.Fatalf("code = %d: %s", w.Code, w.Body.String())
			}
			m := hoDecodeResp(t, w)
			if m["hoState"] != "PREPARING" || m["n2SmInfoType"] != "PDU_RES_SETUP_REQ" {
				t.Fatalf("resp = %v", m)
			}
			tr, ids := decodeSetupTransfer(t, hoRespTransfer(t, m))
			if !equalIDs(ids, c.wantIDs) {
				t.Fatalf("IE ids = %v, want %v", ids, c.wantIDs)
			}
			// UL tunnel unchanged: UPF N3 address + session UL TEID.
			gtp := tr.ProtocolIEs.List[1].Value.ULNGUUPTNLInformation.GTPTunnel
			if got := []byte(gtp.GTPTEID.Value); !bytes.Equal(got, encodeGTPTEID(0x1001)) {
				t.Fatalf("UL TEID = %x", got)
			}
			if !bytes.Equal(gtp.TransportLayerAddress.Value.Bytes, net.ParseIP("10.0.0.1").To4()) {
				t.Fatalf("UL addr = %x", gtp.TransportLayerAddress.Value.Bytes)
			}
			s.sessionMu.Lock()
			if sess.HOState != "PREPARING" || sess.HODirectForwarding != c.wantDirc {
				t.Fatalf("HOState=%q direct=%v", sess.HOState, sess.HODirectForwarding)
			}
			s.sessionMu.Unlock()
			noPFCP(t, upf)
		})
	}
}

func TestHandoverPreparingErrors(t *testing.T) {
	cases := []struct {
		name      string
		ref       string
		n2        string
		typ       string
		status    int
		cause     string
		wantGroup int
		wantVal   aper.Enumerated
	}{
		{"unknown context", "sm-ctx-unknown", "", "", 404, "CONTEXT_NOT_FOUND",
			ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownPDUSessionID},
		{"undecodable transfer", hoTestRef, b64s([]byte{0xff, 0xff, 0xff, 0xff}), "HANDOVER_REQUIRED", 422, "SYSTEM_FAILURE",
			ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError},
		{"unexpected n2SmInfoType", hoTestRef, b64s([]byte{0x00}), "PDU_RES_SETUP_REQ", 422, "SYSTEM_FAILURE",
			ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, sess, upf := hoN2Fixture(t)
			body := map[string]interface{}{"hoState": "PREPARING", "n2SmInfoType": c.typ}
			if c.n2 != "" {
				body["n2SmInfo"] = c.n2
			}
			w := hoPost(s, c.ref, body)
			if w.Code != c.status {
				t.Fatalf("code = %d: %s", w.Code, w.Body.String())
			}
			m := hoDecodeResp(t, w)
			e, _ := m["error"].(map[string]interface{})
			if e == nil || e["cause"] != c.cause {
				t.Fatalf("error = %v", m)
			}
			if m["n2SmInfoType"] != "HANDOVER_PREP_FAIL" {
				t.Fatalf("n2SmInfoType = %v", m["n2SmInfoType"])
			}
			var u ngapType.HandoverPreparationUnsuccessfulTransfer
			if err := aper.UnmarshalWithParams(hoRespTransfer(t, m), &u, "valueExt"); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if u.Cause.Present != c.wantGroup || ngapCauseValue(u.Cause) != int64(c.wantVal) {
				t.Fatalf("cause = %+v", u.Cause)
			}
			if sess.HOState != "" {
				t.Fatalf("HOState set on failure: %q", sess.HOState)
			}
			noPFCP(t, upf)
		})
	}
}

// TestSetupTransferExistingCallersByteIdentical proves the unchanged-output refactor: the
// original builder equals the options variant with the flag off, and removing IE 127 from the
// flag-on output and re-encoding gives exactly the same bytes.
func TestSetupTransferExistingCallersByteIdentical(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	old, err := buildPDUSessionResourceSetupRequestTransfer(ip, 0x1001, 1, 9, 100_000_000, 200_000_000, ngapType.PDUSessionTypePresentIpv4)
	if err != nil {
		t.Fatal(err)
	}
	off, _ := buildPDUSessionResourceSetupRequestTransferOpts(ip, 0x1001, 1, 9, 100_000_000, 200_000_000, ngapType.PDUSessionTypePresentIpv4, false)
	if !bytes.Equal(old, off) {
		t.Fatalf("flag off differs:\n%x\n%x", old, off)
	}
	on, _ := buildPDUSessionResourceSetupRequestTransferOpts(ip, 0x1001, 1, 9, 100_000_000, 200_000_000, ngapType.PDUSessionTypePresentIpv4, true)
	tr, ids := decodeSetupTransfer(t, on)
	if !equalIDs(ids, []int64{130, 139, 127, 134, 136}) {
		t.Fatalf("ids = %v", ids)
	}
	if tr.ProtocolIEs.List[2].Criticality.Value != ngapType.CriticalityPresentReject {
		t.Fatalf("IE 127 criticality = %d, want reject", tr.ProtocolIEs.List[2].Criticality.Value)
	}
	if tr.ProtocolIEs.List[2].Value.DataForwardingNotPossible.Value != ngapType.DataForwardingNotPossiblePresentDataForwardingNotPossible {
		t.Fatalf("IE 127 value wrong")
	}
	tr.ProtocolIEs.List = append(tr.ProtocolIEs.List[:2], tr.ProtocolIEs.List[3:]...)
	re := hoMarshal(t, tr)
	if !bytes.Equal(old, re) {
		t.Fatalf("stripped flag-on output differs from original:\n%x\n%x", old, re)
	}
	_, ids = decodeSetupTransfer(t, old)
	if !equalIDs(ids, []int64{130, 139, 134, 136}) {
		t.Fatalf("original ids = %v", ids)
	}
}

func hoAck(t *testing.T, fwd *ngapType.UPTransportLayerInformation, accepted bool) []byte {
	t.Helper()
	item := ngapType.QosFlowItemWithDataForwarding{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}}
	if accepted {
		item.DataForwardingAccepted = &ngapType.DataForwardingAccepted{Value: ngapType.DataForwardingAcceptedPresentDataForwardingAccepted}
	}
	other := ngapType.QosFlowItemWithDataForwarding{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 2}}
	return hoMarshal(t, ngapType.HandoverRequestAcknowledgeTransfer{
		DLNGUUPTNLInformation:        hoGTPTunnel([4]byte{10, 0, 0, 7}, 0xABCD),
		DLForwardingUPTNLInformation: fwd,
		QosFlowSetupResponseList:     ngapType.QosFlowListWithDataForwarding{List: []ngapType.QosFlowItemWithDataForwarding{item, other}},
	})
}

func TestHandoverReqAckDataForwarding(t *testing.T) {
	fwd := hoGTPTunnel([4]byte{10, 0, 0, 8}, 0x77)
	cases := []struct {
		name     string
		direct   bool
		fwd      *ngapType.UPTransportLayerInformation
		accepted bool
		want     bool // HandoverCommandTransfer carries forwarding info
	}{
		{"direct + fwd tunnel + accepted flow", true, &fwd, true, true},
		{"no direct path", false, &fwd, true, false},
		{"direct but target gave no tunnel", true, nil, true, false},
		{"direct but no flow accepted", true, &fwd, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, sess, upf := hoN2Fixture(t)
			sess.HODirectForwarding = c.direct
			w := hoPost(s, hoTestRef, map[string]interface{}{
				"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_REQ_ACK", "n2SmInfo": b64s(hoAck(t, c.fwd, c.accepted))})
			if w.Code != 200 {
				t.Fatalf("code = %d: %s", w.Code, w.Body.String())
			}
			m := hoDecodeResp(t, w)
			if m["hoState"] != "PREPARED" || m["n2SmInfoType"] != "HANDOVER_CMD" {
				t.Fatalf("resp = %v", m)
			}
			var cmd ngapType.HandoverCommandTransfer
			if err := aper.UnmarshalWithParams(hoRespTransfer(t, m), &cmd, "valueExt"); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if c.want {
				if cmd.DLForwardingUPTNLInformation == nil || cmd.QosFlowToBeForwardedList == nil {
					t.Fatalf("forwarding info missing: %+v", cmd)
				}
				g := cmd.DLForwardingUPTNLInformation.GTPTunnel
				if !bytes.Equal(g.GTPTEID.Value, encodeGTPTEID(0x77)) {
					t.Fatalf("fwd TEID = %x", []byte(g.GTPTEID.Value))
				}
				l := cmd.QosFlowToBeForwardedList.List
				if len(l) != 1 || l[0].QosFlowIdentifier.Value != 1 {
					t.Fatalf("forwarded flows = %+v", l)
				}
			} else if cmd.DLForwardingUPTNLInformation != nil || cmd.QosFlowToBeForwardedList != nil {
				t.Fatalf("unexpected forwarding info: %+v", cmd)
			}
			if sess.HOState != "PREPARED" || sess.HOTargetDLTEID != 0xABCD || sess.State != "ACTIVE" {
				t.Fatalf("HOState=%q teid=%#x state=%q", sess.HOState, sess.HOTargetDLTEID, sess.State)
			}
			noPFCP(t, upf)
		})
	}
}

func TestHandoverReqAckErrorShape(t *testing.T) {
	s, sess, upf := hoN2Fixture(t)
	w := hoPost(s, hoTestRef, map[string]interface{}{
		"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_REQ_ACK", "n2SmInfo": b64s([]byte{0xff, 0xff, 0xff, 0xff})})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code = %d", w.Code)
	}
	m := hoDecodeResp(t, w)
	if m["n2SmInfoType"] != "HANDOVER_PREP_FAIL" {
		t.Fatalf("body = %s", w.Body.String())
	}
	var u ngapType.HandoverPreparationUnsuccessfulTransfer
	if err := aper.UnmarshalWithParams(hoRespTransfer(t, m), &u, "valueExt"); err != nil {
		t.Fatal(err)
	}
	if u.Cause.Present != ngapType.CausePresentProtocol || u.Cause.Protocol.Value != ngapType.CauseProtocolPresentSemanticError {
		t.Fatalf("cause = %+v", u.Cause)
	}
	if sess.HOState != "" {
		t.Fatalf("HOState = %q", sess.HOState)
	}
	noPFCP(t, upf)
}

func TestHandoverPrepFailTransferHoFailureCause(t *testing.T) {
	b := handoverPrepFailTransfer(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)
	var u ngapType.HandoverPreparationUnsuccessfulTransfer
	if err := aper.UnmarshalWithParams(b, &u, "valueExt"); err != nil {
		t.Fatal(err)
	}
	if ngapCauseValue(u.Cause) != 7 || u.Cause.Present != ngapType.CausePresentRadioNetwork {
		t.Fatalf("cause = %+v", u.Cause)
	}
}

func TestHandoverResAllocFail(t *testing.T) {
	valid := hoMarshal(t, ngapType.HandoverResourceAllocationUnsuccessfulTransfer{Cause: ngapCause(
		ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable)})
	cases := []struct {
		name string
		n2   string
	}{
		{"valid transfer", b64s(valid)},
		{"undecodable transfer still accepted", b64s([]byte{0xff, 0xff})},
		{"no n2SmInfo", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, sess, upf := hoN2Fixture(t)
			sess.HOTargetGNBIP, sess.HOTargetDLTEID, sess.HOState, sess.HODirectForwarding = net.IPv4(10, 0, 0, 7), 5, "PREPARED", true
			body := map[string]interface{}{"hoState": "PREPARED", "n2SmInfoType": "HANDOVER_RES_ALLOC_FAIL"}
			if c.n2 != "" {
				body["n2SmInfo"] = c.n2
			}
			w := hoPost(s, hoTestRef, body)
			if w.Code != 403 {
				t.Fatalf("code = %d: %s", w.Code, w.Body.String())
			}
			m := hoDecodeResp(t, w)
			if m["n2SmInfoType"] != "HANDOVER_PREP_FAIL" {
				t.Fatalf("resp = %v", m)
			}
			if sess.HOTargetGNBIP != nil || sess.HOTargetDLTEID != 0 || sess.HOState != "NONE" || sess.HODirectForwarding || !sess.HOTargetFailed {
				t.Fatalf("state not cleared: %+v", sess)
			}
			if sess.State != "ACTIVE" {
				t.Fatalf("session state = %q", sess.State)
			}
			noPFCP(t, upf)
		})
	}
	t.Run("unknown context", func(t *testing.T) {
		s, _, upf := hoN2Fixture(t)
		w := hoPost(s, "sm-ctx-unknown", map[string]interface{}{
			"n2SmInfoType": "HANDOVER_RES_ALLOC_FAIL", "n2SmInfo": b64s(valid)})
		if w.Code != 404 {
			t.Fatalf("code = %d", w.Code)
		}
		m := hoDecodeResp(t, w)
		if e, _ := m["error"].(map[string]interface{}); e == nil || e["cause"] != "CONTEXT_NOT_FOUND" {
			t.Fatalf("body = %s", w.Body.String())
		}
		if _, has := m["n2SmInfo"]; has {
			t.Fatalf("unexpected n2SmInfo")
		}
		noPFCP(t, upf)
	})
}

// TestHandoverCompleteUnknownContext: COMPLETED for an unknown SM context is a 404
// SmContextUpdateError and sends no PFCP (the switching cases are in handover_n2_pfcp_test.go).
func TestHandoverCompleteUnknownContext(t *testing.T) {
	s, _, upf := hoN2Fixture(t)
	w := hoPost(s, "sm-ctx-unknown", map[string]interface{}{"hoState": "COMPLETED"})
	if w.Code != 404 {
		t.Fatalf("code = %d", w.Code)
	}
	m := hoDecodeResp(t, w)
	if e, _ := m["error"].(map[string]interface{}); e == nil || e["cause"] != "CONTEXT_NOT_FOUND" {
		t.Fatalf("body = %s", w.Body.String())
	}
	noPFCP(t, upf)
}

// TestHandoverBranchLogsMandatoryFields checks one procedure key, correlation id, interface,
// direction and spec_ref on the new branches.
func TestHandoverBranchLogsMandatoryFields(t *testing.T) {
	s, _, _ := hoN2Fixture(t)
	var buf bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&buf, nil))
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"hoState":"PREPARING"}`))
	r.SetPathValue("smContextRef", hoTestRef)
	r.Header.Set("X-Correlation-Id", "01CORR")
	s.handleUpdateSMContext(httptest.NewRecorder(), r)
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if !strings.Contains(line, "procedure=N2Handover") || strings.Count(line, "procedure=") != 1 ||
			!strings.Contains(line, "correlation_id=01CORR") || !strings.Contains(line, "interface=Nsmf") ||
			!strings.Contains(line, "direction=") || !strings.Contains(line, "spec_ref=\"TS 23.502 §4.9.1.3.2 step") {
			t.Fatalf("log line lacks mandatory fields: %s", line)
		}
	}
}
