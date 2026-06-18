package server

// smf_modify_test.go — HTTP handler test for PDU Session Modification (UE-requested).
// Tests the Nsmf_PDUSession_UpdateSMContext path when the body carries a 5GSM
// PDU Session Modification Request (0xC9).
// Ref: TS 23.502 §4.3.3.1, TS 29.502 §5.2.2.3.2

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func newTestSMFServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{UEIPPool: "10.60.0.0/24"}
	s, err := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)), nil)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	return s
}

// TestHandleUpdateSMContext_ModifiesSession verifies that a 5GSM Modification Request
// (0xC9) results in HTTP 200 with a valid 0xCB Modification Command in n1SmMsg and a
// non-empty N2SM transfer in n2SmInfo.
func TestHandleUpdateSMContext_ModifiesSession(t *testing.T) {
	s := newTestSMFServer(t)

	const smContextRef = "ctx-modify-001"
	const psi uint8 = 1
	const pti uint8 = 7

	// 5GSM PDU Session Modification Request: EPD | PSI | PTI | 0xC9 (no body IEs)
	n1SmReq := []byte{nas.PDGroupSessionManagement, psi, pti, byte(nas.MsgTypePDUSessionModificationRequest)}
	reqBody := map[string]interface{}{
		"n1SmMsg":      base64.StdEncoding.EncodeToString(n1SmReq),
		"pduSessionId": int(psi),
	}
	bodyJSON, _ := json.Marshal(reqBody)

	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/"+smContextRef+"/modify",
		strings.NewReader(string(bodyJSON)))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("smContextRef", smContextRef)
	w := httptest.NewRecorder()

	s.handleUpdateSMContext(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}

	// ---- n1SmMsg: must be a valid 0xCB Modification Command ----
	n1B64, ok := resp["n1SmMsg"].(string)
	if !ok || n1B64 == "" {
		t.Fatal("n1SmMsg missing or empty in response")
	}
	n1Bytes, err := base64.StdEncoding.DecodeString(n1B64)
	if err != nil {
		t.Fatalf("base64-decode n1SmMsg: %v", err)
	}
	if len(n1Bytes) < 4 {
		t.Fatalf("n1SmMsg too short (%d bytes), need at least 4-octet 5GSM header", len(n1Bytes))
	}
	if n1Bytes[0] != nas.PDGroupSessionManagement {
		t.Errorf("EPD: want 0x%02X, got 0x%02X", nas.PDGroupSessionManagement, n1Bytes[0])
	}
	if n1Bytes[1] != psi {
		t.Errorf("PSI: want %d, got %d (must echo UE's request)", psi, n1Bytes[1])
	}
	if n1Bytes[2] != pti {
		t.Errorf("PTI: want %d, got %d (must echo UE's request)", pti, n1Bytes[2])
	}
	if nas.MessageType(n1Bytes[3]) != nas.MsgTypePDUSessionModificationCommand {
		t.Errorf("message type: want 0xCB, got 0x%02X", n1Bytes[3])
	}

	// ---- n2SmInfo: must be non-empty APER-encoded modify request transfer ----
	n2B64, ok := resp["n2SmInfo"].(string)
	if !ok || n2B64 == "" {
		t.Fatal("n2SmInfo missing or empty in response")
	}
	n2Bytes, err := base64.StdEncoding.DecodeString(n2B64)
	if err != nil {
		t.Fatalf("base64-decode n2SmInfo: %v", err)
	}
	if len(n2Bytes) == 0 {
		t.Error("n2SmInfo must be non-empty (APER encoding contains at least the extension prefix bit)")
	}
}

// TestHandleUpdateSMContext_NonModificationN1SmMsgIgnored verifies that an n1SmMsg
// carrying a message type other than 0xC9 does NOT trigger the modification path
// (falls through to the N2SM GTP path, returning 200 because it has no N2SM info either).
func TestHandleUpdateSMContext_NonModificationN1SmMsgIgnored(t *testing.T) {
	s := newTestSMFServer(t)

	// A 5GSM Establishment Request (0xC1) — should NOT trigger the modification path.
	n1SmReq := []byte{nas.PDGroupSessionManagement, 0x01, 0x01, byte(nas.MsgTypePDUSessionEstablishmentRequest)}
	reqBody := map[string]interface{}{
		"n1SmMsg":      base64.StdEncoding.EncodeToString(n1SmReq),
		"pduSessionId": 1,
	}
	bodyJSON, _ := json.Marshal(reqBody)

	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/ctx-001/modify",
		strings.NewReader(string(bodyJSON)))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("smContextRef", "ctx-001")
	w := httptest.NewRecorder()

	s.handleUpdateSMContext(w, r)

	// The handler falls through to the N2SM GTP path; with no N2SM info it returns 200.
	if w.Code == http.StatusOK {
		// Check that the response body does NOT contain a modification command.
		body := w.Body.String()
		if strings.Contains(body, "n1SmMsg") {
			// Decode and ensure it is NOT a modification command.
			var resp map[string]interface{}
			_ = json.Unmarshal([]byte(body), &resp)
			if n1B64, ok := resp["n1SmMsg"].(string); ok {
				n1, _ := base64.StdEncoding.DecodeString(n1B64)
				if len(n1) >= 4 && nas.MessageType(n1[3]) == nas.MsgTypePDUSessionModificationCommand {
					t.Error("non-0xC9 n1SmMsg should NOT produce a Modification Command in response")
				}
			}
		}
	}
}

// TestHandleUpdateSMContext_ShortN1SmMsgRejectedAsModification verifies that a
// truncated (< 4 bytes) n1SmMsg is NOT treated as a modification request.
func TestHandleUpdateSMContext_ShortN1SmMsgRejectedAsModification(t *testing.T) {
	s := newTestSMFServer(t)

	truncated := []byte{nas.PDGroupSessionManagement, 0x01} // only 2 bytes
	reqBody := map[string]interface{}{
		"n1SmMsg": base64.StdEncoding.EncodeToString(truncated),
	}
	bodyJSON, _ := json.Marshal(reqBody)

	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/ctx-002/modify",
		strings.NewReader(string(bodyJSON)))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("smContextRef", "ctx-002")
	w := httptest.NewRecorder()

	s.handleUpdateSMContext(w, r)

	// Falls through — truncated message does not produce a modification command.
	body := w.Body.String()
	var resp map[string]interface{}
	_ = json.Unmarshal([]byte(body), &resp)
	if n1B64, ok := resp["n1SmMsg"].(string); ok && n1B64 != "" {
		n1, _ := base64.StdEncoding.DecodeString(n1B64)
		if len(n1) >= 4 && nas.MessageType(n1[3]) == nas.MsgTypePDUSessionModificationCommand {
			t.Error("truncated n1SmMsg should NOT produce a Modification Command")
		}
	}
}
