package server

// up_activation_test.go — HTTP handler tests for Service Request UP re-activation:
// Nsmf_PDUSession_UpdateSMContext with upCnxState=ACTIVATING must rebuild the
// session's PDUSessionResourceSetupRequestTransfer (UL TEID + QoS) so the AMF
// can carry N2SM info in InitialContextSetupRequest.
// Ref: TS 23.502 §4.2.3.2 step 12, TS 29.502 §5.2.2.3.2.2

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func newActivationTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{UEIPPool: "10.60.0.0/24", UPFN3Addr: "172.30.3.100"}
	s, err := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)), nil)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	return s
}

func TestHandleUpdateSMContext_Activating(t *testing.T) {
	s := newActivationTestServer(t)

	const smContextRef = "ctx-activate-001"
	s.sessionMu.Lock()
	s.sessions[smContextRef] = &Session{
		SUPI:           "imsi-001010000000001",
		PDUSessionID:   1,
		DNN:            "internet",
		UEIP:           net.ParseIP("10.60.0.1"),
		ULTEID:         42,
		SEID:           7,
		FiveQI:         9,
		AMBRULMbps:     100,
		AMBRDLMbps:     200,
		State:          "IDLE",
		PDUSessionType: nas.PDUSessionTypeIPv4,
	}
	s.sessionMu.Unlock()

	body, _ := json.Marshal(map[string]string{"upCnxState": "ACTIVATING"})
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/"+smContextRef+"/modify",
		strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("smContextRef", smContextRef)
	w := httptest.NewRecorder()

	s.handleUpdateSMContext(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		N2SmInfo     string `json:"n2SmInfo"`
		N2SmInfoType string `json:"n2SmInfoType"`
		UpCnxState   string `json:"upCnxState"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.N2SmInfoType != "PDU_RES_SETUP_REQ" || resp.UpCnxState != "ACTIVATING" {
		t.Fatalf("wrong metadata: %+v", resp)
	}
	n2SmInfo, err := base64.StdEncoding.DecodeString(resp.N2SmInfo)
	if err != nil || len(n2SmInfo) == 0 {
		t.Fatalf("n2SmInfo missing or invalid: %v", err)
	}

	// The rebuilt transfer must APER-decode as an extensible SEQUENCE
	// ("valueExt" — see nf/smf/CLAUDE.md §6) and carry the session's stored
	// UL tunnel endpoint.
	var decoded ngapType.PDUSessionResourceSetupRequestTransfer
	if err := aper.UnmarshalWithParams(n2SmInfo, &decoded, "valueExt"); err != nil {
		t.Fatalf("rebuilt transfer does not decode: %v", err)
	}
	var sawTunnel bool
	for _, ie := range decoded.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDULNGUUPTNLInformation {
			sawTunnel = true
			tnl := ie.Value.ULNGUUPTNLInformation
			if tnl == nil || tnl.GTPTunnel == nil {
				t.Fatal("ULNGUUPTNLInformation missing GTPTunnel")
			}
			if got := net.IP(tnl.GTPTunnel.TransportLayerAddress.Value.Bytes); !got.Equal(net.ParseIP("172.30.3.100")) {
				t.Errorf("UPF N3 addr: want 172.30.3.100, got %v", got)
			}
			teidB := tnl.GTPTunnel.GTPTEID.Value
			teid := uint32(teidB[0])<<24 | uint32(teidB[1])<<16 | uint32(teidB[2])<<8 | uint32(teidB[3])
			if teid != 42 {
				t.Errorf("UL TEID: want 42, got %d", teid)
			}
		}
	}
	if !sawTunnel {
		t.Fatal("ULNGUUPTNLInformation IE not found in rebuilt transfer")
	}
}

func TestHandleUpdateSMContext_ActivatingUnknownSession(t *testing.T) {
	s := newActivationTestServer(t)

	body, _ := json.Marshal(map[string]string{"upCnxState": "ACTIVATING"})
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/ctx-missing/modify",
		strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("smContextRef", "ctx-missing")
	w := httptest.NewRecorder()

	s.handleUpdateSMContext(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 CONTEXT_NOT_FOUND, got %d: %s", w.Code, w.Body.String())
	}
}
