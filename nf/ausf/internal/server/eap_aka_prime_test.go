package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/aka"
	"github.com/francurieses/claudia-5gc/shared/crypto/eapaka"
)

// testHEAVInput is a fixed subscriber credential set for deterministic AVs.
var testHEAVInput = aka.HEAVInput{
	SUPI: "imsi-001010000000099",
	K:    [16]byte{0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc},
	OPc:  [16]byte{0xe8, 0xed, 0x28, 0x9d, 0xeb, 0xa9, 0x52, 0xe4, 0x28, 0x3b, 0x54, 0xe8, 0x8e, 0x61, 0x83, 0xca},
	AMF:  [2]byte{0x80, 0x00},
	SQN:  [6]byte{0, 0, 0, 0, 0, 0x21},
}

const testSNName = "5G:mnc001.mcc001.3gppnetwork.org"

// mockUDM implements UDMClient. For EAP it remembers the generated AV so the
// test can act as the UE (which knows the same secret material).
type mockUDM struct {
	authType string
	lastAV   *aka.EAPAKAPrimeAV
}

func (m *mockUDM) GenerateAuthData(_ context.Context, supi string, _ *UDMAuthDataRequest) (*UDMAuthDataResponse, error) {
	if m.authType == "5G_AKA" {
		heav, err := aka.GenerateFull(testHEAVInput, testSNName)
		if err != nil {
			return nil, err
		}
		return &UDMAuthDataResponse{
			AuthType: "5G_AKA",
			Rand:     hex.EncodeToString(heav.RAND[:]),
			Autn:     hex.EncodeToString(heav.AUTN[:]),
			XresStar: hex.EncodeToString(heav.XRESStar),
			Kausf:    hex.EncodeToString(heav.KAUSF),
			Supi:     supi,
		}, nil
	}
	av, err := aka.GenerateEAPAKAPrime(testHEAVInput, testSNName)
	if err != nil {
		return nil, err
	}
	m.lastAV = av
	return &UDMAuthDataResponse{
		AuthType: "EAP_AKA_PRIME",
		Rand:     hex.EncodeToString(av.RAND[:]),
		Autn:     hex.EncodeToString(av.AUTN[:]),
		Xres:     hex.EncodeToString(av.XRES[:]),
		CkPrime:  hex.EncodeToString(av.CKPrime[:]),
		IkPrime:  hex.EncodeToString(av.IKPrime[:]),
		Supi:     supi,
	}, nil
}

func newTestServer(t *testing.T, udm UDMClient) *httptest.Server {
	t.Helper()
	srv, err := New(Config{ServingNetworkName: testSNName}, udm, aka.NewStore(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return httptest.NewServer(srv.Handler())
}

// initEAP performs the POST init leg and returns the eap-session href and the
// EAP-Request challenge identifier.
func initEAP(t *testing.T, ts *httptest.Server, supi string) (href string, identifier byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"supiOrSuci": supi, "servingNetworkName": testSNName})
	resp, err := http.Post(ts.URL+"/nausf-auth/v1/ue-authentications", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("init POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("init status: got %d want 201", resp.StatusCode)
	}
	var out struct {
		AuthType  string `json:"authType"`
		FiveGAuth struct {
			EapPayload string `json:"eapPayload"`
		} `json:"5gAuthData"`
		Links struct {
			EapSession struct {
				Href string `json:"href"`
			} `json:"eap-session"`
		} `json:"_links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("init decode: %v", err)
	}
	if out.AuthType != "EAP_AKA_PRIME" {
		t.Fatalf("authType: got %q want EAP_AKA_PRIME", out.AuthType)
	}
	if out.Links.EapSession.Href == "" {
		t.Fatal("missing eap-session link")
	}
	chal, err := base64.StdEncoding.DecodeString(out.FiveGAuth.EapPayload)
	if err != nil || len(chal) < 2 {
		t.Fatalf("bad challenge payload: %v", err)
	}
	return out.Links.EapSession.Href, chal[1]
}

// putEAPResponse submits an EAP-Response and returns the decoded result.
func putEAPResponse(t *testing.T, ts *httptest.Server, href string, eapResp []byte) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"eapPayload": base64.StdEncoding.EncodeToString(eapResp)})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+href, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("eap-session PUT: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestEAPAKAPrimeRoundTripSuccess(t *testing.T) {
	udm := &mockUDM{authType: "EAP_AKA_PRIME"}
	ts := newTestServer(t, udm)
	defer ts.Close()

	href, id := initEAP(t, ts, "imsi-001010000000099")

	// UE side: derive the same keys and build a correct EAP-Response.
	keys := eapaka.DeriveKeys(udm.lastAV.CKPrime, udm.lastAV.IKPrime, "imsi-001010000000099")
	eapResp := eapaka.BuildResponse(id, udm.lastAV.XRES[:], keys.KAut)

	status, out := putEAPResponse(t, ts, href, eapResp)
	if status != http.StatusOK {
		t.Fatalf("eap-session status: got %d want 200", status)
	}
	if out["authResult"] != "AUTHENTICATION_SUCCESS" {
		t.Errorf("authResult: got %v want AUTHENTICATION_SUCCESS", out["authResult"])
	}
	if ks, _ := out["kSeaf"].(string); len(ks) != 64 {
		t.Errorf("kSeaf: got %q (want 32-byte hex)", ks)
	}
	if out["supi"] != "imsi-001010000000099" {
		t.Errorf("supi: got %v", out["supi"])
	}
}

func TestEAPAKAPrimeBadMAC(t *testing.T) {
	udm := &mockUDM{authType: "EAP_AKA_PRIME"}
	ts := newTestServer(t, udm)
	defer ts.Close()

	href, id := initEAP(t, ts, "imsi-001010000000099")

	// Wrong K_aut → AT_MAC will not verify.
	wrongKAut := make([]byte, 32)
	eapResp := eapaka.BuildResponse(id, udm.lastAV.XRES[:], wrongKAut)

	status, out := putEAPResponse(t, ts, href, eapResp)
	if status != http.StatusOK {
		t.Fatalf("status: got %d want 200", status)
	}
	if out["authResult"] != "AUTHENTICATION_FAILURE" {
		t.Errorf("authResult: got %v want AUTHENTICATION_FAILURE", out["authResult"])
	}
	if _, ok := out["kSeaf"]; ok {
		t.Error("kSeaf must not be present on failure")
	}
}

func TestEAPAKAPrimeBadRES(t *testing.T) {
	udm := &mockUDM{authType: "EAP_AKA_PRIME"}
	ts := newTestServer(t, udm)
	defer ts.Close()

	href, id := initEAP(t, ts, "imsi-001010000000099")

	// Correct MAC key but wrong RES.
	keys := eapaka.DeriveKeys(udm.lastAV.CKPrime, udm.lastAV.IKPrime, "imsi-001010000000099")
	badRES := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	eapResp := eapaka.BuildResponse(id, badRES, keys.KAut)

	status, out := putEAPResponse(t, ts, href, eapResp)
	if status != http.StatusOK {
		t.Fatalf("status: got %d want 200", status)
	}
	if out["authResult"] != "AUTHENTICATION_FAILURE" {
		t.Errorf("authResult: got %v want AUTHENTICATION_FAILURE", out["authResult"])
	}
}

func TestEAPAKAPrimeUnknownContext(t *testing.T) {
	ts := newTestServer(t, &mockUDM{authType: "EAP_AKA_PRIME"})
	defer ts.Close()

	status, out := putEAPResponse(t, ts,
		"/nausf-auth/v1/ue-authentications/does-not-exist/eap-session", eapaka.BuildSuccess(1))
	if status != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", status)
	}
	if out["cause"] != "CONTEXT_NOT_FOUND" {
		t.Errorf("cause: got %v want CONTEXT_NOT_FOUND", out["cause"])
	}
}

func TestInitAuth5GAKAUnaffected(t *testing.T) {
	ts := newTestServer(t, &mockUDM{authType: "5G_AKA"})
	defer ts.Close()

	body, _ := json.Marshal(map[string]string{"supiOrSuci": "imsi-001010000000001", "servingNetworkName": testSNName})
	resp, err := http.Post(ts.URL+"/nausf-auth/v1/ue-authentications", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("init POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d want 201", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["authType"] != "5G_AKA" {
		t.Errorf("authType: got %v want 5G_AKA", out["authType"])
	}
}
