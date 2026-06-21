package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
)

func postNSSAA(t *testing.T, ts string, supi string, eapPkt []byte) (*nssaaResponse, int) {
	t.Helper()
	body, _ := json.Marshal(nssaaRequest{
		SUPI:       supi,
		SNSSAI:     snssai{SST: 1, SD: "000003"},
		EAPPayload: base64.StdEncoding.EncodeToString(eapPkt),
	})
	resp, err := http.Post(ts+"/nausf-nssaa/v1/"+supi+"/authenticate",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST nssaa: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var out nssaaResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return &out, resp.StatusCode
}

func TestNSSAAAuthenticate_Success(t *testing.T) {
	ts := newTestServer(t, &mockUDM{authType: "5G_AKA"})
	defer ts.Close()

	resp, code := postNSSAA(t, ts.URL, "imsi-001010000000003",
		eap.BuildIdentityResponse(7, "alice@nssaa.example.com"))
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if resp.AuthResult != authResultSuccess {
		t.Fatalf("authResult = %q, want %q", resp.AuthResult, authResultSuccess)
	}
	pkt, _ := base64.StdEncoding.DecodeString(resp.EAPPayload)
	if c, _ := eap.Code(pkt); c != eap.CodeSuccess {
		t.Fatalf("returned EAP code = %d, want Success", c)
	}
}

func TestNSSAAAuthenticate_Failure(t *testing.T) {
	ts := newTestServer(t, &mockUDM{authType: "5G_AKA"})
	defer ts.Close()

	resp, _ := postNSSAA(t, ts.URL, "imsi-001010000000003",
		eap.BuildIdentityResponse(7, "mallory@reject.example.com"))
	if resp.AuthResult != authResultFailure {
		t.Fatalf("authResult = %q, want %q", resp.AuthResult, authResultFailure)
	}
	pkt, _ := base64.StdEncoding.DecodeString(resp.EAPPayload)
	if c, _ := eap.Code(pkt); c != eap.CodeFailure {
		t.Fatalf("returned EAP code = %d, want Failure", c)
	}
}

func TestNSSAAAuthenticate_BadPayload(t *testing.T) {
	ts := newTestServer(t, &mockUDM{authType: "5G_AKA"})
	defer ts.Close()

	body, _ := json.Marshal(nssaaRequest{SUPI: "imsi-1", EAPPayload: "not-base64!!"})
	resp, err := http.Post(ts.URL+"/nausf-nssaa/v1/imsi-1/authenticate",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
