// Package server tests the createSMPolicy behaviour with respect to the UE IPv4
// address forwarded to the PCF (TS 29.512 §5.6.2.3 SmPolicyContextData.ipv4Address).
//
// This is the SMF-side of the BSF-001 PCF binding integration: the SMF must include
// the allocated UE IP in the PCF create body so the PCF can register the binding
// with the BSF. Ref: TS 29.521 §5.2.2.2, TS 29.512 §5.6.2.3.
package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCreateSMPolicyIncludesUEIPv4 verifies that createSMPolicy sends "ipv4Address"
// in the PCF POST body when a non-empty ueIPv4 is provided.
// Ref: TS 29.512 §5.6.2.3 (SmPolicyContextData.ipv4Address)
func TestCreateSMPolicyIncludesUEIPv4(t *testing.T) {
	s := newTestSMFServer(t)

	var receivedBody map[string]any
	mockPCF := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/sm-policies") {
			t.Errorf("unexpected PCF call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Errorf("decode PCF body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "/npcf-smpolicycontrol/v1/sm-policies/pol-001")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"smPolicyId":    "pol-001",
			"x5gcQosSource": "OPERATOR_DEFAULT",
			"qosDecs":       map[string]any{"qd-1": map[string]any{"5qi": 9}},
			"sessRules":     map[string]any{"sr-1": map[string]any{"sessAmbr": map[string]any{"uplink": "100 Mbps", "downlink": "100 Mbps"}}},
		})
	}))
	t.Cleanup(mockPCF.Close)

	s.httpClient = mockPCF.Client()
	s.cfg.Peers.PCF = strings.TrimPrefix(mockPCF.URL, "https://")

	// Call with a UE IPv4 address — must be included in the PCF request body.
	smPolID, _ := s.createSMPolicy(t.Context(), "imsi-001010000000001", "internet", "10.60.0.1",
		SliceID{SST: 1, SD: "000001"}, nil)
	if smPolID == "" {
		t.Fatal("expected smPolicyId, got empty string")
	}
	if got, ok := receivedBody["ipv4Address"]; !ok || got != "10.60.0.1" {
		t.Errorf("PCF body ipv4Address: got %v (present=%v), want 10.60.0.1", got, ok)
	}
}

// TestCreateSMPolicyOmitsIPv4WhenEmpty verifies that createSMPolicy does NOT include
// "ipv4Address" when ueIPv4 is "" (IPv6-only sessions or no IP allocated yet).
// Byte-identical behaviour with the pre-BSF-001 code path.
// Ref: TS 29.512 §5.6.2.3
func TestCreateSMPolicyOmitsIPv4WhenEmpty(t *testing.T) {
	s := newTestSMFServer(t)

	var receivedBody map[string]any
	mockPCF := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/sm-policies") {
			t.Errorf("unexpected PCF call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Errorf("decode PCF body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "/npcf-smpolicycontrol/v1/sm-policies/pol-002")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"smPolicyId":    "pol-002",
			"x5gcQosSource": "OPERATOR_DEFAULT",
			"qosDecs":       map[string]any{"qd-1": map[string]any{"5qi": 9}},
			"sessRules":     map[string]any{"sr-1": map[string]any{"sessAmbr": map[string]any{"uplink": "100 Mbps", "downlink": "100 Mbps"}}},
		})
	}))
	t.Cleanup(mockPCF.Close)

	s.httpClient = mockPCF.Client()
	s.cfg.Peers.PCF = strings.TrimPrefix(mockPCF.URL, "https://")

	// Call with empty ueIPv4 — ipv4Address must NOT appear in the PCF request body.
	smPolID, _ := s.createSMPolicy(t.Context(), "imsi-001010000000001", "ims", "",
		SliceID{SST: 1, SD: "000002"}, nil)
	if smPolID == "" {
		t.Fatal("expected smPolicyId, got empty string")
	}
	if _, present := receivedBody["ipv4Address"]; present {
		t.Errorf("PCF body: ipv4Address should be absent for empty ueIPv4, but it was present")
	}
}
