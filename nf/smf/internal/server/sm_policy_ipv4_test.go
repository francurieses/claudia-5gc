// Package server tests the createSMPolicy behaviour with respect to the UE IPv4
// address forwarded to the PCF (TS 29.512 §5.6.2.3 SmPolicyContextData.ipv4Address).
//
// This is the SMF-side of the BSF-001 PCF binding integration: the SMF must include
// the allocated UE IP in the PCF create body so the PCF can register the binding
// with the BSF. Ref: TS 29.521 §5.2.2.2, TS 29.512 §5.6.2.3.
package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/logging"
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
		w.Header().Set("Location", "https://"+r.Host+"/npcf-smpolicycontrol/v1/sm-policies/pol-001")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
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
	if smPolID != "pol-001" { // from Location only; the 201 body carries no id
		t.Fatalf("smPolicyId = %q, want pol-001", smPolID)
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
		w.Header().Set("Location", "/npcf-smpolicycontrol/v1/sm-policies/pol-002") // legacy relative form stays accepted
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
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
	if smPolID != "pol-002" {
		t.Fatalf("smPolicyId = %q, want pol-002", smPolID)
	}
	if _, present := receivedBody["ipv4Address"]; present {
		t.Errorf("PCF body: ipv4Address should be absent for empty ueIPv4, but it was present")
	}
}

// TestDeleteSMPolicyUsesPostDelete verifies the SMF uses the Rel-17 custom
// delete operation (POST .../delete with an SmPolicyDeleteData JSON body).
// Ref: TS 29.512 §4.2.5.2, §5.3.3.4.2
func TestDeleteSMPolicyUsesPostDelete(t *testing.T) {
	s := newTestSMFServer(t)

	var gotMethod, gotPath, gotCT, gotBody, gotCorr string
	mockPCF := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotCT = r.Method, r.URL.Path, r.Header.Get("Content-Type")
		gotCorr = r.Header.Get("X-Correlation-Id")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(mockPCF.Close)

	s.httpClient = mockPCF.Client()
	s.cfg.Peers.PCF = strings.TrimPrefix(mockPCF.URL, "https://")
	s.deleteSMPolicy(t.Context(), "pol-007")

	if gotMethod != http.MethodPost || gotPath != "/npcf-smpolicycontrol/v1/sm-policies/pol-007/delete" {
		t.Errorf("PCF call: %s %s", gotMethod, gotPath)
	}
	if gotCT != "application/json" || gotBody != "{}" {
		t.Errorf("Content-Type %q body %q, want application/json and {}", gotCT, gotBody)
	}
	if gotCorr == "" {
		t.Error("X-Correlation-Id header missing on the PCF delete")
	}

	// A correlation ID already in ctx is propagated unchanged.
	gotCorr = ""
	s.deleteSMPolicy(logging.WithCorrelationID(t.Context(), "corr-123"), "pol-008")
	if gotCorr != "corr-123" {
		t.Errorf("X-Correlation-Id = %q, want corr-123", gotCorr)
	}
}

// TestCreateSMPolicyLocationForms proves the smPolicyId is taken from an
// absolute {apiRoot} Location (TS 29.501 §4.4.1) with trailing slash / query,
// as well as from the legacy relative form.
func TestCreateSMPolicyLocationForms(t *testing.T) {
	for _, tc := range []struct{ name, loc, want string }{
		{"absolute", "https://pcf:8006/npcf-smpolicycontrol/v1/sm-policies/pol-abs", "pol-abs"},
		{"absolute trailing slash", "https://pcf:8006/npcf-smpolicycontrol/v1/sm-policies/pol-ts/", "pol-ts"},
		{"absolute with query", "https://pcf:8006/npcf-smpolicycontrol/v1/sm-policies/pol-q?x=1/2", "pol-q"},
		{"relative", "/npcf-smpolicycontrol/v1/sm-policies/pol-rel", "pol-rel"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSMFServer(t)
			mockPCF := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", tc.loc)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("{}"))
			}))
			t.Cleanup(mockPCF.Close)
			s.httpClient = mockPCF.Client()
			s.cfg.Peers.PCF = strings.TrimPrefix(mockPCF.URL, "https://")
			got, _ := s.createSMPolicy(t.Context(), "imsi-001010000000001", "internet", "",
				SliceID{SST: 1, SD: "000001"}, nil)
			if got != tc.want {
				t.Errorf("smPolicyId = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCreateSMPolicyMissingLocation proves a 201 whose Location yields no id
// (absent, wrong collection, extra segments, no id) still returns the decision
// but logs a visible Warn with cause=MISSING_LOCATION, and that deleteSMPolicy
// with no recorded id logs at Info and sends nothing.
func TestCreateSMPolicyMissingLocation(t *testing.T) {
	for _, tc := range []struct{ name, loc string }{
		{"absent", ""},
		{"wrong collection", "https://pcf:8006/npcf-policyauthorization/v1/app-sessions/x"},
		{"extra segments", "https://pcf:8006/npcf-smpolicycontrol/v1/sm-policies/a/b"},
		{"no id", "https://pcf:8006/npcf-smpolicycontrol/v1/sm-policies"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSMFServer(t)
			logs := &syncBuffer{}
			s.logger = slog.New(slog.NewJSONHandler(logs, nil))
			deletes := 0
			mockPCF := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/delete") {
					deletes++
				}
				if tc.loc != "" {
					w.Header().Set("Location", tc.loc)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"x5gcQosSource":"PCF_POLICY","qosDecs":{"q":{"5qi":7}}}`))
			}))
			t.Cleanup(mockPCF.Close)
			s.httpClient = mockPCF.Client()
			s.cfg.Peers.PCF = strings.TrimPrefix(mockPCF.URL, "https://")

			id, qos := s.createSMPolicy(t.Context(), "imsi-001010000000001", "internet", "",
				SliceID{SST: 1, SD: "000001"}, nil)
			if id != "" {
				t.Errorf("smPolicyId = %q, want empty", id)
			}
			if qos.FiveQI != 7 {
				t.Errorf("decision not applied: 5QI = %d, want 7", qos.FiveQI)
			}
			out := logs.String()
			for _, want := range []string{`"level":"WARN"`, `"result":"FAILURE"`, `"cause":"MISSING_LOCATION"`, `"interface":"N7"`} {
				if !strings.Contains(out, want) {
					t.Errorf("log lacks %s: %s", want, out)
				}
			}

			logs = &syncBuffer{}
			s.logger = slog.New(slog.NewJSONHandler(logs, nil))
			s.deleteSMPolicy(t.Context(), id)
			if deletes != 0 {
				t.Errorf("deleteSMPolicy with empty id sent %d DELETE(s)", deletes)
			}
			if !strings.Contains(logs.String(), `"level":"INFO"`) || !strings.Contains(logs.String(), "NO_ASSOCIATION") {
				t.Errorf("empty-id delete skip not logged at Info: %s", logs.String())
			}
		})
	}
}
