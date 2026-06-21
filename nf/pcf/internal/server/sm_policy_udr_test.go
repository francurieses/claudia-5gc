package server

// sm_policy_udr_test.go — PCF reads/writes SM policy data through Nudr_DR.
// Ref: UDR-001, TS 29.504 §5.2.13 / TS 29.519 §5.6.2.4.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/types"
)

// fakeUDR is an in-memory UDRClient capturing the last write and serving a
// pre-seeded SM policy document.
type fakeUDR struct {
	smData   map[string]*types.SmPolicyData
	lastPut  *types.SmPolicyData
	putCalls int
}

func newFakeUDR() *fakeUDR { return &fakeUDR{smData: map[string]*types.SmPolicyData{}} }

func (f *fakeUDR) GetPolicySubscription(_ context.Context, _ string) (*types.PolicySubscription, error) {
	return nil, nil
}
func (f *fakeUDR) GetSmPolicyData(_ context.Context, supi string) (*types.SmPolicyData, error) {
	return f.smData[supi], nil
}
func (f *fakeUDR) PutSmPolicyData(_ context.Context, data *types.SmPolicyData) error {
	f.putCalls++
	f.lastPut = data
	f.smData[data.SUPI] = data
	return nil
}

// TestSmPolicyCreateReadsUDR verifies the PCF sources the authorized 5QI from
// UDR SM policy data (qos_source=UDR_POLICY_DATA) when no in-memory override
// exists, and that UDR data beats the UDM subscription default.
func TestSmPolicyCreateReadsUDR(t *testing.T) {
	s := newTestPCF(t)
	udr := newFakeUDR()
	udr.smData["imsi-001010000000001"] = &types.SmPolicyData{
		SUPI: "imsi-001010000000001",
		SmPolicySnssaiData: map[string]types.SmPolicySnssaiData{
			"0": {SmPolicyDnnData: map[string]types.SmPolicyDnnData{
				"internet": {DNN: "internet", FiveQI: 5},
			}},
		},
	}
	s.WithUDRClient(udr)

	// subsDefQos says 6, but UDR policy data (5) is authoritative and wins.
	resp := createSmPolicy(t, s,
		`{"supi":"imsi-001010000000001","dnn":"internet","subsDefQos":{"5qi":6}}`)
	if got := extract5QI(t, resp); got != 5 {
		t.Errorf("5qi: got %d want 5 (UDR policy data)", got)
	}
	if src, _ := resp["x5gcQosSource"].(string); src != "UDR_POLICY_DATA" {
		t.Errorf("qos_source: got %q want UDR_POLICY_DATA", src)
	}
}

// TestSmPolicyOverrideBeatsUDR verifies an in-memory override still wins over
// UDR SM policy data (and the UDR is not consulted when an override matches).
func TestSmPolicyOverrideBeatsUDR(t *testing.T) {
	s := newTestPCF(t)
	udr := newFakeUDR()
	udr.smData["imsi-001010000000001"] = &types.SmPolicyData{
		SUPI: "imsi-001010000000001",
		SmPolicySnssaiData: map[string]types.SmPolicySnssaiData{
			"0": {SmPolicyDnnData: map[string]types.SmPolicyDnnData{
				"internet": {DNN: "internet", FiveQI: 5},
			}},
		},
	}
	s.WithUDRClient(udr)
	s.smPolicyOverrides["imsi-001010000000001"] = SMPolicyOverride{FiveQI: 3}

	resp := createSmPolicy(t, s, `{"supi":"imsi-001010000000001","dnn":"internet"}`)
	if got := extract5QI(t, resp); got != 3 {
		t.Errorf("5qi: got %d want 3 (override wins over UDR)", got)
	}
	if src, _ := resp["x5gcQosSource"].(string); src != "PCF_OVERRIDE" {
		t.Errorf("qos_source: got %q want PCF_OVERRIDE", src)
	}
}

// TestSmPolicyCreateNoUDRClientUnchanged verifies the decision is the UDM
// subscription default when no UDR client is wired (zero regression).
func TestSmPolicyCreateNoUDRClientUnchanged(t *testing.T) {
	s := newTestPCF(t) // no WithUDRClient
	resp := createSmPolicy(t, s,
		`{"supi":"imsi-001010000000001","dnn":"internet","subsDefQos":{"5qi":6}}`)
	if got := extract5QI(t, resp); got != 6 {
		t.Errorf("5qi: got %d want 6 (subscription default)", got)
	}
	if src, _ := resp["x5gcQosSource"].(string); src != "UDM_SUBSCRIPTION" {
		t.Errorf("qos_source: got %q want UDM_SUBSCRIPTION", src)
	}
}

// TestSetQoSOverrideWritesThroughUDR verifies the override mgmt API persists the
// override to the UDR via Nudr_DR (PutSmPolicyData), keyed under the DNN.
func TestSetQoSOverrideWritesThroughUDR(t *testing.T) {
	s := newTestPCF(t)
	udr := newFakeUDR()
	s.WithUDRClient(udr)

	r := httptest.NewRequest(http.MethodPut,
		"/pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override",
		strings.NewReader(`{"5qi":2,"dnn":"ims","ambr_downlink":"50 Mbps"}`))
	r.SetPathValue("supi", "imsi-001010000000001")
	w := httptest.NewRecorder()
	s.handleSetQoSOverride(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("set override: got %d: %s", w.Code, w.Body.String())
	}
	if udr.putCalls != 1 {
		t.Fatalf("expected 1 UDR write, got %d", udr.putCalls)
	}
	d, ok := resolveSmPolicyDnnData(udr.lastPut, "ims")
	if !ok || d.FiveQI != 2 || d.AMBRDownlink != "50 Mbps" {
		t.Errorf("persisted UDR data mismatch: %+v (ok=%v)", d, ok)
	}

	// Round-trip: a fresh PCF (no in-memory override) reads the persisted policy.
	fresh := newTestPCF(t)
	fresh.WithUDRClient(udr)
	resp := createSmPolicy(t, fresh, `{"supi":"imsi-001010000000001","dnn":"ims"}`)
	if got := extract5QI(t, resp); got != 2 {
		t.Errorf("round-trip 5qi: got %d want 2", got)
	}
	if src, _ := resp["x5gcQosSource"].(string); src != "UDR_POLICY_DATA" {
		t.Errorf("round-trip qos_source: got %q want UDR_POLICY_DATA", src)
	}
}

// TestWriteThroughPreservesDirectSlices verifies the override write-through is
// read-modify-write: it manages only the PCF bucket and leaves a directly
// provisioned per-S-NSSAI slice intact (no clobber).
func TestWriteThroughPreservesDirectSlices(t *testing.T) {
	s := newTestPCF(t)
	udr := newFakeUDR()
	// Directly provisioned slice (e.g. operator-provisioned, not via PCF).
	udr.smData["imsi-001010000000001"] = &types.SmPolicyData{
		SUPI: "imsi-001010000000001",
		SmPolicySnssaiData: map[string]types.SmPolicySnssaiData{
			"1-000001": {SmPolicyDnnData: map[string]types.SmPolicyDnnData{
				"internet": {DNN: "internet", FiveQI: 5},
			}},
		},
	}
	s.WithUDRClient(udr)

	r := httptest.NewRequest(http.MethodPut,
		"/pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override",
		strings.NewReader(`{"5qi":1,"dnn":"ims"}`))
	r.SetPathValue("supi", "imsi-001010000000001")
	s.handleSetQoSOverride(httptest.NewRecorder(), r)

	got := udr.smData["imsi-001010000000001"]
	if d := got.SmPolicySnssaiData["1-000001"].SmPolicyDnnData["internet"]; d.FiveQI != 5 {
		t.Errorf("direct slice clobbered: internet 5qi=%d want 5", d.FiveQI)
	}
	if d := got.SmPolicySnssaiData["0"].SmPolicyDnnData["ims"]; d.FiveQI != 1 {
		t.Errorf("override not persisted: ims 5qi=%d want 1", d.FiveQI)
	}

	// Deleting the override removes only the PCF bucket; direct slice survives.
	rd := httptest.NewRequest(http.MethodDelete,
		"/pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override?dnn=ims", nil)
	rd.SetPathValue("supi", "imsi-001010000000001")
	s.handleDeleteQoSOverride(httptest.NewRecorder(), rd)
	got = udr.smData["imsi-001010000000001"]
	if _, ok := got.SmPolicySnssaiData["0"]; ok {
		t.Error("PCF bucket should be removed after delete")
	}
	if d := got.SmPolicySnssaiData["1-000001"].SmPolicyDnnData["internet"]; d.FiveQI != 5 {
		t.Errorf("direct slice lost on delete: internet 5qi=%d want 5", d.FiveQI)
	}
}

// TestResolveSmPolicyDnnData covers exact-DNN, subscriber-wide, and miss cases.
func TestResolveSmPolicyDnnData(t *testing.T) {
	data := &types.SmPolicyData{SmPolicySnssaiData: map[string]types.SmPolicySnssaiData{
		"0": {SmPolicyDnnData: map[string]types.SmPolicyDnnData{
			"internet": {DNN: "internet", FiveQI: 7},
			"":         {FiveQI: 9}, // subscriber-wide
		}},
	}}
	if d, ok := resolveSmPolicyDnnData(data, "internet"); !ok || d.FiveQI != 7 {
		t.Errorf("exact dnn: %+v ok=%v", d, ok)
	}
	if d, ok := resolveSmPolicyDnnData(data, "other"); !ok || d.FiveQI != 9 {
		t.Errorf("wide fallback: %+v ok=%v", d, ok)
	}
	if _, ok := resolveSmPolicyDnnData(nil, "internet"); ok {
		t.Error("nil data should not resolve")
	}
}
