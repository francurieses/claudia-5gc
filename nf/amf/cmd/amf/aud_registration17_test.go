package main

// aud_registration17_test.go - AUD-registration-17: the Nudm_UECM registration
// carries the mandatory Amf3GppAccessRegistration attributes (TS 29.503
// §6.2.6.2.2), its failure rejects the registration (non-emergency) before
// Nudm_SDM_Get, the SDM subscription is created and removed.

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

type audUDM struct {
	mu          sync.Mutex
	uecmStatus  int // forced answer for a valid PUT (0 = 201)
	uecmCause   string
	amDataCalls int
	subscribed  []map[string]any
	deleted     []string
	uecmDeleted int
	regBody     map[string]any
}

func (u *audUDM) handler() http.Handler {
	mux := http.NewServeMux()
	problem := func(w http.ResponseWriter, st int, cause string) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(st)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": st, "cause": cause})
	}
	mux.HandleFunc("PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		u.mu.Lock()
		u.regBody = b
		st, cause := u.uecmStatus, u.uecmCause
		u.mu.Unlock()
		// TS 29.503 §6.2.6.2.2: deregCallbackUri, guami, ratType are mandatory.
		for _, k := range []string{"amfInstanceId", "deregCallbackUri", "guami", "ratType"} {
			if _, ok := b[k]; !ok {
				problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING")
				return
			}
		}
		if st != 0 {
			problem(w, st, cause)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("GET /nudm-sdm/v2/{supi}/am-data", func(w http.ResponseWriter, _ *http.Request) {
		u.mu.Lock()
		u.amDataCalls++
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenAMAnswer))
	})
	mux.HandleFunc("POST /nudm-sdm/v2/{supi}/sdm-subscriptions", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		u.mu.Lock()
		u.subscribed = append(u.subscribed, b)
		u.mu.Unlock()
		w.Header().Set("Location", "/nudm-sdm/v2/"+r.PathValue("supi")+"/sdm-subscriptions/sub-77")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("DELETE /nudm-sdm/v2/{supi}/sdm-subscriptions/{id}", func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.deleted = append(u.deleted, r.PathValue("id"))
		u.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access", func(w http.ResponseWriter, _ *http.Request) {
		u.mu.Lock()
		u.uecmDeleted++
		u.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func newAUD17Env(t *testing.T, withSelf bool, emergency bool) (*audUDM, *procedures.RegistrationHandler, *amfctx.UEContext) {
	t.Helper()
	u := &audUDM{}
	srv := httptest.NewTLSServer(u.handler())
	t.Cleanup(srv.Close)
	c := &HTTPUDMClient{address: strings.TrimPrefix(srv.URL, "https://"), client: srv.Client(),
		profile: testProfile(t, "rel19"), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if withSelf {
		c.SetSelf("amf-test-1", "https://amf.test:8001", "001", "01", 2, 1, 1)
	}
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01", AMFRegionID: 2, AMFSetID: 1, AMFID: 1}, nil, nil, nil)
	h := procedures.NewRegistrationHandler(mgr, nil, c, nil, "amf-test-1", "001", "01", slog.New(slog.NewTextHandler(io.Discard, nil)))
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, goldenSUPI)
	ue.RequestedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	if emergency {
		ue.RegistrationType = byte(nas.RegistrationTypeEmergency)
	}
	return u, h, ue
}

// TestAUDRegistration17_MissingMandatoryAttributesRejects: a UDM that answers 400
// without deregCallbackUri/guami/ratType makes RegisterAMF fail and Phase3 reject
// (#22) without ever calling Nudm_SDM_Get.
func TestAUDRegistration17_MissingMandatoryAttributesRejects(t *testing.T) {
	u, h, ue := newAUD17Env(t, false, false) // no SetSelf: legacy body, attributes missing
	ra, err := h.Phase3_ProcessSMCComplete(t.Context(), ue)
	var rc *procedures.ErrRejectCause
	var ue17 *procedures.UDMError
	if !errors.As(err, &rc) || ra != nil || !errors.As(err, &ue17) || ue17.Status != 400 {
		t.Fatalf("ra=%v err=%v; want ErrRejectCause wrapping UDMError 400", ra, err)
	}
	if rc.Cause != nas.CauseCongestion {
		t.Errorf("cause = %d, want #22", rc.Cause)
	}
	if u.amDataCalls != 0 {
		t.Fatalf("GetAMSubscriptionData called %d times after UECM failure", u.amDataCalls)
	}
}

// TestAUDRegistration17_FullBodyAndSubscription: with the AMF identity set the
// registration carries the mandatory attributes, SDM is read then subscribed
// (callbackReference on the AMF's own apiRoot) and the subscription is deleted
// where the AMF deregisters from the UDM.
func TestAUDRegistration17_FullBodyAndSubscription(t *testing.T) {
	u, h, ue := newAUD17Env(t, true, false)
	ra, err := h.Phase3_ProcessSMCComplete(t.Context(), ue)
	if err != nil || ra == nil {
		t.Fatalf("ra=%v err=%v", ra, err)
	}
	if u.regBody["ratType"] != "NR" || u.regBody["deregCallbackUri"] != "https://amf.test:8001/namf-callback/v1/udm-uecm/dereg-notify/"+goldenSUPI {
		t.Errorf("registration body = %v", u.regBody)
	}
	g, _ := u.regBody["guami"].(map[string]any)
	if g["amfId"] != "020041" { // region 2 | set 1 | pointer 1 = 0x02 0x00 0x41
		t.Errorf("guami = %v", g)
	}
	if u.amDataCalls != 1 || len(u.subscribed) != 1 {
		t.Fatalf("am-data calls=%d subscriptions=%d", u.amDataCalls, len(u.subscribed))
	}
	sub := u.subscribed[0]
	if sub["nfInstanceId"] != "amf-test-1" || sub["callbackReference"] != "https://amf.test:8001/namf-callback/v1/udm-sdm/modification-notify" {
		t.Errorf("subscription = %v", sub)
	}
	if uris, _ := sub["monitoredResourceUris"].([]any); len(uris) != 1 || uris[0] != "/nudm-sdm/v2/"+goldenSUPI+"/am-data" {
		t.Errorf("monitoredResourceUris = %v", sub["monitoredResourceUris"])
	}
	if ue.SDMSubscriptionID != "sub-77" {
		t.Fatalf("subscription id on UE = %q", ue.SDMSubscriptionID)
	}
	if err := h.DeregisterUECM(t.Context(), goldenSUPI); err != nil {
		t.Fatal(err)
	}
	if len(u.deleted) != 1 || u.deleted[0] != "sub-77" || ue.SDMSubscriptionID != "" {
		t.Fatalf("deleted=%v ue sub=%q", u.deleted, ue.SDMSubscriptionID)
	}
}

// TestAUDRegistration17_EmergencyIgnoresUECMFailure: TS 23.502 §4.2.2.2.2 step 14.
func TestAUDRegistration17_EmergencyIgnoresUECMFailure(t *testing.T) {
	u, h, ue := newAUD17Env(t, false, true)
	ra, err := h.Phase3_ProcessSMCComplete(t.Context(), ue)
	if err != nil || ra == nil {
		t.Fatalf("emergency registration must proceed: ra=%v err=%v", ra, err)
	}
	if u.amDataCalls != 1 {
		t.Errorf("am-data calls = %d", u.amDataCalls)
	}
}

// TestAUDRegistration17_StatusToCause drives the mapping end to end.
func TestAUDRegistration17_StatusToCause(t *testing.T) {
	tests := []struct {
		status int
		cause  string
		want   nas.Cause5GMM
	}{
		{403, "ROAMING_NOT_ALLOWED", nas.CausePLMNNotAllowed},
		{404, "USER_NOT_FOUND", nas.Cause5GSServicesNotAllowed},
		{503, "", nas.CauseCongestion},
	}
	for _, tc := range tests {
		t.Run(tc.cause+http.StatusText(tc.status), func(t *testing.T) {
			u, h, ue := newAUD17Env(t, true, false)
			u.uecmStatus, u.uecmCause = tc.status, tc.cause
			_, err := h.Phase3_ProcessSMCComplete(t.Context(), ue)
			var rc *procedures.ErrRejectCause
			if !errors.As(err, &rc) || rc.Cause != tc.want {
				t.Fatalf("err = %v, want cause %d", err, tc.want)
			}
			if u.amDataCalls != 0 {
				t.Fatal("am-data read after UECM failure")
			}
		})
	}
}

// TestAUDRegistration17_RejectAfterUECMRollsBackUDM: a Phase3 reject after the UECM
// registration and SDM subscription (no network slices) deletes the subscription
// and deregisters the AMF from the UDM, so nothing leaks (TS 23.502 §4.2.2.2.2).
func TestAUDRegistration17_RejectAfterUECMRollsBackUDM(t *testing.T) {
	u, h, ue := newAUD17Env(t, true, false)
	ue.RequestedNSSAI = []amfctx.SNSSAISubscribed{{SST: 99, SD: "ABCDEF"}} // not subscribed
	ra, err := h.Phase3_ProcessSMCComplete(t.Context(), ue)
	var nn *procedures.NoNetworkSlicesError
	if ra != nil || !errors.As(err, &nn) {
		t.Fatalf("ra=%v err=%v; want NoNetworkSlicesError", ra, err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.deleted) != 1 || u.deleted[0] != "sub-77" || u.uecmDeleted != 1 || ue.SDMSubscriptionID != "" {
		t.Fatalf("deleted=%v uecmDeleted=%d ue sub=%q", u.deleted, u.uecmDeleted, ue.SDMSubscriptionID)
	}
}
