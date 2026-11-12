package server

// sdm_notify_golden_test.go - byte-identity goldens for the Nudm_SDM
// subscription/notification bodies and the generate-auth-data answer across
// release profiles (REL19-3.5 slice A). The rel17 / no-profile files were
// captured from the pre-change code and must pass UNCHANGED; the rel19 files
// pin the spec-literal shape (TS29503_Nudm_SDM.yaml SdmSubscription,
// ModificationNotification; TS29571_CommonData.yaml NotifyItem, ChangeItem;
// TS29503_Nudm_UEAU.yaml AuthenticationInfoResult). Only generated ids and
// the random AV values are masked.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

const notifySUPI = "imsi-001010000000001"

// notifySnapshot subscribes with a callback served by a local capture server,
// fires the data-change trigger with triggerBody and renders the subscribe
// response plus the notification the callback received.
func notifySnapshot(t *testing.T, p *capability.Profile, subBody, triggerBody string) string {
	t.Helper()
	got := make(chan string, 1)
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- r.Header.Get("Content-Type") + "\n" + string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cb.Close()
	s := newSDMGoldenUDM(t, p)
	subRsp := snapshot(t, s, http.MethodPost, "/nudm-sdm/v2/"+notifySUPI+"/sdm-subscriptions",
		strings.ReplaceAll(subBody, "CALLBACK", cb.URL))
	trig := snapshot(t, s, http.MethodPost, "/nudm-mgmt/v1/"+notifySUPI+"/data-change", triggerBody)
	select {
	case n := <-got:
		subRsp = strings.ReplaceAll(subRsp, cb.URL, "CALLBACK")
		return subRsp + "\n--- trigger ---\n" + trig + "\n--- notification ---\n" + subIDRE.ReplaceAllString(n, "<ID>")
	case <-time.After(5 * time.Second):
		t.Fatal("no notification received")
		return ""
	}
}

func TestGolden_SDMNotification(t *testing.T) {
	const legacySub = `{"nfInstanceId":"amf-1","callbackReference":"CALLBACK","monitoredResourceUri":"https://udm/nudm-sdm/v2/` + notifySUPI + `/am-data"}`
	const specSub = `{"nfInstanceId":"amf-1","callbackReference":"CALLBACK","monitoredResourceUris":["https://udm/nudm-sdm/v2/` + notifySUPI + `/am-data"]}`
	const change = `[{"changeType":"REPLACE","resourcePath":"/subscribedUeAmbr/uplink","originalValue":"1 Mbps","newValue":"2 Mbps"}]`

	t.Run("legacy_profiles", func(t *testing.T) {
		for pname, p := range goldenProfiles(t) {
			t.Run(pname, func(t *testing.T) {
				checkGolden(t, "golden_sdm_notify_legacy.txt", notifySnapshot(t, p, legacySub, change))
			})
			t.Run(pname+"/default_change", func(t *testing.T) {
				checkGolden(t, "golden_sdm_notify_legacy_default.txt", notifySnapshot(t, p, legacySub, ``))
			})
		}
	})
	t.Run("rel19", func(t *testing.T) {
		p := profileNamed(t, "rel19")
		t.Run("spec_subscription", func(t *testing.T) {
			checkGolden(t, "golden_sdm_notify_rel19.txt", notifySnapshot(t, p, specSub, change))
		})
		t.Run("legacy_subscription_decoded", func(t *testing.T) {
			checkGolden(t, "golden_sdm_notify_rel19_legacy_in.txt", notifySnapshot(t, p, legacySub, change))
		})
		t.Run("default_change", func(t *testing.T) {
			checkGolden(t, "golden_sdm_notify_rel19_default.txt", notifySnapshot(t, p, specSub, ``))
		})
	})
	t.Run("spec_subscription_rel17_decoded", func(t *testing.T) {
		// Consumers/producers decode both shapes whatever the profile.
		checkGolden(t, "golden_sdm_notify_rel17_spec_in.txt", notifySnapshot(t, profileNamed(t, "rel17"), specSub, change))
	})
}

func TestGolden_GenerateAuthDataProfiles(t *testing.T) {
	const body = `{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org","ausfInstanceId":"11111111-2222-3333-4444-555555555555"}`
	tests := []struct{ name, method, golden string }{
		{"5g_aka", "5G_AKA", "golden_generate_auth_data_5gaka.txt"},
		{"eap_aka_prime", "EAP_AKA_PRIME", "golden_generate_auth_data_eap.txt"},
	}
	for pname, p := range goldenProfiles(t) {
		for _, tc := range tests {
			t.Run(pname+"/"+tc.name, func(t *testing.T) {
				s := newGoldenUDM(t, tc.method)
				if p != nil {
					s.SetProfile(p)
				}
				checkGolden(t, tc.golden, generateAuthDataSnapshot(t, s, body))
			})
		}
	}
	rel19 := []struct{ name, method, golden string }{
		{"5g_aka", "5G_AKA", "golden_generate_auth_data_5gaka_rel19.txt"},
		{"eap_aka_prime", "EAP_AKA_PRIME", "golden_generate_auth_data_eap_rel19.txt"},
	}
	for _, tc := range rel19 {
		t.Run("rel19/"+tc.name, func(t *testing.T) {
			s := newGoldenUDM(t, tc.method)
			s.SetProfile(profileNamed(t, "rel19"))
			checkGolden(t, tc.golden, generateAuthDataSnapshot(t, s, body))
		})
	}
}
