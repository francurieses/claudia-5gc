package server

// qosref_rel19_test.go - REL19-3.5 slice 2: under rel19 the AF qosReference
// travels as MediaComponent.qosReference (TS 29.514 §5.6.2.10), not as the
// project member ascReqData.qosReference, and the AsSessionWithQoS
// representation carries self instead of subscriptionId/scsAsId (TS 29.122).
// The rel17 bytes are pinned by testdata/golden_ascreqdata_rel17.txt (via
// TestGolden_AscReqData_*), golden_create_201.txt and golden_get_200.txt.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func TestAscReqData_Rel19QosReferenceInMediaComponent(t *testing.T) {
	raw, _ := captureRawAscReq(t, profileNamed(t, "rel19"))
	var body struct {
		AscReqData map[string]json.RawMessage `json:"ascReqData"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	if _, ok := body.AscReqData["qosReference"]; ok {
		t.Errorf("rel19 ascReqData must not carry a top-level qosReference: %s", raw)
	}
	var mc map[string]map[string]any
	if err := json.Unmarshal(body.AscReqData["medComponents"], &mc); err != nil {
		t.Fatal(err)
	}
	if mc["1"]["qosReference"] != "qos-1" {
		t.Errorf("medComponents = %s", body.AscReqData["medComponents"])
	}
}

func TestAscReqData_DecodesBothShapes(t *testing.T) {
	for name, in := range map[string]string{
		"legacy": `{"aspId":"a","qosReference":"q1"}`,
		"spec":   `{"aspId":"a","medComponents":{"1":{"medCompN":1,"qosReference":"q1"}}}`,
	} {
		var a AppSessionContextReqData
		if err := json.Unmarshal([]byte(in), &a); err != nil || a.QosReference != "q1" || a.AspId != "a" {
			t.Errorf("%s: %+v err=%v", name, a, err)
		}
	}
}

func TestSubscription_Rel19RepresentationUsesSelf(t *testing.T) {
	resp, raw, _ := postSub(t, profileNamed(t, "rel19"), "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["subscriptionId"]; ok {
		t.Errorf("rel19 must not carry subscriptionId: %s", raw)
	}
	if _, ok := m["scsAsId"]; ok {
		t.Errorf("rel19 must not carry scsAsId: %s", raw)
	}
	self, _ := m["self"].(string)
	if !strings.Contains(self, "/3gpp-as-session-with-qos/v1/af-1/subscriptions/") || self != resp.Header.Get("Location") {
		t.Errorf("self = %q, Location = %q", self, resp.Header.Get("Location"))
	}
	// the representation decodes back into the record fields
	var sub AsSessionWithQoSSubscription
	if err := json.Unmarshal(raw, &sub); err != nil || sub.ScsAsId != "af-1" || sub.SubscriptionID == "" {
		t.Errorf("decode: %+v err=%v", sub, err)
	}
}

func TestSubscription_LegacyRepresentationHasNoSelf(t *testing.T) {
	for _, p := range []*capability.Profile{nil, profileNamed(t, "rel17")} {
		resp, raw, _ := postSub(t, p, "")
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status %d: %s", resp.StatusCode, raw)
		}
		if strings.Contains(string(raw), `"self"`) || !strings.HasPrefix(string(raw), `{"subscriptionId":"`) {
			t.Errorf("legacy body = %s", raw)
		}
	}
}

// TestAscReqData_Rel19OffersAuthorizationWithRequiredQoS: MediaComponent.qosReference
// is gated by Npcf_PolicyAuthorization feature 17 (bit 16, TS 29.514 §5.8), so
// the rel19 request must offer it in ascReqData.suppFeat; rel17 sends no suppFeat.
func TestAscReqData_Rel19OffersAuthorizationWithRequiredQoS(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *capability.Profile
		want string
	}{
		{"rel19", profileNamed(t, "rel19"), "2010000"},
		{"rel17", profileNamed(t, "rel17"), ""},
		{"noprofile", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := captureRawAscReq(t, tc.p)
			var body struct {
				AscReqData struct {
					SuppFeat string `json:"suppFeat"`
				} `json:"ascReqData"`
			}
			if err := json.Unmarshal([]byte(raw), &body); err != nil {
				t.Fatalf("%v: %s", err, raw)
			}
			if body.AscReqData.SuppFeat != tc.want {
				t.Errorf("suppFeat = %q, want %q", body.AscReqData.SuppFeat, tc.want)
			}
		})
	}
}

// TestAscReqData_RoundTripKeepsShape: decode then marshal never flips the wire
// shape (the shape is explicit, not derived from QosReference != "").
func TestAscReqData_RoundTripKeepsShape(t *testing.T) {
	for name, in := range map[string]string{
		"legacy": `{"aspId":"a","qosReference":"q1","dnn":"internet"}`,
		"spec":   `{"aspId":"a","dnn":"internet","medComponents":{"1":{"medCompN":1,"qosReference":"q1"}}}`,
	} {
		var a AppSessionContextReqData
		if err := json.Unmarshal([]byte(in), &a); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(out) != in {
			t.Errorf("%s: round trip\n got %s\nwant %s", name, out, in)
		}
	}
}
