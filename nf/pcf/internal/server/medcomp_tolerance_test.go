package server

// medcomp_tolerance_test.go - the PCF stores ascReqData.medComponents as
// generic JSON and accepts both the legacy (fDescs at component level) and the
// TS 29.514 §5.6.2.10 (medCompN + medSubComps) shapes, whatever its profile
// (REL19-3.5 slice C).

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestCreateAcceptsBothMedComponentShapes(t *testing.T) {
	bodies := map[string]string{
		"legacy": `{"ascReqData":{"ueIpv4":"10.60.0.1","medComponents":{"1":{"medType":"DATA","fDescs":["permit out ip from any to any"]}}}}`,
		"spec":   `{"ascReqData":{"ueIpv4":"10.60.0.1","medComponents":{"1":{"medCompN":1,"medType":"DATA","medSubComps":{"1":{"fNum":1,"fDescs":["permit out ip from any to any"]}}}}}}`,
	}
	for name, body := range bodies {
		var in struct {
			AscReqData struct {
				MedComponents map[string]any `json:"medComponents"`
			} `json:"ascReqData"`
		}
		if err := json.Unmarshal([]byte(body), &in); err != nil {
			t.Fatal(err)
		}
		want := in.AscReqData.MedComponents
		for _, prof := range []string{"rel17", "rel19"} {
			t.Run(name+"/"+prof, func(t *testing.T) {
				s, _ := newFeaturePCF(t, profileNamed(t, prof), Catalogs{})
				resp, raw := post(t, s, "/npcf-policyauthorization/v1/app-sessions", body, "")
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				// The stored app session must carry the medComponents verbatim.
				id := resp.Header.Get("Location")
				id = id[strings.LastIndex(id, "/")+1:]
				s.appSessionsMu.Lock()
				stored, ok := s.appSessions[id]
				s.appSessionsMu.Unlock()
				if !ok || stored.AscReqData == nil {
					t.Fatalf("app session %q not stored", id)
				}
				if !reflect.DeepEqual(stored.AscReqData.MedComponents, want) {
					t.Errorf("stored medComponents = %v, want %v", stored.AscReqData.MedComponents, want)
				}
			})
		}
	}
}
