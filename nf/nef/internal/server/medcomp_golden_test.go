package server

// medcomp_golden_test.go - byte-identity goldens for the Npcf_PolicyAuthorization
// Create ascReqData.medComponents the NEF builds from flowInfo (REL19-3.5 slice C).
// rel17 (and no profile) = frozen legacy shape; rel19 = TS 29.514 §5.6.2.10
// MediaComponent {medCompN, medSubComps{fNum, fDescs}}.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func TestGolden_MedComponents(t *testing.T) {
	body := []byte(`{"ueIpv4Addr":"10.60.0.1","qosReference":"qos-1","afAppId":"app-1","dnn":"internet",` +
		`"flowInfo":[{"flowId":1,"flowDescriptions":["permit out ip from any to any"]},` +
		`{"flowId":2,"flowDescriptions":["permit out 17 from 1.2.3.4 to 5.6.7.8","permit in 17 from 5.6.7.8 to 1.2.3.4"]}]}`)
	cases := []struct {
		name   string
		p      func(*testing.T) *capability.Profile
		golden string
	}{
		{"noprofile", func(*testing.T) *capability.Profile { return nil }, "golden_medcomp_rel17.txt"},
		{"rel17", func(t *testing.T) *capability.Profile { return profileNamed(t, "rel17") }, "golden_medcomp_rel17.txt"},
		{"rel19", func(t *testing.T) *capability.Profile { return profileNamed(t, "rel19") }, "golden_medcomp_rel19.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcf := defaultPCF()
			srv, ts := newTestServer(t, defaultBSF(), pcf)
			srv.SetProfile(tc.p(t))
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/3gpp-as-session-with-qos/v1/af-1/subscriptions", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+mintToken(t, testScope))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			pcf.mu.Lock()
			defer pcf.mu.Unlock()
			raw, err := json.Marshal(pcf.lastCreateReq.MedComponents)
			if err != nil {
				t.Fatal(err)
			}
			checkGolden(t, tc.golden, string(raw))
		})
	}
}

// postSub posts an AsSessionWithQoS Create with the given flowInfo JSON array
// (empty = attribute absent) and returns the response and body.
func postSub(t *testing.T, prof *capability.Profile, flowInfo string) (*http.Response, []byte, *mockPCFClient) {
	t.Helper()
	body := `{"ueIpv4Addr":"10.60.0.1","qosReference":"qos-1","dnn":"internet"`
	if flowInfo != "" {
		body += `,"flowInfo":` + flowInfo
	}
	body += `}`
	pcf := defaultPCF()
	srv, ts := newTestServer(t, defaultBSF(), pcf)
	srv.SetProfile(prof)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/3gpp-as-session-with-qos/v1/af-1/subscriptions", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+mintToken(t, testScope))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, raw, pcf
}

func medCompsJSON(t *testing.T, pcf *mockPCFClient) string {
	t.Helper()
	pcf.mu.Lock()
	defer pcf.mu.Unlock()
	if pcf.lastCreateReq == nil {
		return "<no PCF call>"
	}
	raw, err := json.Marshal(pcf.lastCreateReq.MedComponents)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestMedComponents_FlowID covers fNum = AF flowId (rel19), the positional
// fallback for a missing flowId, rel19 rejections and rel17 acceptance.
func TestMedComponents_FlowID(t *testing.T) {
	d := `"flowDescriptions":["permit out ip from any to any"]`
	t.Run("rel19 fNum is flowId", func(t *testing.T) {
		resp, raw, pcf := postSub(t, profileNamed(t, "rel19"), `[{"flowId":7,`+d+`},{"flowId":9,`+d+`}]`)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status %d: %s", resp.StatusCode, raw)
		}
		got := medCompsJSON(t, pcf)
		if !strings.Contains(got, `"7":{"fNum":7`) || !strings.Contains(got, `"9":{"fNum":9`) || strings.Contains(got, `"1":{"fNum"`) {
			t.Errorf("medComponents = %s", got)
		}
	})
	t.Run("rel19 missing flowId falls back to position, no collision", func(t *testing.T) {
		resp, raw, pcf := postSub(t, profileNamed(t, "rel19"), `[{`+d+`},{"flowId":1,`+d+`}]`)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status %d: %s", resp.StatusCode, raw)
		}
		got := medCompsJSON(t, pcf)
		if !strings.Contains(got, `"1":{"fNum":1`) || !strings.Contains(got, `"2":{"fNum":2`) {
			t.Errorf("medComponents = %s", got)
		}
	})
	rejects := map[string]struct{ fi, param string }{
		"duplicate flowId":   {`[{"flowId":1,` + d + `},{"flowId":1,` + d + `}]`, "/flowInfo/1/flowId"},
		"three descriptions": {`[{"flowId":1,"flowDescriptions":["a","b","c"]}]`, "/flowInfo/0/flowDescriptions"},
	}
	for name, c := range rejects {
		t.Run("rel19 rejects "+name, func(t *testing.T) {
			resp, raw, pcf := postSub(t, profileNamed(t, "rel19"), c.fi)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d: %s", resp.StatusCode, raw)
			}
			var prob struct {
				Cause         string
				InvalidParams []struct{ Param string }
			}
			if err := json.Unmarshal(raw, &prob); err != nil {
				t.Fatal(err)
			}
			if prob.Cause != "INVALID_MSG_FORMAT" || len(prob.InvalidParams) != 1 || prob.InvalidParams[0].Param != c.param {
				t.Errorf("problem = %s", raw)
			}
			if got := medCompsJSON(t, pcf); got != "<no PCF call>" {
				t.Errorf("PCF was called: %s", got)
			}
		})
		t.Run("rel17 accepts "+name, func(t *testing.T) {
			for _, p := range []*capability.Profile{nil, profileNamed(t, "rel17")} {
				resp, raw, _ := postSub(t, p, c.fi)
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
			}
		})
	}
	t.Run("empty flowInfo sends no medComponents (rel17) / qos-only component (rel19)", func(t *testing.T) {
		for _, p := range []*capability.Profile{nil, profileNamed(t, "rel17"), profileNamed(t, "rel19")} {
			for _, fi := range []string{"", "[]"} {
				resp, raw, pcf := postSub(t, p, fi)
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				want := "null"
				if p != nil && p.Release() >= capability.Rel19 {
					// rel19 carries the qosReference in a MediaComponent
					// (REL19-3.5 slice 2), so a component without flows is sent.
					want = `{"1":{"medCompN":1,"medType":"DATA","qosReference":"qos-1"}}`
				}
				if got := medCompsJSON(t, pcf); got != want {
					t.Errorf("medComponents = %s, want %s", got, want)
				}
			}
		}
	})
}
