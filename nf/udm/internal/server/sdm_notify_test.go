package server

// sdm_notify_test.go - unit tests for the Rel-19 NotifyItem construction and
// the Rel-19 SdmSubscription mandatory-attribute checks (REL19-3.5 slice A).

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestToNotifyItems(t *testing.T) {
	const supi = "imsi-001010000000001"
	const root = "https://udm.example:8443"
	amData := "https://udm.example/nudm-sdm/v2/" + supi + "/am-data"
	smData := "https://udm.example/nudm-sdm/v2/" + supi + "/sm-data"
	tests := []struct {
		name      string
		monitored []string
		in        []triggerChange
		wantJSON  string
		wantErr   string
	}{
		{
			name:      "json pointer maps to matching monitored uri",
			monitored: []string{smData, amData},
			in:        []triggerChange{{legacyChangeItem: legacyChangeItem{ChangeType: "replace", ResourcePath: "/a/b", NewValue: 1}}},
			wantJSON:  `[{"resourceId":"` + amData + `","changes":[{"op":"REPLACE","path":"/a/b","newValue":1}]}]`,
		},
		{
			name:      "relative resource uri path matches second monitored uri",
			monitored: []string{amData, smData},
			in:        []triggerChange{{legacyChangeItem: legacyChangeItem{ChangeType: "REMOVE", ResourcePath: "/nudm-sdm/v2/" + supi + "/sm-data", OriginalValue: "x"}}},
			wantJSON:  `[{"resourceId":"` + smData + `","changes":[{"op":"REMOVE","path":"","origValue":"x"}]}]`,
		},
		{
			name:      "absolute resource uri path matched on path component",
			monitored: []string{amData},
			in:        []triggerChange{{legacyChangeItem: legacyChangeItem{ChangeType: "UPDATE", ResourcePath: "https://other.example/nudm-sdm/v2/" + supi + "/am-data/", NewValue: "n"}}},
			wantJSON:  `[{"resourceId":"` + amData + `","changes":[{"op":"REPLACE","path":"","newValue":"n"}]}]`,
		},
		{
			name:      "no match falls back to apiRoot plus path, ADD without value emits null",
			monitored: []string{smData},
			in:        []triggerChange{{legacyChangeItem: legacyChangeItem{ChangeType: "CREATE", ResourcePath: "/nudm-sdm/v2/" + supi + "/am-data"}}},
			wantJSON:  `[{"resourceId":"` + root + `/nudm-sdm/v2/` + supi + `/am-data","changes":[{"op":"ADD","path":"","newValue":null}]}]`,
		},
		{
			name:      "move carries from",
			monitored: []string{amData},
			in:        []triggerChange{{legacyChangeItem: legacyChangeItem{ChangeType: "MOVE", ResourcePath: "/b"}, From: "/a"}},
			wantJSON:  `[{"resourceId":"` + amData + `","changes":[{"op":"MOVE","path":"/b","from":"/a"}]}]`,
		},
		{
			name:    "move without from rejected",
			in:      []triggerChange{{legacyChangeItem: legacyChangeItem{ChangeType: "MOVE", ResourcePath: "/b"}}},
			wantErr: "requires from",
		},
		{
			name:    "unknown op rejected",
			in:      []triggerChange{{legacyChangeItem: legacyChangeItem{ChangeType: "COPY", ResourcePath: "/b"}}},
			wantErr: "unknown changeType",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := toNotifyItems(supi, root, tc.monitored, tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(got)
			if string(b) != tc.wantJSON {
				t.Fatalf("got  %s\nwant %s", b, tc.wantJSON)
			}
		})
	}
}

func TestSDMSubscribeRel19MandatoryAttributes(t *testing.T) {
	const target = "/nudm-sdm/v2/" + notifySUPI + "/sdm-subscriptions"
	tests := []struct {
		name, profile, body string
		wantStatus          int
		wantParams          []string
	}{
		{"rel19 no nfInstanceId", "rel19", `{"callbackReference":"https://a/cb","monitoredResourceUris":["https://u/x"]}`, 400, []string{"/nfInstanceId"}},
		{"rel19 no monitoredResourceUris", "rel19", `{"nfInstanceId":"amf-1","callbackReference":"https://a/cb"}`, 400, []string{"/monitoredResourceUris"}},
		{"rel19 neither", "rel19", `{"callbackReference":"https://a/cb"}`, 400, []string{"/nfInstanceId", "/monitoredResourceUris"}},
		{"rel19 complete", "rel19", `{"nfInstanceId":"amf-1","callbackReference":"https://a/cb","monitoredResourceUris":["https://u/x"]}`, 201, nil},
		{"rel17 unchanged", "rel17", `{"callbackReference":"https://a/cb"}`, 201, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSDMGoldenUDM(t, profileNamed(t, tc.profile))
			rsp := snapshot(t, s, http.MethodPost, target, tc.body)
			if !strings.HasPrefix(rsp, "status: "+http.StatusText(tc.wantStatus)) {
				t.Fatalf("response %q, want status %d", rsp, tc.wantStatus)
			}
			if tc.wantStatus != 400 {
				return
			}
			body := rsp[strings.Index(rsp, "{"):]
			var pd struct {
				Cause         string              `json:"cause"`
				InvalidParams []map[string]string `json:"invalidParams"`
			}
			if err := json.Unmarshal([]byte(body), &pd); err != nil {
				t.Fatal(err)
			}
			if pd.Cause != "MANDATORY_IE_MISSING" || len(pd.InvalidParams) != len(tc.wantParams) {
				t.Fatalf("problem %+v, want params %v", pd, tc.wantParams)
			}
			for i, w := range tc.wantParams {
				if pd.InvalidParams[i]["param"] != w {
					t.Fatalf("param[%d] = %q, want %q", i, pd.InvalidParams[i]["param"], w)
				}
			}
		})
	}
}

func TestDataChangeTriggerInvalidOp(t *testing.T) {
	const bad = `[{"changeType":"COPY","resourcePath":"/a"}]`
	const target = "/nudm-mgmt/v1/" + notifySUPI + "/data-change"
	for _, tc := range []struct {
		profile string
		want    string
	}{{"rel19", "status: Bad Request"}, {"rel17", "status: No Content"}} {
		t.Run(tc.profile, func(t *testing.T) {
			s := newSDMGoldenUDM(t, profileNamed(t, tc.profile))
			if rsp := snapshot(t, s, http.MethodPost, target, bad); !strings.HasPrefix(rsp, tc.want) {
				t.Fatalf("response %q, want prefix %q", rsp, tc.want)
			}
		})
	}
}
