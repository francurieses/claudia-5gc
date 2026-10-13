package ue

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
)

const listJSON = `[
 {"supi":"imsi-001010000000001","guti":"mcc=001 mnc=01 amf=01 set=1 id=01 tmsi=00000001","gmm_state":"5GMM-REGISTERED","cm_state":"CM-CONNECTED"},
 {"supi":"imsi-001010000000002","guti":"mcc=001 mnc=01 amf=01 set=1 id=01 tmsi=00000002","gmm_state":"5GMM-REGISTERED","cm_state":"CM-IDLE"},
 {"supi":"imsi-001010000000003","guti":"","gmm_state":"5GMM-DEREGISTERED","cm_state":"CM-IDLE"}
]`

func amfServer(t *testing.T) *clients.AMF {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/amf/v1/ue-contexts":
			_, _ = w.Write([]byte(listJSON))
		case "/amf/v1/ue-contexts/imsi-001010000000002":
			_, _ = w.Write([]byte(`{"supi":"imsi-001010000000002","gmm_state":"REGISTERED"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return clients.NewAMF(srv.URL, http.DefaultClient)
}

func TestListFiltersByGMMAndCMState(t *testing.T) {
	tool := listTool{amfServer(t)}
	out, err := tool.Invoke(context.Background(), json.RawMessage(`{"gmm_state":"5GMM-REGISTERED","cm_state":"CM-IDLE"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	m := out.(map[string]any)
	if m["count"] != 1 {
		t.Fatalf("count: got %v, want 1", m["count"])
	}
	raw, _ := json.Marshal(m["ue_contexts"])
	if !strings.Contains(string(raw), "imsi-001010000000002") {
		t.Errorf("wrong UE kept: %s", raw)
	}
}

// TestListFilterAcceptsBareAndPrefixedNames: the AMF sends 5GMM-REGISTERED / CM-IDLE;
// the filters accept both forms, case-insensitively.
func TestListFilterAcceptsBareAndPrefixedNames(t *testing.T) {
	tool := listTool{amfServer(t)}
	cases := []struct {
		args string
		want int
	}{
		{`{"gmm_state":"REGISTERED"}`, 2},
		{`{"gmm_state":"5GMM-REGISTERED"}`, 2},
		{`{"gmm_state":"5gmm-deregistered"}`, 1},
		{`{"cm_state":"IDLE"}`, 2},
		{`{"cm_state":"CM-IDLE"}`, 2},
		{`{"cm_state":"cm-connected"}`, 1},
		{`{"gmm_state":"5GMM-REGISTERED","cm_state":"CONNECTED"}`, 1},
		{`{"gmm_state":"BOGUS"}`, 0},
	}
	for _, c := range cases {
		out, err := tool.Invoke(context.Background(), json.RawMessage(c.args))
		if err != nil {
			t.Fatalf("%s: %v", c.args, err)
		}
		if got := out.(map[string]any)["count"]; got != c.want {
			t.Errorf("%s: count = %v, want %d", c.args, got, c.want)
		}
	}
}

func TestListWithoutFiltersReturnsAll(t *testing.T) {
	out, err := listTool{amfServer(t)}.Invoke(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if out.(map[string]any)["count"] != 3 {
		t.Errorf("count: %v", out.(map[string]any)["count"])
	}
}

func TestGetResolvesGUTIToSUPI(t *testing.T) {
	tool := getTool{amfServer(t)}
	out, err := tool.Invoke(context.Background(), json.RawMessage(
		`{"guti":"mcc=001 mnc=01 amf=01 set=1 id=01 tmsi=00000002"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), "imsi-001010000000002") {
		t.Errorf("GUTI resolved to the wrong UE: %s", raw)
	}
}

func TestGetRequiresExactlyOneIdentifier(t *testing.T) {
	tool := getTool{amfServer(t)}
	for _, args := range []string{`{}`, `{"supi":"imsi-001010000000001","guti":"x"}`} {
		_, err := tool.Invoke(context.Background(), json.RawMessage(args))
		var e *mcperr.Error
		if !errors.As(err, &e) || e.Code != mcperr.CodeInvalidParams {
			t.Errorf("%s: want -32602, got %v", args, err)
		}
	}
}

func TestUnknownGUTIIsAnError(t *testing.T) {
	_, err := getTool{amfServer(t)}.Invoke(context.Background(), json.RawMessage(`{"guti":"nope"}`))
	if err == nil {
		t.Fatal("unknown GUTI must be an error")
	}
}

func TestGMMAliasForwardsToContextGet(t *testing.T) {
	tools := All(amfServer(t))
	var alias bool
	for _, tl := range tools {
		if tl.Name() == "gmm_state_get" {
			alias = true
			out, err := tl.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000002"}`))
			if err != nil {
				t.Fatalf("alias invoke: %v", err)
			}
			raw, _ := json.Marshal(out)
			if !strings.Contains(string(raw), "REGISTERED") {
				t.Errorf("alias result: %s", raw)
			}
		}
	}
	if !alias {
		t.Fatal("gmm_state_get alias not registered")
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		name, in, wantPSI, wantTime string
	}{
		{"base64", `{"pdu_session_ids":"AQ==","registration_time":"0001-01-01T00:00:00Z"}`, `[1]`, `null`},
		{"base64 two", `{"pdu_session_ids":"AQI="}`, `[1,2]`, ``},
		{"int array", `{"pdu_session_ids":[1,2],"registration_time":"2026-10-09T10:00:00Z"}`, `[1,2]`, `"2026-10-09T10:00:00Z"`},
		{"null", `{"pdu_session_ids":null,"registration_time":null}`, `[]`, `null`},
		{"empty string", `{"pdu_session_ids":""}`, `[]`, ``},
		{"out of range dropped", `{"pdu_session_ids":"AQAQ/w=="}`, `[1]`, ``},
		{"invalid base64 untouched", `{"pdu_session_ids":"!!"}`, `"!!"`, ``},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got map[string]json.RawMessage
			if err := json.Unmarshal(normalize(json.RawMessage(c.in)), &got); err != nil {
				t.Fatal(err)
			}
			if string(got["pdu_session_ids"]) != c.wantPSI {
				t.Errorf("pdu_session_ids = %s, want %s", got["pdu_session_ids"], c.wantPSI)
			}
			if c.wantTime != "" && string(got["registration_time"]) != c.wantTime {
				t.Errorf("registration_time = %s, want %s", got["registration_time"], c.wantTime)
			}
		})
	}
	if got := normalize(json.RawMessage(`[1]`)); string(got) != `[1]` {
		t.Errorf("non-object changed: %s", got)
	}
}

func TestNormalizeAppliedToListAndGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const ue = `{"supi":"imsi-001010000000001","gmm_state":"5GMM-REGISTERED","cm_state":"CM-CONNECTED","pdu_session_ids":"AQ==","registration_time":"0001-01-01T00:00:00Z"}`
		if r.URL.Path == "/amf/v1/ue-contexts" {
			_, _ = w.Write([]byte("[" + ue + "]"))
			return
		}
		_, _ = w.Write([]byte(ue))
	}))
	defer srv.Close()
	amf := clients.NewAMF(srv.URL, http.DefaultClient)
	l, err := listTool{amf}.Invoke(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := getTool{amf}.Invoke(context.Background(), json.RawMessage(`{"supi":"imsi-001010000000001"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []any{l, g} {
		raw, _ := json.Marshal(out)
		if !strings.Contains(string(raw), `"pdu_session_ids":[1]`) || !strings.Contains(string(raw), `"registration_time":null`) {
			t.Errorf("not normalised: %s", raw)
		}
	}
}

// TestNormalizeReportsInvalidPSIs: PSIs outside 1-15 move to pdu_session_ids_invalid;
// the field is omitted when every PSI is valid.
func TestNormalizeReportsInvalidPSIs(t *testing.T) {
	var got map[string]json.RawMessage
	if err := json.Unmarshal(normalize(json.RawMessage(`{"pdu_session_ids":"AQAQ/w=="}`)), &got); err != nil {
		t.Fatal(err)
	}
	if string(got["pdu_session_ids"]) != `[1]` || string(got["pdu_session_ids_invalid"]) != `[0,16,255]` {
		t.Errorf("ids = %s invalid = %s", got["pdu_session_ids"], got["pdu_session_ids_invalid"])
	}
	got = nil
	if err := json.Unmarshal(normalize(json.RawMessage(`{"pdu_session_ids":[1,15]}`)), &got); err != nil {
		t.Fatal(err)
	}
	if _, present := got["pdu_session_ids_invalid"]; present {
		t.Errorf("pdu_session_ids_invalid must be omitted when empty: %s", got["pdu_session_ids_invalid"])
	}
}
