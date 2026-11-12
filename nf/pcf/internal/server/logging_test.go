package server

// logging_test.go - PCF-003: every PCF procedure log line carries the mandatory
// fields exactly once, delete 413s are attributed to the delete procedure.
// Ref: root CLAUDE.md "Logging - Required Format"; TS 29.500 §5.2.7.1.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// logRecords decodes the captured JSON log lines and rejects any line that
// repeats a top-level key (slog does not de-duplicate With/attr keys).
func logRecords(t *testing.T, logs *syncBuf) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		if _, err := dec.Token(); err != nil { // '{'
			t.Fatalf("log line is not JSON: %s", line)
		}
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				t.Fatalf("log line %s: %v", line, err)
			}
			key := k.(string)
			if seen[key] {
				t.Errorf("duplicate key %q in log line: %s", key, line)
			}
			seen[key] = true
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("log line %s: %v", line, err)
			}
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

var mandatoryLogKeys = []string{"nf", "procedure", "correlation_id", "interface", "direction", "spec_ref"}

func assertMandatory(t *testing.T, rec map[string]any) {
	t.Helper()
	for _, k := range mandatoryLogKeys {
		if v, _ := rec[k].(string); v == "" {
			t.Errorf("log line %q (procedure %v) lacks %q: %v", rec["msg"], rec["procedure"], k, rec)
		}
	}
}

func serveWithCorr(s *Server, method, path, body string) *http.Response {
	w := serveReq(s, method, path, body, map[string]string{"X-Correlation-Id": "01TESTCORRELATIONID00000000"})
	return w.Result()
}

// TestAMPolicyDelete_LogFields: the AM delete lines (received IN, outcome OUT)
// carry every mandatory field, "nf" appears exactly once, and the outcome has
// result/cause. Ref: TS 29.507 §4.2.5.
func TestAMPolicyDelete_LogFields(t *testing.T) {
	s, logs := newFeaturePCF(t, nil, Catalogs{})
	resp := serveWithCorr(s, http.MethodPost, "/npcf-am-policy-control/v1/policies",
		`{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS"}`)
	id := lastSegment(resp.Header.Get("Location"))
	serveWithCorr(s, http.MethodDelete, "/npcf-am-policy-control/v1/policies/"+id, "")
	serveWithCorr(s, http.MethodDelete, "/npcf-am-policy-control/v1/policies/"+id, "") // unknown now

	var del []map[string]any
	for _, rec := range logRecords(t, logs) {
		if rec["procedure"] == "AMPolicyDelete" {
			del = append(del, rec)
		}
	}
	if len(del) != 4 {
		t.Fatalf("AMPolicyDelete lines = %d, want 4 (received+OK, received+REJECT)", len(del))
	}
	for _, rec := range del {
		assertMandatory(t, rec)
		if rec["correlation_id"] != "01TESTCORRELATIONID00000000" {
			t.Errorf("correlation_id %v", rec["correlation_id"])
		}
		if rec["pol_asso_id"] != id {
			t.Errorf("pol_asso_id %v", rec["pol_asso_id"])
		}
	}
	if del[0]["direction"] != "IN" || del[1]["direction"] != "OUT" || del[1]["result"] != "OK" {
		t.Errorf("first delete lines: %v / %v", del[0], del[1])
	}
	if del[3]["direction"] != "OUT" || del[3]["result"] != "REJECT" || del[3]["cause"] != "POLICY_ASSOCIATION_NOT_FOUND" {
		t.Errorf("unknown delete outcome: %v", del[3])
	}
	for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
		if n := bytes.Count(line, []byte(`"nf":`)); n != 1 {
			t.Errorf("%d nf keys in %s", n, line)
		}
	}
}

// TestAllProcedureLogLines drives every Npcf handler and asserts that every
// emitted line has the mandatory fields once; outcome lines carry result.
func TestAllProcedureLogLines(t *testing.T) {
	s, logs := newFeaturePCF(t, nil, Catalogs{})
	s.cfg.DefaultURSP.Rules = nil
	h := map[string]string{"X-Correlation-Id": "01TESTCORRELATIONID00000000"}
	do := func(method, path, body string) *http.Response { return serveReq(s, method, path, body, h).Result() }

	sm := do(http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies", `{"supi":"imsi-001010000000001","dnn":"internet"}`)
	smID := lastSegment(sm.Header.Get("Location"))
	do(http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+smID+"/update", `{"reqQos":{"5qi":9}}`)
	do(http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+smID+"/delete", `{}`)
	do(http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+smID+"/delete", `{}`)
	do(http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/x/delete", `{bad`)

	ue := do(http.MethodPost, "/npcf-ue-policy-control/v1/policies", `{"supi":"imsi-001010000000001"}`)
	ueID := lastSegment(ue.Header.Get("Location"))
	do(http.MethodDelete, "/npcf-ue-policy-control/v1/policies/"+ueID, "")
	do(http.MethodDelete, "/npcf-ue-policy-control/v1/policies/"+ueID, "")
	do(http.MethodPost, "/npcf-ue-policy-control/v1/policies", `{"supi":"imsi-001010000000001","suppFeat":"zz"}`)

	do(http.MethodPost, "/npcf-am-policy-control/v1/policies", `{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS"}`)

	app := do(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions", `{"ascReqData":{"ueIpv4":"10.60.0.1"}}`)
	appID := lastSegment(app.Header.Get("Location"))
	do(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions", `{"ascReqData":{}}`)
	do(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions/"+appID+"/delete", "")
	do(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions/"+appID+"/delete", "")
	do(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions", `{"x":"`+strings.Repeat("a", features.MaxRequestBodyBytes+1)+`"}`)

	// Internal management API (not a 3GPP SBI): QoS and RFSP overrides.
	do(http.MethodPut, "/pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override", `{"5qi":7}`)
	do(http.MethodGet, "/pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override", "")
	do(http.MethodGet, "/pcf-internal/v1/sm-policy-overrides", "")
	do(http.MethodDelete, "/pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override", "")
	do(http.MethodDelete, "/pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override", "")
	do(http.MethodPut, "/pcf-internal/v1/subscribers/imsi-001010000000001/am-policy-override", `{"rfsp":5}`)
	do(http.MethodGet, "/pcf-internal/v1/subscribers/imsi-001010000000001/am-policy-override", "")
	do(http.MethodDelete, "/pcf-internal/v1/subscribers/imsi-001010000000001/am-policy-override", "")
	do(http.MethodDelete, "/pcf-internal/v1/subscribers/imsi-001010000000001/am-policy-override", "")

	seen := map[string]bool{}
	for _, rec := range logRecords(t, logs) {
		p, _ := rec["procedure"].(string)
		if p == "" { // server start-up lines are not procedure lines
			continue
		}
		assertMandatory(t, rec)
		seen[p] = true
	}
	for _, p := range []string{"SmPolicyCreate", "SmPolicyUpdate", "SmPolicyDelete", "UEPolicyCreate",
		"UEPolicyDelete", "AMPolicyCreate", "PolicyAuthorizationCreate", "PolicyAuthorizationDelete", "FeatureNegotiation",
		"SmPolicyOverride", "SmPolicyOverrideList", "AMPolicyOverride"} {
		if !seen[p] {
			t.Errorf("procedure %s produced no log line", p)
		}
	}
}

// TestUEPolicyDelete_LogAfterOutcome: the delete line reports the real outcome
// (no premature result=OK for an unknown id). Ref: TS 29.525 §4.2.5.
func TestUEPolicyDelete_LogAfterOutcome(t *testing.T) {
	s, logs := newFeaturePCF(t, nil, Catalogs{})
	serveWithCorr(s, http.MethodDelete, "/npcf-ue-policy-control/v1/policies/unknown", "")
	for _, rec := range logRecords(t, logs) {
		if rec["procedure"] != "UEPolicyDelete" {
			continue
		}
		if rec["result"] == "OK" {
			t.Errorf("unknown id logged result=OK: %v", rec)
		}
		if rec["direction"] == "OUT" && (rec["result"] != "REJECT" || rec["cause"] != "POLICY_ASSOCIATION_NOT_FOUND") {
			t.Errorf("outcome line: %v", rec)
		}
	}
}

// TestPayloadTooLarge_DeleteProcedureLabel: a 413 on a delete custom operation
// is logged and counted under the delete procedure, not the create one.
// Ref: TS 29.500 §5.2.7.1.
func TestPayloadTooLarge_DeleteProcedureLabel(t *testing.T) {
	big := `{"x":"` + strings.Repeat("a", features.MaxRequestBodyBytes+1) + `"}`
	for _, tc := range []struct{ name, path, proc, createProc string }{
		{"SM delete", "/npcf-smpolicycontrol/v1/sm-policies/x/delete", "SmPolicyDelete", "SmPolicyCreate"},
		{"app-session delete", "/npcf-policyauthorization/v1/app-sessions/x/delete", "PolicyAuthorizationDelete", "PolicyAuthorizationCreate"},
		{"SM create", "/npcf-smpolicycontrol/v1/sm-policies", "SmPolicyCreate", ""},
		{"UE create", "/npcf-ue-policy-control/v1/policies", "UEPolicyCreate", ""},
		{"AM create", "/npcf-am-policy-control/v1/policies", "AMPolicyCreate", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, logs := newFeaturePCF(t, nil, Catalogs{})
			ctr := metrics.ProcedureTotal.WithLabelValues("PCF", tc.proc, "REJECT")
			before := testutil.ToFloat64(ctr)
			var beforeCreate float64
			if tc.createProc != "" {
				beforeCreate = testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("PCF", tc.createProc, "REJECT"))
			}
			if resp := serveWithCorr(s, http.MethodPost, tc.path, big); resp.StatusCode != http.StatusRequestEntityTooLarge {
				_, _ = io.Copy(io.Discard, resp.Body)
				t.Fatalf("status %d, want 413", resp.StatusCode)
			}
			if got := testutil.ToFloat64(ctr) - before; got != 1 {
				t.Errorf("%s REJECT counter delta = %v, want 1", tc.proc, got)
			}
			if tc.createProc != "" {
				if got := testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("PCF", tc.createProc, "REJECT")) - beforeCreate; got != 0 {
					t.Errorf("%s counter moved by %v on a delete 413", tc.createProc, got)
				}
			}
			found := false
			for _, rec := range logRecords(t, logs) {
				if rec["cause"] == "PAYLOAD_TOO_LARGE" {
					found = true
					assertMandatory(t, rec)
					if rec["procedure"] != tc.proc {
						t.Errorf("413 logged under %v, want %s", rec["procedure"], tc.proc)
					}
				}
			}
			if !found {
				t.Error("no PAYLOAD_TOO_LARGE log line")
			}
		})
	}
}

// TestPolicyAssociationSuppFeatByProfile: suppFeat is a required attribute of
// PolicyAssociation (TS 29.507 §5.6.2.2, TS 29.525 §5.6.2.2). Under rel19 the
// 201 always carries it ("0" when nothing is negotiated); under rel17 a request
// without suppFeat gets a response without it (decision D1, byte-identical
// baseline, dev/REL19_PROGRAM.md §2).
func TestPolicyAssociationSuppFeatByProfile(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"AM", "/npcf-am-policy-control/v1/policies", `{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS"}`},
		{"UE", "/npcf-ue-policy-control/v1/policies", `{"supi":"imsi-001010000000001"}`},
	} {
		for _, prof := range []struct {
			name    string
			want    string
			present bool
		}{{"rel17", "", false}, {"rel19", "0", true}} {
			t.Run(tc.name+"/"+prof.name, func(t *testing.T) {
				s, _ := newFeaturePCF(t, profileNamed(t, prof.name), Catalogs{})
				resp, raw := post(t, s, tc.path, tc.body, "")
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("%d %s", resp.StatusCode, raw)
				}
				var m map[string]any
				if err := json.Unmarshal(raw, &m); err != nil {
					t.Fatal(err)
				}
				v, present := m["suppFeat"]
				if present != prof.present || (present && v != prof.want) {
					t.Errorf("suppFeat present=%v value=%v, want present=%v value=%q", present, v, prof.present, prof.want)
				}
			})
		}
	}
}

// TestRejectPathsLogged: every 4xx reject path (including the ones that
// predate the suppFeat work and the internal management API) emits a Warn with
// result=REJECT, a cause and the mandatory fields; the SM update also logs a
// "received" IN line before processing.
func TestRejectPathsLogged(t *testing.T) {
	const ue = "imsi-001010000000001"
	for _, tc := range []struct {
		name, method, path, body, procedure string
		status                              int
		cause                               string
	}{
		{"SM create bad body", http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies", `{bad`, "SmPolicyCreate", 400, "MANDATORY_IE_MISSING"},
		{"SM update unknown", http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/nope/update", `{}`, "SmPolicyUpdate", 404, "POLICY_ASSOCIATION_NOT_FOUND"},
		{"AM create bad body", http.MethodPost, "/npcf-am-policy-control/v1/policies", `{bad`, "AMPolicyCreate", 400, "MANDATORY_IE_MISSING"},
		{"AM create no supi", http.MethodPost, "/npcf-am-policy-control/v1/policies", `{"accessType":"3GPP_ACCESS"}`, "AMPolicyCreate", 400, "MANDATORY_IE_MISSING"},
		{"AM create no accessType", http.MethodPost, "/npcf-am-policy-control/v1/policies", `{"supi":"` + ue + `"}`, "AMPolicyCreate", 400, "MANDATORY_IE_MISSING"},
		{"UE create bad body", http.MethodPost, "/npcf-ue-policy-control/v1/policies", `{bad`, "UEPolicyCreate", 400, "MANDATORY_IE_MISSING"},
		{"UE create no supi", http.MethodPost, "/npcf-ue-policy-control/v1/policies", `{}`, "UEPolicyCreate", 400, "MANDATORY_IE_MISSING"},
		{"app-session bad body", http.MethodPost, "/npcf-policyauthorization/v1/app-sessions", `{bad`, "PolicyAuthorizationCreate", 400, "MANDATORY_IE_INCORRECT"},
		{"QoS override bad body", http.MethodPut, "/pcf-internal/v1/subscribers/" + ue + "/sm-policy-override", `{bad`, "SmPolicyOverride", 400, "INVALID_BODY"},
		{"QoS override no 5qi", http.MethodPut, "/pcf-internal/v1/subscribers/" + ue + "/sm-policy-override", `{}`, "SmPolicyOverride", 400, "MISSING_FIELD"},
		{"QoS override get none", http.MethodGet, "/pcf-internal/v1/subscribers/" + ue + "/sm-policy-override", "", "SmPolicyOverride", 404, "NOT_FOUND"},
		{"QoS override delete none", http.MethodDelete, "/pcf-internal/v1/subscribers/" + ue + "/sm-policy-override", "", "SmPolicyOverride", 404, "NOT_FOUND"},
		{"RFSP override bad body", http.MethodPut, "/pcf-internal/v1/subscribers/" + ue + "/am-policy-override", `{bad`, "AMPolicyOverride", 400, "INVALID_BODY"},
		{"RFSP override range", http.MethodPut, "/pcf-internal/v1/subscribers/" + ue + "/am-policy-override", `{"rfsp":0}`, "AMPolicyOverride", 400, "INVALID_VALUE"},
		{"RFSP override get none", http.MethodGet, "/pcf-internal/v1/subscribers/" + ue + "/am-policy-override", "", "AMPolicyOverride", 404, "NOT_FOUND"},
		{"RFSP override delete none", http.MethodDelete, "/pcf-internal/v1/subscribers/" + ue + "/am-policy-override", "", "AMPolicyOverride", 404, "NOT_FOUND"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, logs := newFeaturePCF(t, nil, Catalogs{})
			resp := serveWithCorr(s, tc.method, tc.path, tc.body)
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
			found := false
			for _, rec := range logRecords(t, logs) {
				if rec["procedure"] != tc.procedure {
					continue
				}
				assertMandatory(t, rec)
				if rec["result"] == "REJECT" {
					found = true
					if rec["cause"] != tc.cause || rec["level"] != "WARN" {
						t.Errorf("reject line: %v", rec)
					}
					if rec["correlation_id"] != "01TESTCORRELATIONID00000000" {
						t.Errorf("correlation_id %v", rec["correlation_id"])
					}
				}
			}
			if !found {
				t.Errorf("no result=REJECT log line for %s", tc.name)
			}
		})
	}
}

// TestSmPolicyUpdate_ReceivedLine: the SM update logs an IN "received" line
// (TS 29.512 §4.2.3) before the OUT outcome line.
func TestSmPolicyUpdate_ReceivedLine(t *testing.T) {
	s, logs := newFeaturePCF(t, nil, Catalogs{})
	sm := serveWithCorr(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies", `{"supi":"imsi-001010000000001","dnn":"internet"}`)
	id := lastSegment(sm.Header.Get("Location"))
	serveWithCorr(s, http.MethodPost, "/npcf-smpolicycontrol/v1/sm-policies/"+id+"/update", `{"reqQos":{"5qi":9}}`)
	var dirs []string
	for _, rec := range logRecords(t, logs) {
		if rec["procedure"] == "SmPolicyUpdate" {
			assertMandatory(t, rec)
			if rec["spec_ref"] != "TS 29.512 §4.2.3" {
				t.Errorf("spec_ref %v", rec["spec_ref"])
			}
			dirs = append(dirs, rec["direction"].(string))
		}
	}
	if len(dirs) != 2 || dirs[0] != "IN" || dirs[1] != "OUT" {
		t.Errorf("SmPolicyUpdate directions = %v, want [IN OUT]", dirs)
	}
}

// TestNoFQDNWarning: constructing the server without sbi.fqdn logs one Warn
// that the Location authority comes from the request Host. Ref: TS 29.501 §4.4.1.
func TestNoFQDNWarning(t *testing.T) {
	_, logs := newFeaturePCF(t, nil, Catalogs{})
	n := 0
	for _, rec := range logRecords(t, logs) {
		if rec["msg"] == "sbi.fqdn not set: Location authority taken from the request Host" {
			n++
			if rec["level"] != "WARN" || rec["spec_ref"] != "TS 29.501 §4.4.1" || rec["nf"] == nil {
				t.Errorf("warning record: %v", rec)
			}
		}
	}
	if n != 1 {
		t.Errorf("sbi.fqdn warning logged %d times, want 1", n)
	}
}

// failWriter is a ResponseWriter whose body write always fails.
type failWriter struct{ http.ResponseWriter }

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// TestEncodeBodyFailureLogged: a failed 201 body write is logged as a Warn
// carrying the error and the correlation_id instead of being dropped.
func TestEncodeBodyFailureLogged(t *testing.T) {
	s, logs := newFeaturePCF(t, nil, Catalogs{})
	r := httptest.NewRequest(http.MethodPost, "/npcf-am-policy-control/v1/policies",
		strings.NewReader(`{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS"}`))
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	s.handleCreateAMPolicy(failWriter{httptest.NewRecorder()}, r)
	found := false
	for _, rec := range logRecords(t, logs) {
		if rec["msg"] == "response body encode failed" {
			found = true
			assertMandatory(t, rec)
			if rec["level"] != "WARN" || rec["error"] == nil || rec["correlation_id"] != "01TESTCORRELATIONID00000000" {
				t.Errorf("encode failure record: %v", rec)
			}
		}
	}
	if !found {
		t.Error("encode failure not logged")
	}
}
