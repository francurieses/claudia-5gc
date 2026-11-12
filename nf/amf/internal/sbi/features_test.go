package sbi

// features_test.go - REL19-2.7 producer side: supportedFeatures validation,
// answer and FeatureNegotiation logging in the namf-comm handlers
// (decision D1, dev/REL19_PROGRAM.md §2). The no-attribute rel17 bytes are
// pinned by golden_features_test.go.
// Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2; TS 29.518 §6.1.8.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func profileNamed(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("NewProfile(%q): %v", name, err)
	}
	return p
}

// featureServer builds a server with the given profile, the given catalog
// (nil = the real, nothing-implemented one) and a JSON log buffer.
func featureServer(t *testing.T, p *capability.Profile, cat *features.Catalog) (*Server, *amfctx.Manager, *syncBuf) {
	t.Helper()
	buf := &syncBuf{}
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	s, err := New(Config{Address: "127.0.0.1:0"}, mgr, slog.New(slog.NewJSONHandler(buf, nil)).With("nf", "AMF"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetProfile(p)
	if cat != nil {
		s.SetCatalog(cat)
	}
	return s, mgr, buf
}

// implCatalog is the injected test catalog: F1 (Rel-17) and F9 (Rel-19), both
// implemented. Local set: "1" under nil/rel17, "101" under rel19.
func implCatalog() *features.Catalog {
	return features.MustCatalog(
		features.Entry{Number: 1, Name: "F1", Release: capability.Rel17, Implemented: true},
		features.Entry{Number: 9, Name: "F9", Release: capability.Rel19, Implemented: true},
	)
}

// sfCase: request value (sent == nil -> attribute absent), the expected
// response value per profile ("" = attribute omitted) and the negotiated set
// logged per profile.
type sfCase struct {
	name         string
	sent         *string
	extra        map[string]any // unknown JSON attributes added to the body
	bad          bool
	rel17, rel19 string
	neg17, neg19 string
}

func sp(s string) *string { return &s }

func sfCases() []sfCase {
	long := strings.Repeat("0", 299) + "1" // schema-valid, 300 hex chars, over MaxHexChars
	return []sfCase{
		{name: "absent", sent: nil, rel17: "", rel19: "0", neg17: "0", neg19: "0"},
		{name: "empty string", sent: sp(""), rel17: "", rel19: "0", neg17: "0", neg19: "0"},
		{name: "zero", sent: sp("0"), rel17: "0", rel19: "0", neg17: "0", neg19: "0"},
		{name: "F1+F9", sent: sp("101"), rel17: "1", rel19: "101", neg17: "1", neg19: "101"},
		{name: "mixed case low bits", sent: sp("1B"), rel17: "1", rel19: "1", neg17: "1", neg19: "1"},
		{name: "high bit ignored", sent: sp("8000000001"), rel17: "1", rel19: "1", neg17: "1", neg19: "1"},
		{name: "over-long valid", sent: sp(long), rel17: "1", rel19: "1", neg17: "1", neg19: "1"},
		{name: "only unknown feature", sent: sp("2"), rel17: "0", rel19: "0", neg17: "0", neg19: "0"},
		{name: "unknown JSON attribute", sent: sp("1"), extra: map[string]any{"futureAttr": map[string]any{"x": 1}},
			rel17: "1", rel19: "1", neg17: "1", neg19: "1"},
		{name: "non-hex", sent: sp("zz"), bad: true},
		{name: "0x prefix", sent: sp("0x1"), bad: true},
		{name: "embedded space", sent: sp("1 01"), bad: true},
	}
}

// expect returns the response value, the negotiated set and the local set
// logged under the named profile.
func (tc sfCase) expect(prof string) (answer, negotiated, local string) {
	if prof == "rel19" {
		return tc.rel19, tc.neg19, "101"
	}
	return tc.rel17, tc.neg17, "1"
}

func (tc sfCase) body(extra map[string]any) []byte {
	m := map[string]any{}
	for k, v := range extra {
		m[k] = v
	}
	for k, v := range tc.extra {
		m[k] = v
	}
	if tc.sent != nil {
		m["supportedFeatures"] = *tc.sent
	}
	b, _ := json.Marshal(m)
	return b
}

// syncBuf is a mutex-guarded log sink: handlers log from detached goroutines.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

func logRecords(t *testing.T, buf *syncBuf, procedure string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.bytes()), []byte("\n")) {
		var m map[string]any
		if json.Unmarshal(line, &m) == nil && m["procedure"] == procedure {
			out = append(out, m)
		}
	}
	return out
}

func assertInvalidParam(t *testing.T, raw []byte) {
	t.Helper()
	var pd ProblemDetails
	if err := json.Unmarshal(raw, &pd); err != nil {
		t.Fatalf("problem body: %v (%s)", err, raw)
	}
	if pd.Status != 400 || pd.Cause != CauseInvalidMsgFormat ||
		len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != "/supportedFeatures" {
		t.Errorf("problem = %+v, want 400 INVALID_MSG_FORMAT invalidParams[/supportedFeatures]", pd)
	}
}

func TestUEContextTransfer_SupportedFeatures(t *testing.T) {
	for _, prof := range []string{"nil", "rel17", "rel19"} {
		for _, tc := range sfCases() {
			t.Run(prof+"/"+tc.name, func(t *testing.T) {
				var p *capability.Profile
				if prof != "nil" {
					p = profileNamed(t, prof)
				}
				srv, mgr, logs := featureServer(t, p, implCatalog())
				ue := seedRegisteredUE(mgr, "imsi-001010000000001")

				resp, raw := post(t, srv, "imsi-001010000000001", tc.body(map[string]any{"reason": ReasonMobiReg, "accessType": AccessType3GPP}))

				ue.Lock()
				transferred := ue.Transferred
				ue.Unlock()

				if tc.bad {
					if resp.StatusCode != http.StatusBadRequest {
						t.Fatalf("status %d, want 400: %s", resp.StatusCode, raw)
					}
					assertInvalidParam(t, raw)
					if transferred {
						t.Error("UE context marked Transferred by a rejected request")
					}
					recs := logRecords(t, logs, features.ProcedureName)
					if len(recs) != 1 || recs[0]["result"] != "REJECT" || recs[0]["cause"] != CauseInvalidMsgFormat ||
						recs[0]["spec_ref"] != features.SpecRefInvalid || recs[0]["features_peer"] != *tc.sent {
						t.Errorf("reject log = %v", recs)
					}
					return
				}
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status %d: %s", resp.StatusCode, raw)
				}
				if !transferred {
					t.Error("UE context not marked Transferred")
				}
				want, wantNeg, wantLocal := tc.expect(prof)
				var rsp UeContextTransferRspData
				if err := json.Unmarshal(raw, &rsp); err != nil {
					t.Fatal(err)
				}
				if rsp.SupportedFeatures != want {
					t.Errorf("response supportedFeatures = %q, want %q", rsp.SupportedFeatures, want)
				}
				if _, present := mapOf(t, raw)["supportedFeatures"]; present != (want != "") {
					t.Errorf("supportedFeatures presence = %v, want %v (omitempty)", present, want != "")
				}
				recs := logRecords(t, logs, features.ProcedureName)
				if len(recs) != 1 {
					t.Fatalf("want one FeatureNegotiation record, got %v", recs)
				}
				r := recs[0]
				peer := features.PeerAbsent
				if tc.sent != nil && *tc.sent != "" {
					peer = *tc.sent
					// LogAttrs bounds the peer-controlled value: cut to
					// MaxLoggedPeerChars and suffixed with "...".
					if len(peer) > features.MaxLoggedPeerChars {
						peer = peer[:features.MaxLoggedPeerChars] + "..."
					}
				}
				for k, v := range map[string]string{
					"nf": "AMF", "interface": "Namf", "direction": "IN", "peer_nf_type": "AMF",
					"spec_ref": features.SpecRef, "result": "OK", "features_peer": peer,
					"features_local": wantLocal, "features_negotiated": wantNeg,
				} {
					if r[k] != v {
						t.Errorf("log %s = %v, want %q", k, r[k], v)
					}
				}
			})
		}
	}
}

func mapOf(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestN1N2MessageTransfer_SupportedFeatures(t *testing.T) {
	for _, prof := range []string{"nil", "rel17", "rel19"} {
		for _, state := range []amfctx.CMState{amfctx.CMConnected, amfctx.CMIdle} {
			for _, tc := range sfCases() {
				t.Run(prof+"/"+state.String()+"/"+tc.name, func(t *testing.T) {
					var p *capability.Profile
					if prof != "nil" {
						p = profileNamed(t, prof)
					}
					srv, mgr, logs := featureServer(t, p, implCatalog())
					fp := &fakePager{}
					srv.SetPager(fp)
					ue := seedRegisteredUE(mgr, "imsi-001010000000001")
					ue.Lock()
					ue.CMState = state
					ue.Unlock()

					resp, raw := postN1N2(t, srv, "imsi-001010000000001", tc.body(map[string]any{"pduSessionId": 1}))

					ue.Lock()
					pending := ue.PendingN1N2
					ue.Unlock()

					if tc.bad {
						if resp.StatusCode != http.StatusBadRequest {
							t.Fatalf("status %d, want 400: %s", resp.StatusCode, raw)
						}
						assertInvalidParam(t, raw)
						if fp.paged != 0 || pending || len(ue.PagedPDUSessions()) != 0 {
							t.Errorf("side effects after 400: paged=%d pending=%v paged-psis=%v", fp.paged, pending, ue.PagedPDUSessions())
						}
						recs := logRecords(t, logs, features.ProcedureName)
						if len(recs) != 1 || recs[0]["result"] != "REJECT" || recs[0]["peer_nf_type"] != "SMF" ||
							recs[0]["spec_ref"] != features.SpecRefInvalid {
							t.Errorf("reject log = %v", recs)
						}
						return
					}
					wantStatus := http.StatusOK
					if state == amfctx.CMIdle {
						wantStatus = http.StatusAccepted
						if fp.paged != 1 || !pending {
							t.Errorf("idle UE not paged: paged=%d pending=%v", fp.paged, pending)
						}
					}
					if resp.StatusCode != wantStatus {
						t.Fatalf("status %d, want %d: %s", resp.StatusCode, wantStatus, raw)
					}
					want, wantNeg, wantLocal := tc.expect(prof)
					var rsp N1N2MessageTransferRspData
					if err := json.Unmarshal(raw, &rsp); err != nil {
						t.Fatal(err)
					}
					if rsp.SupportedFeatures != want {
						t.Errorf("response supportedFeatures = %q, want %q", rsp.SupportedFeatures, want)
					}
					recs := logRecords(t, logs, features.ProcedureName)
					if len(recs) != 1 || recs[0]["features_negotiated"] != wantNeg || recs[0]["features_local"] != wantLocal || recs[0]["peer_nf_type"] != "SMF" ||
						recs[0]["supi"] != "imsi-001010000000001" {
						t.Errorf("log = %v", recs)
					}
				})
			}
		}
	}
}

// With the real catalog (nothing implemented) a rel19 producer answers "0" to
// everything; rel17 omits when the attribute is absent.
func TestProducerRealCatalog(t *testing.T) {
	srv, mgr, _ := featureServer(t, profileNamed(t, "rel19"), nil)
	seedRegisteredUE(mgr, "imsi-001010000000001")
	_, raw := post(t, srv, "imsi-001010000000001", []byte(`{"reason":"MOBI_REG","accessType":"3GPP_ACCESS","supportedFeatures":"ffff"}`))
	var rsp UeContextTransferRspData
	_ = json.Unmarshal(raw, &rsp)
	if rsp.SupportedFeatures != "0" {
		t.Errorf("rel19 real catalog answer = %q, want 0", rsp.SupportedFeatures)
	}
}

// A request for an unknown UE with a valid supportedFeatures stays a 404 and
// does not log a successful negotiation.
func TestProducerUnknownUE_NoNegotiationLog(t *testing.T) {
	srv, _, logs := featureServer(t, profileNamed(t, "rel19"), nil)
	resp, _ := post(t, srv, "imsi-009", []byte(`{"reason":"MOBI_REG","accessType":"3GPP_ACCESS","supportedFeatures":"1"}`))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if recs := logRecords(t, logs, features.ProcedureName); len(recs) != 0 {
		t.Errorf("unexpected negotiation log %v", recs)
	}
}

// TestCatalogsImplementedFeatures pins the implemented set of both AMF
// catalogs: the Namf_Communication producer catalog implements nothing; the
// Nsmf_PDUSession consumer catalog implements exactly 8 ES3XX (SBI-FEAT-001).
// HOFAIL (7), AASN (10) and SCID (29) are deferred and must stay unimplemented.
func TestCatalogsImplementedFeatures(t *testing.T) {
	for name, tc := range map[string]struct {
		c    *features.Catalog
		impl map[int]bool
		want string
	}{
		"namf": {NamfCommunicationCatalog(), map[int]bool{}, "0"},
		"nsmf": {NsmfPDUSessionCatalog(), map[int]bool{8: true}, "80"},
	} {
		for _, e := range tc.c.Entries() {
			if e.Implemented != tc.impl[e.Number] {
				t.Errorf("%s feature %d (%s) Implemented=%v, want %v", name, e.Number, e.Name, e.Implemented, tc.impl[e.Number])
			}
		}
		if got := tc.c.Supported(profileNamed(t, "rel19")).String(); got != tc.want {
			t.Errorf("%s offers %s, want %s", name, got, tc.want)
		}
	}
	if n := len(NamfCommunicationCatalog().Entries()); n != 22 {
		t.Errorf("namf catalog has %d entries, want 22", n)
	}
	if n := len(NsmfPDUSessionCatalog().Entries()); n != 41 {
		t.Errorf("nsmf catalog has %d entries, want 41", n)
	}
}

// TestSupportedFeaturesJSONType: a non-string supportedFeatures is a JSON type
// error on exactly that field and is answered 400 INVALID_MSG_FORMAT with the
// JSON Pointer param, logged REJECT (TS 29.500 §5.2.7.2, TS 29.571 §5.2.4.6).
// Other decode errors keep the generic MANDATORY_IE_MISSING answer.
func TestSupportedFeaturesJSONType(t *testing.T) {
	type poster func(*testing.T, *Server, string, []byte) (*http.Response, []byte)
	for _, h := range []struct {
		name string
		post poster
		peer string
	}{
		{"UEContextTransfer", post, "AMF"},
		{"N1N2MessageTransfer", postN1N2, "SMF"},
	} {
		t.Run(h.name, func(t *testing.T) {
			for _, bad := range []string{`5`, `true`, `["1"]`, `{"a":1}`} {
				srv, mgr, logs := featureServer(t, nil, implCatalog())
				seedRegisteredUE(mgr, "imsi-001010000000001")
				resp, raw := h.post(t, srv, "imsi-001010000000001", []byte(`{"reason":"MOBI_REG","pduSessionId":1,"supportedFeatures":`+bad+`}`))
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("%s: status %d: %s", bad, resp.StatusCode, raw)
				}
				assertInvalidParam(t, raw)
				recs := logRecords(t, logs, features.ProcedureName)
				if len(recs) != 1 || recs[0]["result"] != "REJECT" || recs[0]["cause"] != CauseInvalidMsgFormat || recs[0]["peer_nf_type"] != h.peer {
					t.Errorf("%s: reject log = %v", bad, recs)
				}
			}
			// A type error on another field is not ours: unchanged behaviour.
			srv, mgr, _ := featureServer(t, nil, implCatalog())
			seedRegisteredUE(mgr, "imsi-001010000000001")
			resp, raw := h.post(t, srv, "imsi-001010000000001", []byte(`{"pduSessionId":"x","reason":5,"supportedFeatures":"1"}`))
			var pd ProblemDetails
			_ = json.Unmarshal(raw, &pd)
			if resp.StatusCode != http.StatusBadRequest || pd.Cause != "MANDATORY_IE_MISSING" || len(pd.InvalidParams) != 0 {
				t.Errorf("other type error: %d %s", resp.StatusCode, raw)
			}
		})
	}
}

// TestFeatureNegotiationLogKeysOnce: slog's JSON handler does not de-duplicate
// keys, so every canonical key must appear exactly once in the raw line.
func TestFeatureNegotiationLogKeysOnce(t *testing.T) {
	srv, mgr, logs := featureServer(t, profileNamed(t, "rel19"), implCatalog())
	seedRegisteredUE(mgr, "imsi-001010000000001")
	for _, body := range []string{`{"reason":"MOBI_REG","accessType":"3GPP_ACCESS","supportedFeatures":"101"}`, `{"reason":"MOBI_REG","accessType":"3GPP_ACCESS","supportedFeatures":"zz"}`} {
		post(t, srv, "imsi-001010000000001", []byte(body))
	}
	n := 0
	for _, line := range bytes.Split(bytes.TrimSpace(logs.bytes()), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"procedure":"`+features.ProcedureName+`"`)) {
			continue
		}
		n++
		for _, k := range []string{"nf", "procedure", "interface", "direction", "spec_ref", "result", "features_peer"} {
			if c := bytes.Count(line, []byte(`"`+k+`":`)); c != 1 {
				t.Errorf("key %q appears %d times in %s", k, c, line)
			}
		}
	}
	if n != 2 {
		t.Fatalf("FeatureNegotiation lines = %d, want 2", n)
	}
}
