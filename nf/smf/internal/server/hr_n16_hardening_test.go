package server

// hr_n16_hardening_test.go — ROAM-002 rework tests: PostSmContexts error mapping, H-SMF Location
// pinning and absolute URI, originating-PLMN checks, N16 body limits, unknownN1SmInfo split and a
// concurrent-access check that guards the sessionMu discipline of the HR roles (run with -race).
// Ref: TS 29.502 Table 6.1.3.2.3.1-3, Table 6.1.3.5.3.1-4, §5.2.3.1.2; TS 29.500 §5.2.3.2.15.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"testing"
)

func TestMapPostSmContextsError(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		cause      string
		fromHSMF   bool
		wantStatus int
		wantCause  string
	}{
		{"SEPP 504 TARGET_NF_NOT_REACHABLE", 504, "TARGET_NF_NOT_REACHABLE", false, 504, "PEER_NOT_RESPONDING"},
		{"SEPP 502", 502, "", false, 504, "PEER_NOT_RESPONDING"},
		{"SEPP 503", 503, "NF_CONGESTION", false, 504, "PEER_NOT_RESPONDING"},
		{"SEPP 408", 408, "TIMED_OUT_REQUEST", false, 504, "PEER_NOT_RESPONDING"},
		{"SEPP 500 plain", 500, "SYSTEM_FAILURE", false, 500, "SYSTEM_FAILURE"},
		{"SEPP 403 PLMNID_MISMATCH", 403, "PLMNID_MISMATCH", false, 500, "SYSTEM_FAILURE"},
		{"SEPP 404 CONTEXT_NOT_FOUND", 404, "CONTEXT_NOT_FOUND", false, 500, "SYSTEM_FAILURE"},
		{"H-SMF 403 DNN_DENIED", 403, "DNN_DENIED", true, 403, "DNN_DENIED"},
		{"H-SMF 403 N1_SM_ERROR", 403, "N1_SM_ERROR", true, 403, "N1_SM_ERROR"},
		{"H-SMF 403 unlisted cause", 403, "HOME_ROUTED_ROAMING_REQUIRED_X", true, 500, "SYSTEM_FAILURE"},
		{"H-SMF 403 PLMNID_MISMATCH", 403, "PLMNID_MISMATCH", true, 500, "SYSTEM_FAILURE"},
		{"H-SMF 404 CONTEXT_NOT_FOUND", 404, "CONTEXT_NOT_FOUND", true, 500, "SYSTEM_FAILURE"},
		{"H-SMF 400 MANDATORY_IE_MISSING", 400, "MANDATORY_IE_MISSING", true, 500, "SYSTEM_FAILURE"},
		{"H-SMF 400 INVALID_MSG_FORMAT", 400, "INVALID_MSG_FORMAT", true, 500, "SYSTEM_FAILURE"},
		{"H-SMF 413", 413, "MAX_JSON_SIZE_EXCEEDED", true, 500, "SYSTEM_FAILURE"},
		{"H-SMF 500 SYSTEM_FAILURE", 500, "SYSTEM_FAILURE", true, 500, "SYSTEM_FAILURE"},
		{"H-SMF 500 slice resources", 500, "INSUFFICIENT_RESOURCES_SLICE", true, 500, "INSUFFICIENT_RESOURCES_SLICE"},
		{"H-SMF 500 slice+DNN resources", 500, "INSUFFICIENT_RESOURCES_SLICE_DNN", true, 500, "INSUFFICIENT_RESOURCES_SLICE_DNN"},
		{"H-SMF 500 odd cause", 500, "UPF_NOT_RESPONDING", true, 500, "SYSTEM_FAILURE"},
		{"H-SMF 503 DNN_CONGESTION", 503, "DNN_CONGESTION", true, 503, "DNN_CONGESTION"},
		{"H-SMF 503 S_NSSAI_CONGESTION", 503, "S_NSSAI_CONGESTION", true, 503, "S_NSSAI_CONGESTION"},
		{"H-SMF 503 other", 503, "NF_CONGESTION", true, 504, "PEER_NOT_RESPONDING"},
		{"H-SMF 504", 504, "PEER_NOT_RESPONDING", true, 504, "PEER_NOT_RESPONDING"},
		{"H-SMF 502", 502, "", true, 504, "PEER_NOT_RESPONDING"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, c := mapPostSmContextsError(tc.status, tc.cause, tc.fromHSMF)
			if st != tc.wantStatus || c != tc.wantCause {
				t.Errorf("mapPostSmContextsError(%d, %q, %v) = %d %q, want %d %q",
					tc.status, tc.cause, tc.fromHSMF, st, c, tc.wantStatus, tc.wantCause)
			}
		})
	}
}

// The AMF-facing SmContextCreateError carries only PostSmContexts-allowed status/cause, and the
// UE-facing 5GSM REJECT cause is unchanged by the mapping.
func TestVSMFCreate_ErrorStatusMapping(t *testing.T) {
	respond := func(status int, body []byte) func(http.ResponseWriter, *http.Request, seppRecord) {
		return func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}
	}
	tests := []struct {
		name       string
		h          func(http.ResponseWriter, *http.Request, seppRecord)
		closeSEPP  bool
		wantStatus int
		wantCause  string
	}{
		{"SEPP 504 TARGET_NF_NOT_REACHABLE", respond(504, problemBody(504, "TARGET_NF_NOT_REACHABLE")), false, 504, "PEER_NOT_RESPONDING"},
		{"H-SMF 404 CONTEXT_NOT_FOUND", respond(404, createErrorBody(404, "CONTEXT_NOT_FOUND", "")), false, 500, "SYSTEM_FAILURE"},
		{"H-SMF 400 MANDATORY_IE_MISSING", respond(400, createErrorBody(400, "MANDATORY_IE_MISSING", "")), false, 500, "SYSTEM_FAILURE"},
		{"H-SMF 403 DNN_DENIED relayed", respond(403, createErrorBody(403, "DNN_DENIED", "1B")), false, 403, "DNN_DENIED"},
		{"H-SMF 500 slice DNN relayed", respond(500, createErrorBody(500, "INSUFFICIENT_RESOURCES_SLICE_DNN", "")), false, 500, "INSUFFICIENT_RESOURCES_SLICE_DNN"},
		{"H-SMF 503 DNN_CONGESTION relayed", respond(503, createErrorBody(503, "DNN_CONGESTION", "")), false, 503, "DNN_CONGESTION"},
		{"SEPP unreachable", respond(500, nil), true, 504, "PEER_NOT_RESPONDING"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newVSMFFixture(t, tc.h)
			if tc.closeSEPP {
				f.sepp.srv.Close()
			}
			w := f.createSMContext(t, smContextCreateData(nil))
			var body struct {
				Error struct {
					Status int    `json:"status"`
					Cause  string `json:"cause"`
				} `json:"error"`
				N1SmMsg string `json:"n1SmMsg"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("SmContextCreateError: %v: %s", err, w.Body.String())
			}
			if w.Code != tc.wantStatus || body.Error.Status != tc.wantStatus || body.Error.Cause != tc.wantCause {
				t.Errorf("answer = %d %d %q, want %d %q", w.Code, body.Error.Status, body.Error.Cause, tc.wantStatus, tc.wantCause)
			}
			if body.N1SmMsg == "" {
				t.Error("no 5GSM REJECT in n1SmMsg")
			}
		})
	}
}

func TestResolveHSMFLocation(t *testing.T) {
	const base = "https://smf.home:8004/nsmf-pdusession/v1"
	tests := []struct {
		name, loc string
		want      string // "" = refused
	}{
		{"absolute same host", "https://smf.home:8004/nsmf-pdusession/v1/pdu-sessions/ref-1", "https://smf.home:8004/nsmf-pdusession/v1/pdu-sessions/ref-1"},
		{"relative path", "/nsmf-pdusession/v1/pdu-sessions/ref-1", "https://smf.home:8004/nsmf-pdusession/v1/pdu-sessions/ref-1"},
		{"host case-insensitive", "https://SMF.HOME:8004/nsmf-pdusession/v1/pdu-sessions/ref-1", "https://SMF.HOME:8004/nsmf-pdusession/v1/pdu-sessions/ref-1"},
		{"other host", "https://evil.example/nsmf-pdusession/v1/pdu-sessions/ref-1", ""},
		{"other port", "https://smf.home:9999/nsmf-pdusession/v1/pdu-sessions/ref-1", ""},
		{"http scheme", "http://smf.home:8004/nsmf-pdusession/v1/pdu-sessions/ref-1", ""},
		{"other service path", "/nudm-sdm/v2/imsi-1/sm-data", ""},
		{"collection itself", "/nsmf-pdusession/v1/pdu-sessions/", ""},
		{"nested path", "/nsmf-pdusession/v1/pdu-sessions/ref-1/release", ""},
		{"dot-dot escape", "/nsmf-pdusession/v1/pdu-sessions/../../admin", ""},
		{"userinfo", "https://u:p@smf.home:8004/nsmf-pdusession/v1/pdu-sessions/ref-1", ""},
		{"query", "/nsmf-pdusession/v1/pdu-sessions/ref-1?x=1", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveHSMFLocation(tc.loc, base)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("resolveHSMFLocation(%q) = %q, want an error", tc.loc, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("resolveHSMFLocation(%q) = %q, %v, want %q", tc.loc, got, err, tc.want)
			}
		})
	}
}

// A 201 whose Location names another host is refused: no release is steered there, the V-UPF is
// cleaned up and the AMF gets 500 SYSTEM_FAILURE.
func TestVSMFCreate_ForeignLocationRefused(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), "https://evil.example/nsmf-pdusession/v1/pdu-sessions/ref-1"))
	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), causeSystemFailure) {
		t.Fatalf("answer = %d %s", w.Code, w.Body.String())
	}
	if _, _, del := f.upf.counts(); del != 1 {
		t.Errorf("V-UPF deletions = %d, want 1", del)
	}
	if f.sessionCount() != 0 {
		t.Errorf("session left behind: %d", f.sessionCount())
	}
	for _, r := range f.sepp.records() {
		if strings.HasSuffix(r.Path, "/release") {
			t.Errorf("release sent to %s despite the refused Location", r.Header.Get("3gpp-Sbi-Target-apiRoot"))
		}
	}
}

func TestHSMFCreate_LocationIsAbsolute(t *testing.T) {
	tests := []struct {
		name, fqdn, addr, wantPrefix string
	}{
		{"fqdn + port", "smf.5gc.mnc002.mcc001.3gppnetwork.org", "0.0.0.0:8004", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004/nsmf-pdusession/v1/pdu-sessions/"},
		{"fqdn without port", "smf.5gc.mnc002.mcc001.3gppnetwork.org", "", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org/nsmf-pdusession/v1/pdu-sessions/"},
		{"request host", "", "0.0.0.0:8004", "https://example.com/nsmf-pdusession/v1/pdu-sessions/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newHRFixture(t, udmSubscribed)
			f.s.cfg.SBI.FQDN, f.s.cfg.SBI.Address = tc.fqdn, tc.addr
			w := f.post(t, validCreateData(), nil)
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, tc.wantPrefix) {
				t.Errorf("Location = %q, want prefix %q", loc, tc.wantPrefix)
			}
		})
	}
}

func TestHSMFCreate_SupiOfAnotherPLMN(t *testing.T) {
	f := newHRFixture(t, udmSubscribed)
	f.s.cfg.PLMN.MCC, f.s.cfg.PLMN.MNC = "001", "02"
	for name, tc := range map[string]struct {
		supi string
		want int
	}{
		"home PLMN":    {"imsi-001020000000001", http.StatusCreated},
		"foreign IMSI": {"imsi-310260000000001", http.StatusForbidden},
		"non-IMSI":     {"nai-user@example.com", http.StatusCreated},
	} {
		t.Run(name, func(t *testing.T) {
			d := validCreateData()
			d["supi"] = tc.supi
			d["pduSessionId"] = 7 + len(tc.supi)%5 // distinct per subtest, 1..15
			w := f.post(t, d, nil)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusForbidden {
				if e := decodeCreateError(t, w); e.Error.Cause != causeSubscriptionDenied {
					t.Errorf("cause = %q, want %q", e.Error.Cause, causeSubscriptionDenied)
				}
			}
		})
	}
	if est := f.upf.establishments(); len(est) != 2 {
		t.Errorf("H-UPF establishments = %d, want 2 (the foreign IMSI must not reach N4)", len(est))
	}
}

func TestHSMFRelease_OriginatingPLMN(t *testing.T) {
	f := newHRFixture(t, udmSubscribed)
	create := func(psi int) string {
		d := validCreateData()
		d["pduSessionId"] = psi
		w := f.post(t, d, nil)
		if w.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", w.Code, w.Body.String())
		}
		return refFromLocation(w.Header().Get("Location"))
	}
	rel := func(ref, nid string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/pdu-sessions/"+ref+"/release", strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		if nid != "" {
			r.Header.Set(hdrOriginatingNetworkID, nid)
		}
		r.SetPathValue("pduSessionRef", ref)
		w := httptest.NewRecorder()
		f.s.handleHsmfReleasePduSession(w, r)
		return w
	}
	ref := create(5)
	// D/#17: a missing header is 403 MISSING_PARAMETER (TS 29.500 Table 5.2.7.2-1); a foreign or own-PLMN
	// originating network is 404 CONTEXT_NOT_FOUND with the body of an unknown ref (no existence oracle).
	// Neither reaches the H-UPF.
	f.s.cfg.PLMN.MCC, f.s.cfg.PLMN.MNC = "001", "02" // the H-SMF's own PLMN (the session came from 001-01)
	unknown := rel("no-such-ref", "001-01")
	for name, c := range map[string]struct {
		nid    string
		status int
		cause  string
	}{
		"missing":  {"", http.StatusForbidden, causeMissingParameter},
		"foreign":  {"310-260", http.StatusNotFound, causeContextNotFound},
		"own PLMN": {"001-02", http.StatusNotFound, causeContextNotFound},
	} {
		w := rel(ref, c.nid)
		if w.Code != c.status || !strings.Contains(w.Body.String(), c.cause) || strings.Contains(w.Body.String(), causePLMNIDMismatch) {
			t.Fatalf("%s release = %d %s, want %d %s", name, w.Code, w.Body.String(), c.status, c.cause)
		}
		if c.status == http.StatusNotFound && w.Body.String() != unknown.Body.String() {
			t.Errorf("%s release body %q differs from the unknown-ref body %q (existence oracle)", name, w.Body.String(), unknown.Body.String())
		}
	}
	if f.upf.deletionCount() != 0 {
		t.Error("refused release reached the H-UPF")
	}
	for _, nid := range []string{"001-01", "001-01-000007ed9d5", "001-01; src: SEPP-sepp.example.org"} {
		ref := create(6)
		if w := rel(ref, nid); w.Code != http.StatusNoContent {
			t.Errorf("release with Originating-Network-Id %q = %d, want 204", nid, w.Code)
		}
	}
	// The original session is still there and the right PLMN releases it.
	if w := rel(ref, "001-01"); w.Code != http.StatusNoContent {
		t.Errorf("release = %d, want 204", w.Code)
	}
}

// TestHSMFCreate_OriginatingNetworkID: the header is mandatory, must equal servingNetwork and must not
// be the H-SMF's own PLMN (TS 29.500 §5.2.3.2.15); nothing is allocated or sent to the H-UPF.
func TestHSMFCreate_OriginatingNetworkID(t *testing.T) {
	f := newHRFixture(t, udmSubscribed)
	f.s.cfg.PLMN.MCC, f.s.cfg.PLMN.MNC = "001", "02"
	for name, tc := range map[string]struct {
		nid  string
		want int
	}{
		"missing":                 {"", http.StatusForbidden},
		"other PLMN than serving": {"310-260", http.StatusForbidden},
		"matches servingNetwork":  {"001-01", http.StatusCreated},
	} {
		t.Run(name, func(t *testing.T) {
			w := f.postNID(t, validCreateData(), nil, tc.nid)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusForbidden {
				if e := decodeCreateError(t, w); e.Error.Cause != causeOriginNotAllowed {
					t.Errorf("cause = %q", e.Error.Cause)
				}
			}
		})
	}
	t.Run("own PLMN", func(t *testing.T) {
		d := validCreateData()
		d["servingNetwork"] = map[string]any{"mcc": "001", "mnc": "02"}
		if w := f.postNID(t, d, nil, "001-02"); w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: %s", w.Code, w.Body.String())
		}
	})
	if est := f.upf.establishments(); len(est) != 1 {
		t.Errorf("H-UPF establishments = %d, want 1 (only the matching request)", len(est))
	}
}

func TestHSMFBodyLimits(t *testing.T) {
	f := newHRFixture(t, udmSubscribed)
	post := func(ct string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/pdu-sessions", bytes.NewReader(body))
		r.Header.Set("Content-Type", ct)
		w := httptest.NewRecorder()
		f.s.handleHsmfCreatePduSession(w, r)
		return w
	}
	t.Run("oversize JSON", func(t *testing.T) {
		big := []byte(`{"dnn":"` + strings.Repeat("a", maxHRRequestBody+10) + `"}`)
		w := post("application/json", big)
		if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), causeMaxJSONSizeExceeded) {
			t.Fatalf("got %d %s, want 413 %s", w.Code, w.Body.String(), causeMaxJSONSizeExceeded)
		}
	})
	t.Run("too many multipart parts", func(t *testing.T) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for i := 0; i <= maxHRMultipartParts; i++ {
			p, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json"}})
			_, _ = p.Write([]byte(`{}`))
		}
		_ = mw.Close()
		w := post(`multipart/related; boundary=`+mw.Boundary(), buf.Bytes())
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("got %d %s, want 413", w.Code, w.Body.String())
		}
	})
	t.Run("oversize release body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/pdu-sessions/x/release",
			strings.NewReader(`{"cause":"`+strings.Repeat("a", maxHRRequestBody+10)+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.SetPathValue("pduSessionRef", "x")
		w := httptest.NewRecorder()
		f.s.handleHsmfReleasePduSession(w, r)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("got %d %s, want 413", w.Code, w.Body.String())
		}
	})
	t.Run("part at the limit parses", func(t *testing.T) {
		if _, err := readHRBody("application/json", strings.NewReader(`{"a":"`+strings.Repeat("b", 1000)+`"}`)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSplitN1SmInfoFromUe(t *testing.T) {
	tests := []struct {
		name         string
		in           string // hex
		known, unkwn string
	}{
		{"type and ssc only", "91a1", "91a1", ""},
		{"unknown TLV after known", "91a1 3e02aabb", "91a1", "3e02aabb"},
		{"unknown type 1 between known", "91 c5 a1", "91a1", "c5"},
		{"known TLV-E EPCO kept", "7b0003010203 91", "7b000301020391", ""},
		{"unknown TLV-E", "91 780002aabb a1", "91a1", "780002aabb"},
		{"known 5GSM capability TLV", "280101 91", "28010191", ""},
		{"known TV 0x55", "55 0010 91", "55001091", ""},
		{"truncated tail forwarded as known", "91 3e05aa", "913e05aa", ""},
		{"empty", "", "", ""},
		{"always-on IE dropped from both parts", "91 b1 a1 3e02aabb b0", "91a1", "3e02aabb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := mustHex(t, tc.in)
			k, u := splitN1SmInfoFromUe(in)
			if got := hexOf(k); got != strings.ReplaceAll(tc.known, " ", "") {
				t.Errorf("known = %s, want %s", got, tc.known)
			}
			if got := hexOf(u); got != strings.ReplaceAll(tc.unkwn, " ", "") {
				t.Errorf("unknown = %s, want %s", got, tc.unkwn)
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// The V-SMF forwards IEs it does not comprehend in a separate unknownN1SmInfo part.
func TestVSMFCreate_UnknownN1SmInfoPart(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	n1 := append(n1EstRequest(), 0x3E, 0x02, 0xAA, 0xBB) // unknown TLV IE 0x3E after PDU session type + SSC mode
	w := f.createSMContext(t, smContextCreateData(func(m map[string]any) {
		m["n1SmMsg"] = base64.StdEncoding.EncodeToString(n1)
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	rq := f.sepp.records()[0]
	mp, err := readHRBody(rq.ContentType, bytes.NewReader(rq.Body))
	if err != nil {
		t.Fatal(err)
	}
	var data PduSessionCreateData
	if err := json.Unmarshal(mp.JSON, &data); err != nil {
		t.Fatal(err)
	}
	if data.N1SmInfoFromUe == nil || !bytes.Equal(mp.Parts[data.N1SmInfoFromUe.ContentID], []byte{0x91, 0xA1}) {
		t.Errorf("n1SmInfoFromUe = %+v parts=%v", data.N1SmInfoFromUe, mp.Parts)
	}
	if data.UnknownN1SmInfo == nil || !bytes.Equal(mp.Parts[data.UnknownN1SmInfo.ContentID], []byte{0x3E, 0x02, 0xAA, 0xBB}) {
		t.Errorf("unknownN1SmInfo = %+v parts=%v", data.UnknownN1SmInfo, mp.Parts)
	}
	if missing, incorrect := validatePduSessionCreateData(&data); len(missing)+len(incorrect) > 0 {
		t.Errorf("H-SMF validation: missing=%v incorrect=%v", missing, incorrect)
	}
}

// Readers that follow the package locking rule (sessionMu) run while both HR roles establish and
// release sessions; under -race any unlocked write to a published Session / HRSession is reported.
func TestHRSessionsConcurrentAccess(t *testing.T) {
	home := newHRFixture(t, udmSubscribed)
	home.s.cfg.SBI.Address, home.s.cfg.SBI.FQDN = ":8004", "smf.5gc.mnc002.mcc001.3gppnetwork.org"
	f := newVSMFFixture(t, func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
		home.s.httpSrv.Handler.ServeHTTP(w, r)
	})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, s := range []*Server{f.s, home.s} {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s.sessionMu.Lock()
				for _, sess := range s.sessions {
					_ = sess.State
					_ = sess.FiveQI
					_ = sess.AMBRDLKbps
					_ = sess.PDUSessionType
					_ = sess.N4Stale
					if sess.HR != nil {
						_ = sess.HR.PeerTunnel
						_ = sess.HR.HSmfPduSessionRef
						_ = sess.HR.UEIPv4
					}
				}
				s.sessionMu.Unlock()
			}
		}(s)
	}
	for i := 0; i < 3; i++ {
		w := f.createSMContext(t, smContextCreateData(nil))
		if w.Code != http.StatusCreated {
			t.Fatalf("create %d: %d %s", i, w.Code, w.Body.String())
		}
		resp, _, _ := decodeCreateResp(t, w)
		if d := f.deleteSMContext(resp.SMContextRef); d.Code != http.StatusNoContent {
			t.Fatalf("release %d: %d", i, d.Code)
		}
	}
	close(stop)
	wg.Wait()
}

func TestSplitN1SmInfo_AlwaysOn(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{{"91a1", false}, {"91 b1 a1", true}, {"91 b0", false}} {
		if _, _, got := splitN1SmInfo(mustHex(t, tc.in)); got != tc.want {
			t.Errorf("%s: alwaysOn = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// The Always-on PDU session requested IE becomes alwaysOnRequested and is not in n1SmInfoFromUe.
func TestVSMFCreate_AlwaysOnRequested(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	n1 := append(n1EstRequest(), 0xB1)
	w := f.createSMContext(t, smContextCreateData(func(m map[string]any) {
		m["n1SmMsg"] = base64.StdEncoding.EncodeToString(n1)
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	rq := f.sepp.records()[0]
	mp, err := readHRBody(rq.ContentType, bytes.NewReader(rq.Body))
	if err != nil {
		t.Fatal(err)
	}
	var data PduSessionCreateData
	if err := json.Unmarshal(mp.JSON, &data); err != nil {
		t.Fatal(err)
	}
	if !data.AlwaysOnRequested {
		t.Error("alwaysOnRequested not set")
	}
	if data.N1SmInfoFromUe == nil || !bytes.Equal(mp.Parts[data.N1SmInfoFromUe.ContentID], []byte{0x91, 0xA1}) {
		t.Errorf("n1SmInfoFromUe = %+v parts=%v, want 91A1 without B1", data.N1SmInfoFromUe, mp.Parts)
	}
}
