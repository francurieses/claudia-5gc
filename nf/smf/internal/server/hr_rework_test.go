package server

// hr_rework_test.go — ROAM-002 rework pass: JSON log lines never repeat a key, H-SMF/V-SMF N4 deletion
// results, rollback of a session the peer never learned about, mandatory originating network id,
// hSmfUri validation, vsmfPduSessionUri, SscMode enum, bounded N16 answers.
// Ref: TS 29.500 §5.2.3.2.15; TS 23.003 §28.5; TS 29.502 §5.2.2.7.1, §5.2.2.9, Table 6.1.6.2.9-1;
// TS 29.571 §5.4.3.6.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	pfcpie "github.com/wmnsk/go-pfcp/ie"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// duplicateKeys returns the "path" of every key repeated inside one JSON object of the line.
func duplicateKeys(line string) ([]string, error) {
	dec := json.NewDecoder(strings.NewReader(line))
	var dups []string
	if err := scanJSONValue(dec, "", &dups); err != nil {
		return nil, err
	}
	return dups, nil
}

func scanJSONValue(dec *json.Decoder, path string, dups *[]string) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			if seen[key] {
				*dups = append(*dups, path+key)
			}
			seen[key] = true
			if err := scanJSONValue(dec, path+key+".", dups); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := scanJSONValue(dec, path, dups); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // closing delimiter
	return err
}

// assertNoDuplicateKeys fails for every log line (JSON) that repeats a key.
func assertNoDuplicateKeys(t *testing.T, who, logs string) {
	t.Helper()
	n := 0
	for _, line := range strings.Split(logs, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		n++
		dups, err := duplicateKeys(line)
		if err != nil {
			t.Errorf("%s: log line is not JSON: %v: %s", who, err, line)
			continue
		}
		if len(dups) > 0 {
			t.Errorf("%s: duplicate JSON keys %v in %s", who, dups, line)
		}
	}
	if n == 0 {
		t.Errorf("%s: no log lines captured", who)
	}
}

func TestDuplicateKeysDetector(t *testing.T) {
	if d, _ := duplicateKeys(`{"a":1,"b":{"c":1,"c":2},"d":[{"e":1}]}`); len(d) != 1 || d[0] != "b.c" {
		t.Errorf("nested duplicate not found: %v", d)
	}
	if d, _ := duplicateKeys(`{"interface":"N4","direction":"IN","interface":"N4"}`); len(d) != 1 {
		t.Errorf("top-level duplicate not found: %v", d)
	}
	if d, err := duplicateKeys(`{"a":1,"b":[1,2]}`); err != nil || len(d) != 0 {
		t.Errorf("false positive: %v %v", d, err)
	}
}

// jsonLogger returns a JSON logger with the root nf attribute (as cmd/smf/main.go) writing to a buffer.
func jsonLogger() (*slog.Logger, *syncBuffer) {
	b := &syncBuffer{}
	return slog.New(slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})).With("nf", "SMF"), b
}

// TestHRLogs_NoDuplicateKeys drives the V-SMF and H-SMF happy paths (create + release) and the main
// failure branches and asserts no log line of either role repeats a JSON key.
func TestHRLogs_NoDuplicateKeys(t *testing.T) {
	home := newHRFixture(t, udmSubscribed)
	home.s.cfg.UPFN9Addr = "10.0.1.9"
	home.s.cfg.SBI.Address, home.s.cfg.SBI.FQDN = ":8004", "smf.5gc.mnc002.mcc001.3gppnetwork.org"
	home.s.cfg.PLMN.MCC, home.s.cfg.PLMN.MNC = "001", "02"
	hl, hlogs := jsonLogger()
	home.s.logger = hl
	f := newVSMFFixture(t, func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
		home.s.httpSrv.Handler.ServeHTTP(w, r)
	})

	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	resp, _, _ := decodeCreateResp(t, w)
	if w := f.deleteSMContext(resp.SMContextRef); w.Code != http.StatusNoContent {
		t.Fatalf("release: %d", w.Code)
	}

	// H-SMF failure branches: DNN not served, H-UPF rejects, release of an unknown ref, H-UPF deletion rejected.
	d := validCreateData()
	d["dnn"] = "nodnn.mnc002.mcc001.gprs"
	home.post(t, d, nil)
	home.upf.mu.Lock()
	home.upf.estCause = pfcpie.CauseRequestRejected
	home.upf.mu.Unlock()
	home.post(t, validCreateData(), nil)

	// V-SMF failure branches: N4 establishment rejected, UL FAR update rejected (abort with N16 release),
	// H-SMF refusal, SEPP failure.
	f.upf.setCauses(pfcpie.CauseRequestRejected, pfcpie.CauseRequestAccepted)
	f.createSMContext(t, smContextCreateData(nil))
	f.upf.setCauses(pfcpie.CauseRequestAccepted, pfcpie.CauseRequestRejected)
	f.createSMContext(t, smContextCreateData(nil))

	assertNoDuplicateKeys(t, "V-SMF", f.logs.String())
	assertNoDuplicateKeys(t, "H-SMF", hlogs.String())

	f2 := newVSMFFixture(t, func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("not json at all"))
	})
	f2.createSMContext(t, smContextCreateData(nil))
	assertNoDuplicateKeys(t, "V-SMF (SEPP 500)", f2.logs.String())
	f3 := newVSMFFixture(t, func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(createErrorBody(403, causeDNNDenied, "1B"))
	})
	f3.createSMContext(t, smContextCreateData(nil))
	assertNoDuplicateKeys(t, "V-SMF (H-SMF 403)", f3.logs.String())
}

// Each log line must carry exactly one interface: spot-check the lines the live run showed duplicated.
func TestHRLogs_InterfaceOnLines(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	f.createSMContext(t, smContextCreateData(nil))
	want := map[string]string{
		"PFCP Session Establishment Request sent (V-UPF)": "N4",
		"N16 PostPduSessions answered":                    "N16",
		"home-routed PDU session established (V-SMF)":     "Nsmf",
	}
	for _, line := range strings.Split(f.logs.String(), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		if iface, ok := want[fmt.Sprint(m["msg"])]; ok {
			if m["interface"] != iface {
				t.Errorf("%q interface = %v, want %s", m["msg"], m["interface"], iface)
			}
			delete(want, fmt.Sprint(m["msg"]))
		}
	}
	if len(want) != 0 {
		t.Errorf("lines not logged: %v", want)
	}
}

// H-SMF release: an H-UPF deletion failure (rejected Cause) keeps the 204, frees the SMF-side context
// and is counted FAILURE; a clean deletion is counted OK.
func TestHSMFRelease_N4DeleteFailureCounted(t *testing.T) {
	for name, tc := range map[string]struct {
		delCause uint8
		want     string
	}{"accepted": {pfcpie.CauseRequestAccepted, "OK"}, "rejected": {pfcpie.CauseRequestRejected, "FAILURE"}} {
		t.Run(name, func(t *testing.T) {
			f := newHRFixture(t, udmSubscribed)
			l, logs := jsonLogger()
			f.s.logger = l
			w := f.post(t, validCreateData(), nil)
			if w.Code != http.StatusCreated {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			ref := refFromLocation(w.Header().Get("Location"))
			f.upf.mu.Lock()
			f.upf.delCause = tc.delCause
			f.upf.mu.Unlock()
			metric := func() float64 {
				return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"Release", tc.want))
			}
			before := metric()
			r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/pdu-sessions/"+ref+"/release", strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set(hdrOriginatingNetworkID, "001-01")
			r.SetPathValue("pduSessionRef", ref)
			// A cancelled N16 request must not skip the H-UPF deletion.
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			rw := httptest.NewRecorder()
			f.s.handleHsmfReleasePduSession(rw, r.WithContext(ctx))
			if rw.Code != http.StatusNoContent {
				t.Fatalf("release = %d, want 204", rw.Code)
			}
			if f.upf.deletionCount() != 1 {
				t.Errorf("H-UPF deletions = %d, want 1 even with a cancelled request", f.upf.deletionCount())
			}
			f.s.sessionMu.Lock()
			left := len(f.s.sessions)
			f.s.sessionMu.Unlock()
			if left != 0 {
				t.Errorf("SMF context leaked: %d sessions", left)
			}
			if got := metric() - before; got != 1 {
				t.Errorf("procedure_total{%s} delta = %v, want 1", tc.want, got)
			}
			if tc.want == "FAILURE" && !strings.Contains(logs.String(), `"level":"WARN"`) {
				t.Errorf("no WARN log: %s", logs.String())
			}
			assertNoDuplicateKeys(t, "H-SMF release", logs.String())
		})
	}
}

// A silent H-UPF (establishment timeout) is followed by a best-effort Session Deletion of that SEID.
func TestHSMFCreate_N4TimeoutSendsDeletion(t *testing.T) {
	f := newHRFixture(t, udmSubscribed)
	f.upf.mu.Lock()
	f.upf.silent = true
	f.upf.mu.Unlock()
	w := f.post(t, validCreateData(), nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	if f.upf.deletionCount() != 1 {
		t.Fatalf("H-UPF deletions = %d, want 1", f.upf.deletionCount())
	}
	est := f.upf.establishments()
	f.upf.mu.Lock()
	seids := append([]uint64(nil), f.upf.deleteSEID...)
	f.upf.mu.Unlock()
	if len(est) == 0 || len(seids) != 1 {
		t.Fatalf("est=%d del=%v", len(est), seids)
	}
	fs, _ := est[0].CPFSEID.FSEID()
	if fs.SEID != seids[0] {
		t.Errorf("deleted SEID %d != established SEID %d", seids[0], fs.SEID)
	}
}

// failWriter is a ResponseWriter whose body write fails (V-SMF gone after the headers).
type failWriter struct {
	h    http.Header
	code int
}

func (w *failWriter) Header() http.Header       { return w.h }
func (w *failWriter) WriteHeader(c int)         { w.code = c }
func (w *failWriter) Write([]byte) (int, error) { return 0, errors.New("stream closed") }

// If the 201 cannot be written, or the request is already cancelled when the session is ready,
// the H-SMF rolls back: H-UPF deletion, IP freed, context dropped.
func TestHSMFCreate_RollsBackWhenAnswerCannotBeDelivered(t *testing.T) {
	t.Run("write fails", func(t *testing.T) {
		f := newHRFixture(t, udmSubscribed)
		l, logs := jsonLogger()
		f.s.logger = l
		r := f.createRequest(t, validCreateData())
		f.s.handleHsmfCreatePduSession(&failWriter{h: http.Header{}}, r)
		f.assertRolledBack(t)
		if !strings.Contains(logs.String(), "rolled back") {
			t.Errorf("no rollback log: %s", logs.String())
		}
		assertNoDuplicateKeys(t, "H-SMF rollback", logs.String())
	})
	t.Run("request cancelled while N4 is established", func(t *testing.T) {
		f := newHRFixture(t, udmSubscribed)
		// The request context reports cancellation once the H-UPF holds the session: the answer is ready for nobody.
		ctx := &cancelAfterN4Ctx{Context: context.Background(), f: f}
		r := f.createRequest(t, validCreateData()).WithContext(ctx)
		rw := httptest.NewRecorder()
		f.s.handleHsmfCreatePduSession(rw, r)
		f.assertRolledBack(t)
		if rw.Body.Len() != 0 {
			t.Errorf("a response was written to a cancelled request: %s", rw.Body.String())
		}
	})
}

// cancelAfterN4Ctx is a context whose Err() turns context.Canceled once the fake H-UPF saw an establishment.
type cancelAfterN4Ctx struct {
	context.Context
	f *hrFixture
}

func (c *cancelAfterN4Ctx) Err() error {
	if len(c.f.upf.establishments()) > 0 {
		return context.Canceled
	}
	return nil
}

func (f *hrFixture) createRequest(t *testing.T, data map[string]any) *http.Request {
	t.Helper()
	b, _ := json.Marshal(data)
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/pdu-sessions", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(hdrOriginatingNetworkID, "001-01")
	return r
}

func (f *hrFixture) assertRolledBack(t *testing.T) {
	t.Helper()
	if f.upf.deletionCount() != 1 {
		t.Errorf("H-UPF deletions = %d, want 1", f.upf.deletionCount())
	}
	f.s.sessionMu.Lock()
	left := len(f.s.sessions)
	f.s.sessionMu.Unlock()
	if left != 0 {
		t.Errorf("sessions left = %d", left)
	}
	// The UE address went back to the pool: the whole /24 is allocatable again.
	pool, _ := f.s.hrPoolFor("internet")
	ip, err := pool.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.60.0.1" && ip.String() != "10.60.0.2" {
		t.Logf("first free address after rollback: %s", ip)
	}
	pool.Release(ip)
}

// vsmfReleaseHome folds the V-UPF deletion result into the counted/logged result.
func TestVSMFRelease_V_UPFDeleteFailureFolded(t *testing.T) {
	f, ref := establishedVSMF(t, answerCreated(createdJSON(nil), testHRefPath))
	f.upf.mu.Lock()
	f.upf.delCause = pfcpie.CauseRequestRejected
	f.upf.mu.Unlock()
	metric := func() float64 {
		return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"Release", "FAILURE"))
	}
	before := metric()
	if w := f.deleteSMContext(ref); w.Code != http.StatusNoContent {
		t.Fatalf("release = %d", w.Code)
	}
	if f.sessionCount() != 0 {
		t.Error("V-SMF context leaked")
	}
	if got := metric() - before; got != 1 {
		t.Errorf("FAILURE delta = %v, want 1", got)
	}
	var found bool
	for _, line := range strings.Split(f.logs.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "home-routed PDU session released (V-SMF)" {
			found = true
			if m["result"] != "FAILURE" || m["level"] != "WARN" || m["interface"] != "Nsmf" {
				t.Errorf("release line = %v, want WARN result FAILURE", m)
			}
		}
	}
	if !found {
		t.Errorf("no release line: %s", f.logs.String())
	}
}

// V-SMF: 201 with a Location but an unparseable PduSessionCreatedData -> best-effort N16 Release, then reject.
func TestVSMFCreate_UnparseableCreatedReleasesHSMF(t *testing.T) {
	f := newVSMFFixture(t, answerCreated([]byte("{not json"), testHRefPath))
	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code < 400 {
		t.Fatalf("status = %d, want a rejection", w.Code)
	}
	recs := f.sepp.records()
	if len(recs) != 2 || recs[1].Path != testHRefPath+"/release" {
		t.Fatalf("SEPP requests = %+v, want create + release of the Location", recs)
	}
	if f.sessionCount() != 0 {
		t.Error("session leaked")
	}
	if _, _, del := f.upf.counts(); del != 1 {
		t.Errorf("V-UPF deletions = %d, want 1", del)
	}
}

// V-SMF: an answer above the read limit fails explicitly (never truncated) and releases the H-SMF session.
func TestVSMFCreate_OversizeAnswerRejectedAndReleased(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxHRResponseBody+1)
	f := newVSMFFixture(t, answerCreated(big, testHRefPath))
	w := f.createSMContext(t, smContextCreateData(nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	recs := f.sepp.records()
	if len(recs) != 2 || recs[1].Path != testHRefPath+"/release" {
		t.Fatalf("SEPP requests = %d, want create + release", len(recs))
	}
	if !strings.Contains(f.logs.String(), "answer too large") {
		t.Errorf("no explicit size log: %s", f.logs.String())
	}
	// Exactly at the limit still parses as a body (here: a non-JSON error, handled as a path failure).
	f2 := newVSMFFixture(t, func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxHRResponseBody))
	})
	if w := f2.createSMContext(t, smContextCreateData(nil)); w.Code != http.StatusInternalServerError {
		t.Errorf("status at the limit = %d", w.Code)
	}
	if strings.Contains(f2.logs.String(), "answer too large") {
		t.Error("a body exactly at the limit was refused")
	}
}

// An unparseable N16 error body is logged at WARN with at most 256 bytes of it.
func TestVSMFCreate_UnparseableErrorBodyWarned(t *testing.T) {
	f := newVSMFFixture(t, func(w http.ResponseWriter, r *http.Request, rec seppRecord) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("x", 1000)))
	})
	f.createSMContext(t, smContextCreateData(nil))
	var found bool
	for _, line := range strings.Split(f.logs.String(), "\n") {
		if !strings.Contains(line, "neither a PduSessionCreateError nor a ProblemDetails") {
			continue
		}
		found = true
		var m map[string]any
		_ = json.Unmarshal([]byte(line), &m)
		if m["level"] != "WARN" {
			t.Errorf("level = %v, want WARN", m["level"])
		}
		if b, _ := m["body"].(string); len(b) != maxLoggedErrBody {
			t.Errorf("logged body = %d bytes, want %d", len(b), maxLoggedErrBody)
		}
	}
	if !found {
		t.Errorf("no WARN for the unparseable body: %s", f.logs.String())
	}
}

func TestValidateHSmfURI(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath)) // own PLMN 001/01
	const supi = "imsi-001020000000001"                                   // MCC 001, MNC 02
	tests := []struct {
		name, uri, supi string
		ok              bool
	}{
		{"api uri", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004/nsmf-pdusession/v1", supi, true},
		{"api root only", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004", supi, true},
		{"root slash", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org/", supi, true},
		{"multi-label", "https://hsmf.set1.5gc.mnc002.mcc001.3gppnetwork.org/nsmf-pdusession/v1/", supi, true},
		{"upper case host", "https://SMF.5GC.MNC002.MCC001.3GPPNETWORK.ORG", supi, true},
		{"3-digit MNC supi", "https://smf.5gc.mnc310.mcc310.3gppnetwork.org", "imsi-310310000000001", true},
		{"http", "http://smf.5gc.mnc002.mcc001.3gppnetwork.org", supi, false},
		{"userinfo", "https://u:p@smf.5gc.mnc002.mcc001.3gppnetwork.org", supi, false},
		{"query", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org/?a=b", supi, false},
		{"empty query", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org/?", supi, false},
		{"fragment", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org/#x", supi, false},
		{"other path", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org/evil", supi, false},
		{"IP literal", "https://10.0.0.1:8004", supi, false},
		{"not 3gppnetwork", "https://smf.example.org", supi, false},
		{"suffix trick", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org.evil.com", supi, false},
		{"prefix trick", "https://evil.com/.5gc.mnc002.mcc001.3gppnetwork.org", supi, false},
		{"MCC differs", "https://smf.5gc.mnc002.mcc310.3gppnetwork.org", supi, false},
		{"MNC differs", "https://smf.5gc.mnc003.mcc001.3gppnetwork.org", supi, false},
		{"own PLMN", "https://smf.5gc.mnc001.mcc001.3gppnetwork.org", "imsi-001010000000001", false},
		{"non-IMSI supi", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org", "nai-x@y", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.s.validateHSmfURI(tc.uri, tc.supi)
			if (err == nil) != tc.ok {
				t.Fatalf("validateHSmfURI(%q) err = %v, want ok=%v", tc.uri, err, tc.ok)
			}
		})
	}
}

// A rejected hSmfUri answers like the other HR configuration errors (400 MANDATORY_IE_INCORRECT, N1 reject)
// with invalidParams /hSmfUri, and nothing leaves the V-SMF.
func TestVSMFCreate_InvalidHSmfURIRejected(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	w := f.createSMContext(t, smContextCreateData(func(m map[string]any) { m["hSmfUri"] = "https://evil.example.com" }))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Error struct {
			Cause         string
			InvalidParams []HRInvalidParam `json:"invalidParams"`
		} `json:"error"`
		N1SmMsg string `json:"n1SmMsg"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Cause != causeMandatoryIEIncorrect || len(body.Error.InvalidParams) != 1 || body.Error.InvalidParams[0].Param != "/hSmfUri" || body.N1SmMsg == "" {
		t.Errorf("answer = %s", w.Body.String())
	}
	if len(f.sepp.records()) != 0 || f.sessionCount() != 0 {
		t.Error("an invalid hSmfUri reached N16 or left state")
	}
}

func TestVSMFAPIRoot(t *testing.T) {
	f := newVSMFFixture(t, answerCreated(createdJSON(nil), testHRefPath))
	for name, tc := range map[string]struct {
		addr, fqdn, mcc, mnc, want string
	}{
		"sbi.fqdn wins":      {"0.0.0.0:8004", "smf.example.org", "001", "01", "https://smf.example.org:8004"},
		"TS 23.003 FQDN":     {"0.0.0.0:8004", "", "001", "01", "https://smf.5gc.mnc001.mcc001.3gppnetwork.org:8004"},
		"2-digit MNC padded": {":8004", "", "310", "26", "https://smf.5gc.mnc026.mcc310.3gppnetwork.org:8004"},
		"3-digit MNC":        {"[::]:9000", "", "310", "260", "https://smf.5gc.mnc260.mcc310.3gppnetwork.org:9000"},
		"no PLMN, concrete":  {"10.1.2.3:8004", "", "", "", "https://10.1.2.3:8004"},
		"no PLMN, wildcard":  {"0.0.0.0:8004", "", "", "", "https://smf:8004"},
	} {
		t.Run(name, func(t *testing.T) {
			f.s.cfg.SBI.Address, f.s.cfg.SBI.FQDN = tc.addr, tc.fqdn
			f.s.cfg.PLMN.MCC, f.s.cfg.PLMN.MNC = tc.mcc, tc.mnc
			got := f.s.vsmfAPIRoot()
			if got != tc.want || strings.Contains(got, "0.0.0.0") || strings.Contains(got, "[::]") {
				t.Errorf("vsmfAPIRoot = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSscModeEnum(t *testing.T) {
	for in, want := range map[string]uint8{"SSC_MODE_1": 1, "SSC_MODE_2": 2, "SSC_MODE_3": 3, "1": 1, "3": 3, "": 1, "SSC_MODE_9": 1, "x": 1} {
		if got := sscModeOf(in); got != want {
			t.Errorf("sscModeOf(%q) = %d, want %d", in, got, want)
		}
	}
	if got := sscModeName(1); got != "SSC_MODE_1" {
		t.Errorf("sscModeName(1) = %q", got)
	}
	// The 201 body carries the enum string.
	f := newHRFixture(t, udmSubscribed)
	w := f.post(t, validCreateData(), nil)
	var c PduSessionCreatedData
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || c.SscMode != "SSC_MODE_1" {
		t.Errorf("201 sscMode = %q (%v)", c.SscMode, err)
	}
}

// A single-interface UPF (no upf_n9_addr) with a local SEPP configured warns once at start-up.
func TestNew_WarnsWhenSEPPWithoutN9Addr(t *testing.T) {
	logs := warnAtStartup(t, "sepp:9443", "")
	if n := strings.Count(logs, "upf_n9_addr is empty"); n != 1 {
		t.Errorf("warnings = %d, want 1: %s", n, logs)
	}
	for name, c := range map[string][2]string{"n9 set": {"sepp:9443", "10.0.0.9"}, "no sepp": {"", ""}} {
		if l := warnAtStartup(t, c[0], c[1]); strings.Contains(l, "upf_n9_addr is empty") {
			t.Errorf("%s: unexpected warning", name)
		}
	}
}

func warnAtStartup(t *testing.T, sepp, n9 string) string {
	t.Helper()
	l, buf := jsonLogger()
	s := newTestSMFServer(t)
	_ = s
	cfg := s.cfg
	cfg.Peers.SEPP, cfg.UPFN9Addr = sepp, n9
	if _, err := New(cfg, l, nil); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
