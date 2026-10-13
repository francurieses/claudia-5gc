package mgmt

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/free5gc/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
)

type fakeUEs map[string]*amfctx.UEContext

func (f fakeUEs) GetBySUPI(s string) (*amfctx.UEContext, bool) { u, ok := f[s]; return u, ok }

type fakeRel struct {
	assoc      bool
	dropAtSend bool // association vanishes between HasN2Association and the send
	err        error
	calls      int
	gotPres    int
	gotCause   int64
}

func (f *fakeRel) HasN2Association(*amfctx.UEContext) bool { return f.assoc }
func (f *fakeRel) SendUEContextReleaseCommandForUEStrict(_ *amfctx.UEContext, p int, c int64) error {
	f.calls++
	if f.dropAtSend {
		return ngap.ErrNoN2Association
	}
	f.gotPres, f.gotCause = p, c
	return f.err
}

const testSUPI = "imsi-001010000000001"

func testUE(cm amfctx.CMState, pending bool) *amfctx.UEContext {
	return &amfctx.UEContext{
		SUPI: testSUPI, CMState: cm, PendingRemoval: pending,
		AMFUENGAPId: 7, RANUENGAPId: 9,
		PDUSessions: map[uint8]*amfctx.PDUSession{2: {PDUSessionID: 2}, 1: {PDUSessionID: 1}},
	}
}

// newMux builds the production routing including the method-less catch-all, so
// a pattern conflict would panic here.
func newMux(ues UELookup, rel ANReleaser) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterANRelease(mux, ues, rel, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux.HandleFunc("/amf/v1/ue-contexts/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // sentinel: reached the catch-all
	})
	return mux
}

func do(mux *http.ServeMux, method, supi string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, "/amf/v1/ue-contexts/"+supi+"/an-release", nil))
	return rec
}

func TestANReleaseHandler(t *testing.T) {
	tests := []struct {
		name      string
		ue        *amfctx.UEContext
		rel       *fakeRel
		supi      string
		method    string
		want      int
		wantCalls int
	}{
		{"accepted", testUE(amfctx.CMConnected, false), &fakeRel{assoc: true}, testSUPI, "POST", 202, 1},
		{"unknown supi", testUE(amfctx.CMConnected, false), &fakeRel{assoc: true}, "imsi-999", "POST", 404, 0},
		{"cm idle", testUE(amfctx.CMIdle, false), &fakeRel{assoc: true}, testSUPI, "POST", 409, 0},
		{"pending removal", testUE(amfctx.CMConnected, true), &fakeRel{assoc: true}, testSUPI, "POST", 409, 0},
		{"no association", testUE(amfctx.CMConnected, false), &fakeRel{assoc: false}, testSUPI, "POST", 503, 0},
		{"association dropped between check and send", testUE(amfctx.CMConnected, false), &fakeRel{assoc: true, dropAtSend: true}, testSUPI, "POST", 503, 1},
		{"send failure", testUE(amfctx.CMConnected, false), &fakeRel{assoc: true, err: errors.New("sctp")}, testSUPI, "POST", 500, 1},
		{"GET not allowed", testUE(amfctx.CMConnected, false), &fakeRel{assoc: true}, testSUPI, "GET", 405, 0},
		{"DELETE not allowed", testUE(amfctx.CMConnected, false), &fakeRel{assoc: true}, testSUPI, "DELETE", 405, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := newMux(fakeUEs{testSUPI: tc.ue}, tc.rel)
			rec := do(mux, tc.method, tc.supi)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.rel.calls != tc.wantCalls {
				t.Errorf("NGAP calls = %d, want %d", tc.rel.calls, tc.wantCalls)
			}
			if tc.want == 405 && rec.Header().Get("Allow") != "POST" {
				t.Errorf("Allow = %q, want POST", rec.Header().Get("Allow"))
			}
			if tc.ue.PendingRemoval != (tc.name == "pending removal") {
				t.Error("PendingRemoval must not be modified")
			}
			if tc.want == 202 {
				if tc.rel.gotPres != ngapType.CausePresentMisc ||
					tc.rel.gotCause != int64(ngapType.CauseMiscPresentOmIntervention) {
					t.Errorf("cause = (%d,%d)", tc.rel.gotPres, tc.rel.gotCause)
				}
				if tc.ue.CMState != amfctx.CMConnected {
					t.Error("handler must not change CMState")
				}
				var body map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body["accepted"] != true || body["supi"] != testSUPI ||
					body["previous_cm_state"] != "CM-CONNECTED" || body["spec_ref"] == "" {
					t.Errorf("body = %v", body)
				}
				ids, _ := body["affected_pdu_sessions"].([]any)
				if len(ids) != 2 || ids[0] != float64(1) || ids[1] != float64(2) {
					t.Errorf("affected_pdu_sessions = %v", body["affected_pdu_sessions"])
				}
			}
		})
	}
}

// TestANReleaseCatchAllIntact verifies other ue-contexts paths still reach the
// method-less catch-all (no routing regression, no pattern conflict).
func TestANReleaseCatchAllIntact(t *testing.T) {
	mux := newMux(fakeUEs{}, &fakeRel{})
	for _, p := range []string{"/amf/v1/ue-contexts/", "/amf/v1/ue-contexts/" + testSUPI, "/amf/v1/ue-contexts/" + testSUPI + "/pdu-sessions/1"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("DELETE", p, nil))
		if rec.Code != http.StatusTeapot {
			t.Errorf("%s: status %d, want catch-all", p, rec.Code)
		}
	}
}
