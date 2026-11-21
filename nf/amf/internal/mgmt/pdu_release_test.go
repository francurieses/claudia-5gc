package mgmt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
)

type fakeReleaser struct {
	calls []uint8 // causes
	err   error
}

func (f *fakeReleaser) InitiateNetworkPDUSessionRelease(_ context.Context, _ *amfctx.UEContext, _ uint8, cause uint8) error {
	f.calls = append(f.calls, cause)
	return f.err
}

type oneUE struct{ ue *amfctx.UEContext }

func (o oneUE) GetBySUPI(supi string) (*amfctx.UEContext, bool) {
	if supi == "imsi-001010000000001" {
		return o.ue, true
	}
	return nil, false
}

// TestHandlePDUSessionRelease covers the O&M release contract of
// docs/procedures/SmfRestartRecovery.md §4.4. Ref: TS 23.502 §4.3.4.2.
func TestHandlePDUSessionRelease(t *testing.T) {
	tests := []struct {
		name      string
		supi      string
		psi       string
		query     string
		err       error
		wantCode  int
		wantCause []uint8
	}{
		{"cause absent defaults to 36", "imsi-001010000000001", "1", "", nil, 202, []uint8{36}},
		{"cause 36", "imsi-001010000000001", "1", "?cause=36", nil, 202, []uint8{36}},
		{"cause 39", "imsi-001010000000001", "1", "?cause=39", nil, 202, []uint8{39}},
		{"cause 40 rejected", "imsi-001010000000001", "1", "?cause=40", nil, 400, nil},
		{"cause not numeric", "imsi-001010000000001", "1", "?cause=x", nil, 400, nil},
		{"psi 0", "imsi-001010000000001", "0", "?cause=39", nil, 400, nil},
		{"psi 16", "imsi-001010000000001", "16", "?cause=39", nil, 400, nil},
		{"unknown UE", "imsi-001010000000999", "1", "?cause=39", nil, 404, nil},
		{"unknown PSI", "imsi-001010000000001", "9", "?cause=39", fmt.Errorf("x: %w", nasmsg.ErrPDUSessionNotFound), 404, []uint8{39}},
		{"send failure", "imsi-001010000000001", "1", "", errors.New("boom"), 500, []uint8{36}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rel := &fakeReleaser{err: tc.err}
			req := httptest.NewRequest(http.MethodDelete, "/amf/v1/ue-contexts/"+tc.supi+"/pdu-sessions/"+tc.psi+tc.query, nil)
			rec := httptest.NewRecorder()
			HandlePDUSessionRelease(rec, req, oneUE{&amfctx.UEContext{}}, rel, tc.supi, tc.psi,
				slog.New(slog.NewTextHandler(io.Discard, nil)))
			if rec.Code != tc.wantCode {
				t.Fatalf("status=%d; want %d", rec.Code, tc.wantCode)
			}
			if !bytes.Equal(rel.calls, tc.wantCause) {
				t.Fatalf("causes=%v; want %v", rel.calls, tc.wantCause)
			}
		})
	}
}

func TestSplitPDUSessionPath(t *testing.T) {
	if s, p, ok := SplitPDUSessionPath("imsi-1/pdu-sessions/5"); !ok || s != "imsi-1" || p != "5" {
		t.Fatalf("got %q %q %v", s, p, ok)
	}
	for _, bad := range []string{"imsi-1", "imsi-1/pdu-sessions/", "/pdu-sessions/1"} {
		if _, _, ok := SplitPDUSessionPath(bad); ok {
			t.Fatalf("%q must not match", bad)
		}
	}
}
