package nasmsg

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
)

// activatorSender embeds the Sender interface (nil) and adds ActivateSMContext;
// only ActivateSMContext is exercised by activatePDUSessions.
type activatorSender struct {
	Sender
	calls []string
	fail  map[string]bool
}

func (a *activatorSender) ActivateSMContext(_ context.Context, ref string) ([]byte, error) {
	a.calls = append(a.calls, ref)
	if a.fail[ref] {
		return nil, errors.New("smf unavailable")
	}
	return []byte{0xAA}, nil
}

func pagedTestUE(psis ...uint8) *amfctx.UEContext {
	ue := &amfctx.UEContext{PDUSessions: map[uint8]*amfctx.PDUSession{}}
	for _, p := range psis {
		ue.PDUSessions[p] = &amfctx.PDUSession{SMFInstanceID: "ref-" + string(rune('0'+p))}
	}
	return ue
}

func psiList(items []ngap.PDUSessionSetupItemCxtReq) []uint8 {
	var out []uint8
	for _, it := range items {
		out = append(out, it.PDUSessionID)
	}
	return out
}

func equalPSIs(a, b []uint8) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestActivatePDUSessions_Paged(t *testing.T) {
	ulds := func(psis ...uint8) *uint16 {
		var v uint16
		for _, p := range psis {
			v |= 1 << (8 + p) // PSI 0-7 in the high byte (TS 24.501 §9.11.3.57)
		}
		return &v
	}
	tests := []struct {
		name      string
		sessions  []uint8
		paged     []uint8
		ulds      *uint16
		fail      map[string]bool
		wantItems []uint8
		wantCalls int
	}{
		{"paged only", []uint8{1}, []uint8{1}, nil, nil, []uint8{1}, 1},
		{"union with ULDS no duplicates ascending", []uint8{1, 2, 3}, []uint8{2, 3}, ulds(1, 2), nil, []uint8{1, 2, 3}, 3},
		{"activation failure", []uint8{1}, []uint8{1}, nil, map[string]bool{"ref-1": true}, nil, 1},
		{"paged PSI missing", []uint8{1}, []uint8{5}, nil, nil, nil, 0},
		{"signalling only no page", []uint8{1}, nil, nil, nil, nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &activatorSender{fail: tc.fail}
			h := &Handler{sender: s}
			ue := pagedTestUE(tc.sessions...)
			for _, p := range tc.paged {
				ue.AddPagedPDUSession(p)
			}
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			items := h.activatePDUSessions(context.Background(), ue, tc.ulds, nil, log)
			if got := psiList(items); !equalPSIs(got, tc.wantItems) {
				t.Errorf("items = %v, want %v", got, tc.wantItems)
			}
			if len(s.calls) != tc.wantCalls {
				t.Errorf("ActivateSMContext calls = %d, want %d", len(s.calls), tc.wantCalls)
			}
			if left := ue.PagedPDUSessions(); len(left) != 0 {
				t.Errorf("paged set leaked after SR: %v", left)
			}
		})
	}
}

// TestActivatePDUSessions_PagedPDUSessionStatus covers TS 24.501 §5.6.1.4.1:
// a PSI the UE reports inactive in PDU session status is released locally
// (releaseInactivePDUSessions) and never activated, whether paged or flagged
// in Uplink data status.
func TestActivatePDUSessions_PagedPDUSessionStatus(t *testing.T) {
	status := func(psis ...uint8) *uint16 {
		var v uint16
		for _, p := range psis {
			v |= 1 << (8 + p)
		}
		return &v
	}
	tests := []struct {
		name      string
		paged     []uint8
		status    *uint16
		ulds      *uint16
		wantItems []uint8
		wantCalls int
	}{
		{"paged PSI bit 0 released not activated", []uint8{1}, status(2), nil, nil, 0},
		{"paged PSI bit 1 activated", []uint8{1}, status(1), nil, []uint8{1}, 1},
		{"status absent activates", []uint8{1}, nil, nil, []uint8{1}, 1},
		{"mixed", []uint8{1, 2}, status(2), nil, []uint8{2}, 1},
		{"ULDS PSI reported inactive released not activated", []uint8{2}, status(), status(1), nil, 0},
		{"ULDS PSI reported active activated", nil, status(1), status(1), []uint8{1}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &activatorSender{}
			h := &Handler{sender: s}
			ue := pagedTestUE(1, 2)
			for _, p := range tc.paged {
				ue.AddPagedPDUSession(p)
			}
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			released := h.releaseInactivePDUSessions(context.Background(), ue, tc.status)
			items := h.activatePDUSessions(context.Background(), ue, tc.ulds, released, log)
			if got := psiList(items); !equalPSIs(got, tc.wantItems) {
				t.Errorf("items = %v, want %v", got, tc.wantItems)
			}
			if len(s.calls) != tc.wantCalls {
				t.Errorf("ActivateSMContext calls = %d, want %d", len(s.calls), tc.wantCalls)
			}
		})
	}
}

// TestNotifyUEReachable_ClearsPagedSet: Registration Update / other paths that
// return the UE to CM-CONNECTED without a Service Request drop the paged set
// and still fire the callback.
func TestNotifyUEReachable_ClearsPagedSet(t *testing.T) {
	ue := pagedTestUE(1)
	ue.AddPagedPDUSession(1)
	fired := false
	h := &Handler{onUEReachable: func(*amfctx.UEContext) { fired = true }}
	h.notifyUEReachable(ue)
	if left := ue.PagedPDUSessions(); len(left) != 0 {
		t.Errorf("paged set not cleared: %v", left)
	}
	if !fired {
		t.Error("onUEReachable not invoked")
	}
	(&Handler{}).notifyUEReachable(ue) // nil callback must not panic
}
