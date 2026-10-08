package nasmsg

// service_accept_test.go — Service Accept IEs and local release of PDU
// sessions the UE reports inactive in the Service Request.
// Ref: TS 24.501 §5.6.1.4.1, §8.2.17

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// releaseActivateSender records ActivateSMContext and DeleteSMContext calls.
// DeleteSMContext runs on a goroutine, so it is mutex-guarded and signalled.
type releaseActivateSender struct {
	activatorSender
	mu      sync.Mutex
	deleted []string
	delDone chan string
}

func (r *releaseActivateSender) DeleteSMContext(_ context.Context, ref string) error {
	r.mu.Lock()
	r.deleted = append(r.deleted, ref)
	r.mu.Unlock()
	if r.delDone != nil {
		r.delDone <- ref
	}
	return nil
}

func waitDeletes(t *testing.T, ch chan string, n int) []string {
	t.Helper()
	var got []string
	for i := 0; i < n; i++ {
		select {
		case ref := <-ch:
			got = append(got, ref)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for DeleteSMContext %d/%d (got %v)", i+1, n, got)
		}
	}
	sort.Strings(got)
	return got
}

func mask(psis ...uint8) *uint16 {
	m := nas.PSIMask(psis...)
	return &m
}

func TestReleaseInactivePDUSessions(t *testing.T) {
	tests := []struct {
		name         string
		sessions     []uint8
		status       *uint16
		wantReleased []uint8
		wantLeft     []uint8
	}{
		{"status absent: nothing released", []uint8{1, 2}, nil, nil, []uint8{1, 2}},
		{"all active: nothing released", []uint8{1, 2}, mask(1, 2), nil, []uint8{1, 2}},
		{"PSI 2 inactive released", []uint8{1, 2}, mask(1), []uint8{2}, []uint8{1}},
		{"empty status releases all", []uint8{1, 2}, mask(), []uint8{1, 2}, nil},
		{"UE-only active PSI ignored", []uint8{1}, mask(1, 5), nil, []uint8{1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &releaseActivateSender{delDone: make(chan string, 16)}
			h := &Handler{sender: s, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			ue := pagedTestUE(tc.sessions...)
			released := h.releaseInactivePDUSessions(context.Background(), ue, tc.status)

			var got []uint8
			for psi := range released {
				got = append(got, psi)
			}
			sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
			if !equalPSIs(got, tc.wantReleased) {
				t.Errorf("released = %v, want %v", got, tc.wantReleased)
			}
			var left []uint8
			for psi := range ue.PDUSessions {
				left = append(left, psi)
			}
			sort.Slice(left, func(i, j int) bool { return left[i] < left[j] })
			if !equalPSIs(left, tc.wantLeft) {
				t.Errorf("UE context sessions = %v, want %v", left, tc.wantLeft)
			}
			var wantRefs []string
			for _, p := range tc.wantReleased {
				wantRefs = append(wantRefs, "ref-"+string(rune('0'+p)))
			}
			refs := waitDeletes(t, s.delDone, len(wantRefs))
			if len(refs) != len(wantRefs) {
				t.Fatalf("SMF releases = %v, want %v", refs, wantRefs)
			}
			for i := range refs {
				if refs[i] != wantRefs[i] {
					t.Errorf("SMF releases = %v, want %v", refs, wantRefs)
				}
			}
			select {
			case extra := <-s.delDone:
				t.Errorf("unexpected extra SMF release %q", extra)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// Sessions without an SM context (establishment not completed) are never
// released locally nor reported to the SMF.
func TestReleaseInactivePDUSessions_SkipsWithoutSMContext(t *testing.T) {
	s := &releaseActivateSender{delDone: make(chan string, 4)}
	h := &Handler{sender: s, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ue := &amfctx.UEContext{PDUSessions: map[uint8]*amfctx.PDUSession{3: {}}}
	if r := h.releaseInactivePDUSessions(context.Background(), ue, mask()); len(r) != 0 {
		t.Fatalf("released = %v, want none", r)
	}
	if _, ok := ue.PDUSessions[3]; !ok {
		t.Fatal("session without SM context was removed")
	}
}

func TestBuildServiceAccept(t *testing.T) {
	items := func(psis ...uint8) []ngap.PDUSessionSetupItemCxtReq {
		var out []ngap.PDUSessionSetupItemCxtReq
		for _, p := range psis {
			out = append(out, ngap.PDUSessionSetupItemCxtReq{PDUSessionID: p})
		}
		return out
	}
	tests := []struct {
		name       string
		sessions   []uint8 // left in UE context after the local release
		released   []uint8
		sr         nas.ServiceRequest
		activated  []ngap.PDUSessionSetupItemCxtReq
		wantStatus *uint16
		wantResult *uint16
	}{
		{name: "signalling SR without IEs: empty accept", sessions: []uint8{1}},
		{name: "status echoes AMF-active sessions", sessions: []uint8{1, 2},
			sr: nas.ServiceRequest{PDUSessionStatus: mask(1, 2, 5)}, wantStatus: mask(1, 2)},
		{name: "status excludes released", sessions: []uint8{1}, released: []uint8{2},
			sr: nas.ServiceRequest{PDUSessionStatus: mask(1)}, wantStatus: mask(1)},
		{name: "reactivation all OK", sessions: []uint8{1, 2},
			sr: nas.ServiceRequest{UplinkDataStatus: mask(1, 2)}, activated: items(1, 2), wantResult: mask()},
		{name: "reactivation PSI 2 failed", sessions: []uint8{1, 2},
			sr: nas.ServiceRequest{UplinkDataStatus: mask(1, 2)}, activated: items(1), wantResult: mask(2)},
		{name: "reactivation ignores paged-only PSI", sessions: []uint8{1, 2},
			sr: nas.ServiceRequest{UplinkDataStatus: mask(1)}, activated: items(1, 2), wantResult: mask()},
		{name: "both IEs", sessions: []uint8{1}, released: []uint8{2},
			sr:         nas.ServiceRequest{PDUSessionStatus: mask(1), UplinkDataStatus: mask(1, 2)},
			activated:  items(1),
			wantStatus: mask(1), wantResult: mask(2)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ue := pagedTestUE(tc.sessions...)
			rel := map[uint8]struct{}{}
			for _, p := range tc.released {
				rel[p] = struct{}{}
			}
			sr := tc.sr
			a := buildServiceAccept(ue, &sr, rel, tc.activated)
			checkMask(t, "PDUSessionStatus", a.PDUSessionStatus, tc.wantStatus)
			checkMask(t, "PDUSessionReactivationResult", a.PDUSessionReactivationResult, tc.wantResult)
		})
	}
}

func checkMask(t *testing.T, name string, got, want *uint16) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil || want == nil:
		t.Errorf("%s presence = %v, want %v", name, got != nil, want != nil)
	case *got != *want:
		t.Errorf("%s = %04X, want %04X", name, *got, *want)
	}
}
