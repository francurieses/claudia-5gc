package nasmsg

// reactivation_cause_test.go — PDU session reactivation result error cause
// (IEI 0x72) of the Service Accept. Ref: TS 24.501 §5.6.1.4.1, §9.11.3.43

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

type fakeSMFErr struct{ cause string }

func (e *fakeSMFErr) Error() string               { return "smf: status 403 " + e.cause }
func (e *fakeSMFErr) SMFApplicationCause() string { return e.cause }

func TestReactivationErrorCause_Mapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want uint8
	}{
		{"non LADN service area", &fakeSMFErr{"UE_IN_NON_LADN_SERVICE_AREA"}, 43},
		{"prioritized services only", &fakeSMFErr{"PRIORITIZED_SERVICES_ONLY"}, 28},
		{"NSAC", &fakeSMFErr{"S-NSSAI_UNAVAILABLE_DUE_TO_NSAC"}, 69},
		{"wrapped typed", fmt.Errorf("amf: x: %w", &fakeSMFErr{"UE_IN_NON_LADN_SERVICE_AREA"}), 43},
		{"UPF not responding", &fakeSMFErr{"UPF_NOT_RESPONDING"}, 92},
		{"empty cause", &fakeSMFErr{""}, 92},
		{"transport error", errors.New("dial tcp: refused"), 92},
		{"empty n2SmInfo", errors.New("smf: activate sm context: empty or invalid n2SmInfo"), 92},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := reactivationErrorCause(tc.err); got != tc.want {
				t.Errorf("cause = %d, want %d", got, tc.want)
			}
		})
	}
}

type causeSender struct {
	activatorSender
	errs map[string]error
}

func (c *causeSender) ActivateSMContext(_ context.Context, ref string) ([]byte, error) {
	if e := c.errs[ref]; e != nil {
		return nil, e
	}
	return []byte{0xAA}, nil
}

func TestActivatePDUSessions_FailureCauses(t *testing.T) {
	s := &causeSender{errs: map[string]error{
		"ref-2": &fakeSMFErr{"UE_IN_NON_LADN_SERVICE_AREA"},
		"ref-3": errors.New("boom"),
	}}
	h := &Handler{sender: s}
	ue := pagedTestUE(1, 2, 3)
	ulds := nas.PSIMask(1, 2, 3)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	items, causes := h.activatePDUSessions(context.Background(), ue, &ulds, nil, log)
	if got := psiList(items); !equalPSIs(got, []uint8{1}) {
		t.Errorf("items = %v", got)
	}
	if len(causes) != 2 || causes[2] != 43 || causes[3] != 92 {
		t.Errorf("causes = %v", causes)
	}
}

func TestBuildServiceAccept_ErrorCauses(t *testing.T) {
	mask := func(p ...uint8) *uint16 { m := nas.PSIMask(p...); return &m }
	ue := pagedTestUE(1, 2, 3)
	sr := &nas.ServiceRequest{PDUSessionStatus: mask(1, 2, 3), UplinkDataStatus: mask(1, 2, 3, 7)}
	activated := []ngap.PDUSessionSetupItemCxtReq{{PDUSessionID: 1}}
	// PSI 3: SMF failure #43; PSI 2 (no failure entry) and PSI 7 (unknown) -> #111.
	a := buildServiceAccept(ue, sr, nil, activated, map[uint8]uint8{3: 43})
	want := []nas.PDUSessionErrorCause{
		{PDUSessionID: 2, Cause5GMM: 111}, {PDUSessionID: 3, Cause5GMM: 43}, {PDUSessionID: 7, Cause5GMM: 111}}
	got := a.PDUSessionReactivationResultErrorCause
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %v, want %v", i, got[i], want[i])
		}
	}
	b, err := nas.EncodeServiceAccept(a)
	if err != nil {
		t.Fatal(err)
	}
	// IE order 0x50, 0x26, 0x72 (TLV-E, 3 entries -> 6 octets).
	if b[0] != 0x50 || b[4] != 0x26 || b[8] != 0x72 {
		t.Errorf("IE order wrong: % X", b)
	}
	if !bytes.HasSuffix(b, []byte{0x72, 0x00, 0x06, 2, 111, 3, 43, 7, 111}) {
		t.Errorf("0x72 bytes wrong: % X", b)
	}
	dec, err := nas.DecodeServiceAccept(b)
	if err != nil || len(dec.PDUSessionReactivationResultErrorCause) != 3 {
		t.Fatalf("round trip: %v %v", dec, err)
	}
}

func TestBuildServiceAccept_AllSuccessNoErrorCauseIE(t *testing.T) {
	mask := func(p ...uint8) *uint16 { m := nas.PSIMask(p...); return &m }
	ue := pagedTestUE(1, 2)
	sr := &nas.ServiceRequest{UplinkDataStatus: mask(1, 2)}
	a := buildServiceAccept(ue, sr, nil,
		[]ngap.PDUSessionSetupItemCxtReq{{PDUSessionID: 1}, {PDUSessionID: 2}}, nil)
	if a.PDUSessionReactivationResultErrorCause != nil {
		t.Fatalf("0x72 present: %v", a.PDUSessionReactivationResultErrorCause)
	}
	b, _ := nas.EncodeServiceAccept(a)
	if !bytes.Equal(b, []byte{0x26, 0x02, 0x00, 0x00}) {
		t.Errorf("bytes = % X", b)
	}
	// No Uplink data status: no 0x26, no 0x72.
	a = buildServiceAccept(ue, &nas.ServiceRequest{}, nil, nil, map[uint8]uint8{1: 92})
	if a.PDUSessionReactivationResult != nil || a.PDUSessionReactivationResultErrorCause != nil {
		t.Errorf("unexpected IEs: %+v", a)
	}
}
