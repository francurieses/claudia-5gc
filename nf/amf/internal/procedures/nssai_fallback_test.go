package procedures

// nssai_fallback_test.go - AMF-036: Allowed NSSAI default S-NSSAI fallback
// (TS 23.501 §5.15.5.2.1, TS 24.501 §5.5.1.2.4, §5.5.1.3.4) and mapped
// S-NSSAIs in the Extended rejected NSSAI (TS 24.501 §9.11.3.75).

import (
	"context"
	"errors"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

type fbUDM struct{ sub *UDMAMSubscription }

func (fbUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (fbUDM) DeregisterUECM(context.Context, string) error              { return nil }
func (u fbUDM) GetAMSubscriptionData(context.Context, string) (*UDMAMSubscription, error) {
	return u.sub, nil
}

var (
	fbDefault = amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}
	fbSingle  = amfctx.SNSSAISubscribed{SST: 1, SD: "000002"}
)

func fbSub(defaults ...amfctx.SNSSAISubscribed) *UDMAMSubscription {
	return &UDMAMSubscription{
		AllowedNSSAI: MergeSubscribedNSSAI(defaults, []amfctx.SNSSAISubscribed{fbSingle}),
		DefaultNSSAI: defaults,
	}
}

func fbPhase3(t *testing.T, sub *UDMAMSubscription, requested []amfctx.SNSSAISubscribed) (*nas.RegistrationAccept, *amfctx.UEContext, error) {
	t.Helper()
	h, mgr := newRegAudRegistration(t, nil, fbUDM{sub})
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, "imsi-001010000000001")
	ue.RequestedNSSAI = requested
	ra, err := h.Phase3_ProcessSMCComplete(context.Background(), ue)
	return ra, ue, err
}

func TestNoRequestedNSSAIAllowsDefaultsOnly(t *testing.T) {
	_, ue, err := fbPhase3(t, fbSub(fbDefault), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ue.AllowedNSSAI) != 1 || ue.AllowedNSSAI[0].SD != "000001" {
		t.Fatalf("Allowed = %+v, want only the default 1-000001", ue.AllowedNSSAI)
	}
	if len(ue.SubscribedNSSAI) != 2 || len(ue.DefaultNSSAI) != 1 || len(ue.NotAvailableNSSAI) != 0 {
		t.Fatalf("subscribed=%+v default=%+v notAvail=%+v", ue.SubscribedNSSAI, ue.DefaultNSSAI, ue.NotAvailableNSSAI)
	}
}

func TestRequestedNotSubscribedFallsBackToDefaults(t *testing.T) {
	req := []amfctx.SNSSAISubscribed{{SST: 9, SD: "00000a"}, {SST: 8}}
	ra, ue, err := fbPhase3(t, fbSub(fbDefault), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(ue.AllowedNSSAI) != 1 || ue.AllowedNSSAI[0].SD != "000001" {
		t.Fatalf("Allowed = %+v, want defaults", ue.AllowedNSSAI)
	}
	if len(ue.NotAvailableNSSAI) != 2 {
		t.Fatalf("rejected = %+v, want the two requested", ue.NotAvailableNSSAI)
	}
	// Accept carries the Rejected NSSAI IE (no ER-NSSAI): cause "not available in the current PLMN".
	want := []byte{0x40 | nas.RejectedCauseNotAvailableInPLMN, 9, 0, 0, 0x0a, 0x10 | nas.RejectedCauseNotAvailableInPLMN, 8}
	if string(ra.RejectedNSSAI) != string(want) || ra.ExtendedRejectedNSSAI != nil {
		t.Fatalf("Phase3 accept rejected NSSAI = %x, want %x", ra.RejectedNSSAI, want)
	}
	h, _ := newRegAudRegistration(t, nil, fbUDM{fbSub(fbDefault)})
	ra = &nas.RegistrationAccept{}
	if !h.setAcceptRejectedNSSAI(ra, ue, false) || string(ra.RejectedNSSAI) != string(want) || ra.ExtendedRejectedNSSAI != nil {
		t.Fatalf("accept rejected NSSAI = %x, want %x", ra.RejectedNSSAI, want)
	}
}

func TestNoDefaultStillRejects62(t *testing.T) {
	_, _, err := fbPhase3(t, fbSub(), []amfctx.SNSSAISubscribed{{SST: 9}})
	var nn *NoNetworkSlicesError
	if !errors.As(err, &nn) {
		t.Fatalf("err = %v, want NoNetworkSlicesError", err)
	}
}

func TestRequestedPermittedKeepsRequestedOnly(t *testing.T) {
	_, ue, err := fbPhase3(t, fbSub(fbDefault), []amfctx.SNSSAISubscribed{fbSingle})
	if err != nil {
		t.Fatal(err)
	}
	if len(ue.AllowedNSSAI) != 1 || ue.AllowedNSSAI[0].SD != "000002" || len(ue.NotAvailableNSSAI) != 0 {
		t.Fatalf("Allowed = %+v notAvail=%+v", ue.AllowedNSSAI, ue.NotAvailableNSSAI)
	}
}

func TestReevaluateAllowedNSSAIDefaultFallback(t *testing.T) {
	h, _ := newRegAudRegistration(t, nil, fbUDM{})
	ue := &amfctx.UEContext{
		RequestedNSSAI:  []amfctx.SNSSAISubscribed{{SST: 9}},
		SubscribedNSSAI: []amfctx.SNSSAISubscribed{fbDefault, fbSingle},
		DefaultNSSAI:    []amfctx.SNSSAISubscribed{fbDefault},
		AllowedNSSAI:    []amfctx.SNSSAISubscribed{fbSingle},
	}
	h.ReevaluateAllowedNSSAI(context.Background(), ue)
	if len(ue.AllowedNSSAI) != 1 || ue.AllowedNSSAI[0].SD != "000001" {
		t.Fatalf("Allowed = %+v, want defaults", ue.AllowedNSSAI)
	}
	ue.DefaultNSSAI = nil
	ue.AllowedNSSAI = []amfctx.SNSSAISubscribed{fbSingle}
	h.ReevaluateAllowedNSSAI(context.Background(), ue)
	if len(ue.AllowedNSSAI) != 1 || ue.AllowedNSSAI[0].SD != "000002" {
		t.Fatalf("Allowed = %+v, want unchanged without defaults", ue.AllowedNSSAI)
	}
}

func TestExtendedRejectedNSSAIMappedValue(t *testing.T) {
	ue := &amfctx.UEContext{RequestedNSSAI: []amfctx.SNSSAISubscribed{
		{SST: 9, SD: "00000a", HasMapped: true, MappedSST: 3, MappedSD: "000004"},
		{SST: 8, HasMapped: true, MappedSST: 2},
		{SST: 7},
		{SST: 6, SD: "000006", HasMapped: true, MappedSST: 1},
	}}
	list := []nas.RejectedSNSSAI{
		{Cause: nas.RejectedCauseNotAvailableInPLMN, SNSSAI: toNASSNSSAI(ue.RequestedNSSAI[0])},
		{Cause: nas.RejectedCauseNotAvailableInPLMN, SNSSAI: toNASSNSSAI(ue.RequestedNSSAI[1])},
		{Cause: nas.RejectedCauseNotAvailableInPLMN, SNSSAI: toNASSNSSAI(ue.RequestedNSSAI[2])},
		{Cause: nas.RejectedCauseNSSAAFailedOrRevoked, SNSSAI: toNASSNSSAI(ue.RequestedNSSAI[3])},
	}
	e := ExtendedRejectedNSSAIForUE(ue, list)
	raw, err := nas.EncodeExtendedRejectedNSSAI(e)
	if err != nil {
		t.Fatal(err)
	}
	back, err := nas.DecodeExtendedRejectedNSSAI(raw)
	if err != nil {
		t.Fatal(err)
	}
	els := back.Lists[0].Elements
	if len(els) != 4 || els[0].Mapped == nil || els[0].Mapped.SST != 3 || els[0].Mapped.SD != 4 ||
		els[1].Mapped == nil || els[1].Mapped.SST != 2 || els[2].Mapped != nil || els[3].Mapped != nil {
		t.Fatalf("decoded elements = %+v", els)
	}
}

type fbNSSAA struct{ NSSAAClient }

type fbNSSF struct{ out []amfctx.SNSSAISubscribed }

func (f fbNSSF) NSSelection(context.Context, string, string, []amfctx.SNSSAISubscribed) ([]amfctx.SNSSAISubscribed, error) {
	return f.out, nil
}

// Finding 1: the update path never allows a slice with failed NSSAA or one
// subject to NSSAA that is not already authorized (TS 24.501 §5.5.1.3.4).
func TestReevaluateAllowedNSSAIExcludesUnauthorizedNSSAA(t *testing.T) {
	nssaaSlice := amfctx.SNSSAISubscribed{SST: 2, SD: "000002", SubjectToNSSAA: true}
	failed := amfctx.SNSSAISubscribed{SST: 3, SD: "000003", SubjectToNSSAA: true}
	plain := amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}
	newUE := func(req []amfctx.SNSSAISubscribed, allowed []amfctx.SNSSAISubscribed, def []amfctx.SNSSAISubscribed) *amfctx.UEContext {
		return &amfctx.UEContext{
			RequestedNSSAI:  req,
			SubscribedNSSAI: []amfctx.SNSSAISubscribed{plain, nssaaSlice, failed},
			DefaultNSSAI:    def,
			AllowedNSSAI:    allowed,
			RejectedNSSAI:   []amfctx.SNSSAISubscribed{failed},
		}
	}
	tests := []struct {
		name string
		ue   *amfctx.UEContext
		want []amfctx.SNSSAISubscribed
	}{
		{"requested: unauthorized and failed left out", newUE([]amfctx.SNSSAISubscribed{plain, nssaaSlice, failed}, []amfctx.SNSSAISubscribed{plain}, nil), []amfctx.SNSSAISubscribed{plain}},
		{"requested: authorized NSSAA slice kept", newUE([]amfctx.SNSSAISubscribed{plain, nssaaSlice}, []amfctx.SNSSAISubscribed{plain, nssaaSlice}, nil), []amfctx.SNSSAISubscribed{plain, nssaaSlice}},
		{"fallback defaults filtered", newUE([]amfctx.SNSSAISubscribed{{SST: 9}}, []amfctx.SNSSAISubscribed{plain}, []amfctx.SNSSAISubscribed{nssaaSlice, plain}), []amfctx.SNSSAISubscribed{plain}},
		{"all filtered: unchanged", newUE([]amfctx.SNSSAISubscribed{nssaaSlice, failed}, []amfctx.SNSSAISubscribed{plain}, []amfctx.SNSSAISubscribed{nssaaSlice}), []amfctx.SNSSAISubscribed{plain}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newRegAudRegistration(t, nil, fbUDM{})
			h.WithNSSAA(fbNSSAA{})
			h.ReevaluateAllowedNSSAI(context.Background(), tc.ue)
			if len(tc.ue.AllowedNSSAI) != len(tc.want) {
				t.Fatalf("Allowed = %+v, want %+v", tc.ue.AllowedNSSAI, tc.want)
			}
			for i, w := range tc.want {
				if tc.ue.AllowedNSSAI[i].SST != w.SST || tc.ue.AllowedNSSAI[i].SD != w.SD {
					t.Fatalf("Allowed = %+v, want %+v", tc.ue.AllowedNSSAI, tc.want)
				}
			}
		})
	}
}

// Finding 2: a UE without NSSAA support whose defaults are all subject to NSSAA
// is rejected #62 (TS 24.501 §5.5.1.2.5 b) 2)); an NSSAA-capable UE is accepted.
func TestNoNSSAASupportAllDefaultsNSSAAReject62(t *testing.T) {
	nssaaDef := amfctx.SNSSAISubscribed{SST: 1, SD: "000001", SubjectToNSSAA: true}
	run := func(cap *nas.FiveGMMCapability) error {
		h, mgr := newRegAudRegistration(t, nil, fbUDM{&UDMAMSubscription{
			AllowedNSSAI: []amfctx.SNSSAISubscribed{nssaaDef}, DefaultNSSAI: []amfctx.SNSSAISubscribed{nssaaDef},
		}})
		h.WithNSSAA(fbNSSAA{})
		ue := mgr.AllocateUEContext(1)
		mgr.SetSUPI(ue, "imsi-001010000000001")
		ue.RequestedNSSAI = []amfctx.SNSSAISubscribed{{SST: 9}}
		ue.Capability5GMM = cap
		_, err := h.Phase3_ProcessSMCComplete(context.Background(), ue)
		return err
	}
	var nn *NoNetworkSlicesError
	if err := run(nil); !errors.As(err, &nn) {
		t.Fatalf("no capability: err = %v, want NoNetworkSlicesError", err)
	}
	if err := run(&nas.FiveGMMCapability{}); !errors.As(err, &nn) {
		t.Fatalf("NSSAA bit clear: err = %v, want NoNetworkSlicesError", err)
	}
	if err := run(&nas.FiveGMMCapability{NSSAA: true}); err != nil {
		t.Fatalf("NSSAA-capable UE: err = %v, want Accept with pending NSSAI", err)
	}
}

// Finding 4: NSSF branch without Requested NSSAI -> default S-NSSAIs only.
func TestNSSFNoRequestedNSSAIAllowsDefaults(t *testing.T) {
	nssfOut := []amfctx.SNSSAISubscribed{fbDefault, fbSingle}
	for name, out := range map[string][]amfctx.SNSSAISubscribed{
		"intersection": nssfOut,
		"empty":        {{SST: 77}},
	} {
		t.Run(name, func(t *testing.T) {
			h, mgr := newRegAudRegistration(t, nil, fbUDM{fbSub(fbDefault)})
			h.WithNSSF(fbNSSF{out})
			ue := mgr.AllocateUEContext(1)
			mgr.SetSUPI(ue, "imsi-001010000000001")
			if _, err := h.Phase3_ProcessSMCComplete(context.Background(), ue); err != nil {
				t.Fatal(err)
			}
			if len(ue.AllowedNSSAI) != 1 || ue.AllowedNSSAI[0].SD != "000001" {
				t.Fatalf("Allowed = %+v, want only the default", ue.AllowedNSSAI)
			}
		})
	}
}

// A UE without NSSAA support requesting only an NSSAA-subject slice gets the
// non-NSSAA default (Accept), the NSSAA slice rejected, and no NSSAA pending;
// an NSSAA-supporting UE keeps pending NSSAI (TS 23.501 §5.15.10).
func TestNoNSSAASupportFallsBackToNonNSSAADefault(t *testing.T) {
	nssaaSl := amfctx.SNSSAISubscribed{SST: 2, SD: "000002", SubjectToNSSAA: true}
	plainDef := amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}
	run := func(cap *nas.FiveGMMCapability) *amfctx.UEContext {
		h, mgr := newRegAudRegistration(t, nil, fbUDM{&UDMAMSubscription{
			AllowedNSSAI: []amfctx.SNSSAISubscribed{plainDef, nssaaSl}, DefaultNSSAI: []amfctx.SNSSAISubscribed{plainDef},
		}})
		h.WithNSSAA(fbNSSAA{})
		ue := mgr.AllocateUEContext(1)
		mgr.SetSUPI(ue, "imsi-001010000000001")
		ue.RequestedNSSAI = []amfctx.SNSSAISubscribed{nssaaSl}
		ue.Capability5GMM = cap
		if _, err := h.Phase3_ProcessSMCComplete(context.Background(), ue); err != nil {
			t.Fatal(err)
		}
		return ue
	}
	ue := run(&nas.FiveGMMCapability{})
	if len(ue.AllowedNSSAI) != 1 || ue.AllowedNSSAI[0].SD != "000001" {
		t.Fatalf("Allowed = %+v, want only the non-NSSAA default", ue.AllowedNSSAI)
	}
	if len(ue.PendingNSSAA) != 0 {
		t.Fatalf("Pending = %+v, want none", ue.PendingNSSAA)
	}
	if len(ue.NotAvailableNSSAI) != 1 || ue.NotAvailableNSSAI[0].SD != "000002" {
		t.Fatalf("NotAvailable = %+v, want the NSSAA slice", ue.NotAvailableNSSAI)
	}
	ue = run(&nas.FiveGMMCapability{NSSAA: true})
	if len(ue.PendingNSSAA) != 1 || ue.PendingNSSAA[0].SD != "000002" {
		t.Fatalf("NSSAA UE: Pending = %+v, want the NSSAA slice", ue.PendingNSSAA)
	}
}
