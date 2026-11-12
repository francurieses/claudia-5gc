package procedures

// nssaa_dereg_test.go - AMF-022 decision rule of the rel19 network-initiated
// de-registration after a failed/revoked NSSAA.
// Ref: TS 23.502 §4.2.9.2 step 19b, TS 24.501 §4.6.2.4 c)

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

type snssais = []amfctx.SNSSAISubscribed

func TestNSSAADeregistrationRequired(t *testing.T) {
	nssaa := func(sd string) amfctx.SNSSAISubscribed {
		return amfctx.SNSSAISubscribed{SST: 1, SD: sd, SubjectToNSSAA: true}
	}
	plain := amfctx.SNSSAISubscribed{SST: 2, SD: "000009"}
	tests := []struct {
		name          string
		spec          bool
		mk            func(ue *amfctx.UEContext)
		wantDereg     bool
		wantEmergency bool
	}{
		{name: "all failed", spec: true, wantDereg: true, mk: func(ue *amfctx.UEContext) {
			ue.RejectedNSSAI, ue.SubscribedNSSAI = snssais{nssaa("000003")}, snssais{nssaa("000003")}
		}},
		{name: "some slice still allowed", spec: true, mk: func(ue *amfctx.UEContext) {
			ue.AllowedNSSAI, ue.RejectedNSSAI = snssais{nssaa("000004")}, snssais{nssaa("000003")}
		}},
		{name: "non-NSSAA default can be allowed", spec: true, mk: func(ue *amfctx.UEContext) {
			ue.RejectedNSSAI, ue.SubscribedNSSAI = snssais{nssaa("000003")}, snssais{nssaa("000003"), plain}
		}},
		{name: "exchange still queued", spec: true, mk: func(ue *amfctx.UEContext) {
			ue.RejectedNSSAI, ue.PendingNSSAA = snssais{nssaa("000003")}, snssais{nssaa("000004")}
		}},
		{name: "exchange running", spec: true, mk: func(ue *amfctx.UEContext) {
			ue.RejectedNSSAI = snssais{nssaa("000003")}
			ue.NSSAAInProgress = &amfctx.SNSSAISubscribed{SST: 1, SD: "000004"}
		}},
		{name: "slice PENDING at the NSSAAF", spec: true, mk: func(ue *amfctx.UEContext) {
			ue.RejectedNSSAI, ue.NSSAAPendingStatus = snssais{nssaa("000003")}, snssais{nssaa("000004")}
		}},
		{name: "nothing rejected", spec: true, mk: func(*amfctx.UEContext) {}},
		{name: "emergency PDU session", spec: true, wantEmergency: true, mk: func(ue *amfctx.UEContext) {
			ue.EmergencyPDUSession, ue.RejectedNSSAI = true, snssais{nssaa("000003")}
		}},
		{name: "rel17 never de-registers", spec: false, mk: func(ue *amfctx.UEContext) {
			ue.RejectedNSSAI, ue.SubscribedNSSAI = snssais{nssaa("000003")}, snssais{nssaa("000003")}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &RegistrationHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			h.nssaaSpec = tc.spec
			ue := &amfctx.UEContext{}
			tc.mk(ue)
			dereg, emergency := h.NSSAADeregistrationRequired(ue)
			if dereg != tc.wantDereg || emergency != tc.wantEmergency {
				t.Fatalf("got (dereg=%v, emergency=%v), want (%v, %v)", dereg, emergency, tc.wantDereg, tc.wantEmergency)
			}
		})
	}
}

// ---- AMF-022 rework: builders, default S-NSSAIs, Extended rejected NSSAI ----

type nopNSSAA struct{}

func (nopNSSAA) Authenticate(context.Context, string, string, uint8, string, []byte) (*NSSAAAuthResult, error) {
	return nil, nil
}

func newSpecHandler(spec bool) *RegistrationHandler {
	h := &RegistrationHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), nssaa: nopNSSAA{}}
	h.nssaaSpec = spec
	return h
}

// NSSAADeregRequest: Extended rejected NSSAI INSTEAD of the Rejected NSSAI for an
// ER-NSSAI UE; spare half octet zero; cap of 8 entries.
func TestNSSAADeregRequestBuilder(t *testing.T) {
	ue := &amfctx.UEContext{RejectedNSSAI: snssais{{SST: 1, SD: "000003"}, {SST: 2, SD: "000004"}}}
	plain := NSSAADeregRequest(ue, false)
	if plain.Cause5GMM != 62 || plain.AccessType != AccessType3GPP || plain.ReregistrationRequired ||
		!plain.SpareHalfOctetZero || len(plain.RejectedNSSAI) != 2 || plain.ExtendedRejectedNSSAI != nil {
		t.Fatalf("plain = %+v", plain)
	}
	ext := NSSAADeregRequest(ue, true)
	if len(ext.RejectedNSSAI) != 0 || ext.ExtendedRejectedNSSAI == nil ||
		len(ext.ExtendedRejectedNSSAI.Lists[0].Elements) != 2 {
		t.Fatalf("extended = %+v", ext)
	}
	body, err := nas.EncodeDeregistrationRequestNW(ext)
	if err != nil {
		t.Fatal(err)
	}
	if body[0] != 0x01 { // spare 0 | re-registration not required | 3GPP
		t.Fatalf("octet 4 = %#x", body[0])
	}
	back, err := nas.DecodeDeregistrationRequestNW(body)
	if err != nil || back.ExtendedRejectedNSSAI == nil || len(back.RejectedNSSAI) != 0 {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
}

// Default S-NSSAIs that can be allowed: not subject to NSSAA, not rejected, <= 8.
func TestAllowableDefaultNSSAI(t *testing.T) {
	ue := &amfctx.UEContext{
		SubscribedNSSAI: snssais{
			{SST: 1, SD: "000003", SubjectToNSSAA: true},
			{SST: 1, SD: "000004"},
			{SST: 1, SD: "000005"}, // rejected below
		},
		RejectedNSSAI: snssais{{SST: 1, SD: "000005"}},
	}
	got := allowableDefaultNSSAI(ue)
	if len(got) != 1 || got[0].SD != "000004" {
		t.Fatalf("defaults = %+v, want only 1-000004", got)
	}
	ue.SubscribedNSSAI = nil
	for i := 0; i < 12; i++ {
		ue.SubscribedNSSAI = append(ue.SubscribedNSSAI, amfctx.SNSSAISubscribed{SST: 1, SD: fmt.Sprintf("%06x", 0x100+i)})
	}
	if got := allowableDefaultNSSAI(ue); len(got) != maxAllowedSNSSAIs {
		t.Fatalf("%d defaults, want the Allowed NSSAI limit %d", len(got), maxAllowedSNSSAIs)
	}
}

// decideNSSAAEnd: default S-NSSAIs become the Allowed NSSAI (rel19), CUC; rel17 untouched.
func TestDecideNSSAAEndAllowsDefaults(t *testing.T) {
	mk := func() *amfctx.UEContext {
		return &amfctx.UEContext{
			RejectedNSSAI:   snssais{{SST: 1, SD: "000003", SubjectToNSSAA: true}},
			SubscribedNSSAI: snssais{{SST: 1, SD: "000003", SubjectToNSSAA: true}, {SST: 1, SD: "000009"}},
		}
	}
	ue := mk()
	dereg, cuc := newSpecHandler(true).decideNSSAAEnd(ue)
	if dereg || !cuc || len(ue.AllowedNSSAI) != 1 || ue.AllowedNSSAI[0].SD != "000009" {
		t.Fatalf("rel19: dereg=%v cuc=%v allowed=%+v", dereg, cuc, ue.AllowedNSSAI)
	}
	ue = mk()
	dereg, cuc = newSpecHandler(false).decideNSSAAEnd(ue)
	if dereg || !cuc || len(ue.AllowedNSSAI) != 0 {
		t.Fatalf("rel17: dereg=%v cuc=%v allowed=%+v (frozen)", dereg, cuc, ue.AllowedNSSAI)
	}
	// a slice still PENDING: nothing is settled, no defaults are added
	ue = mk()
	ue.NSSAAPendingStatus = snssais{{SST: 1, SD: "000004", SubjectToNSSAA: true}}
	if _, _ = newSpecHandler(true).decideNSSAAEnd(ue); len(ue.AllowedNSSAI) != 0 {
		t.Fatalf("defaults added with a PENDING slice: %+v", ue.AllowedNSSAI)
	}
}

// REGISTRATION ACCEPT: the rejected NSSAI goes into the Extended rejected NSSAI IE
// for an ER-NSSAI UE, else into the Rejected NSSAI IE; rel17 adds neither.
func TestRegistrationAcceptExtendedRejectedNSSAI(t *testing.T) {
	for _, tc := range []struct {
		name              string
		spec, er          bool
		wantER, wantPlain bool
	}{
		{"rel19 ER-NSSAI UE", true, true, true, false},
		{"rel19 plain UE", true, false, false, true},
		{"rel17", false, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ue := &amfctx.UEContext{ERNSSAISupported: tc.er, RejectedNSSAI: snssais{{SST: 1, SD: "000003"}}}
			ra := &nas.RegistrationAccept{}
			newSpecHandler(tc.spec).applyNSSAAAcceptIEs(ra, ue)
			if (ra.ExtendedRejectedNSSAI != nil) != tc.wantER || (len(ra.RejectedNSSAI) > 0) != tc.wantPlain {
				t.Fatalf("accept = %+v", ra)
			}
			if tc.wantER {
				if _, err := nas.EncodeRegistrationAccept(ra); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// DeregisterUECM without a UDM client is a logged no-op, not a nil dereference.
func TestDeregisterUECMNilUDM(t *testing.T) {
	if err := newSpecHandler(true).DeregisterUECM(context.Background(), "imsi-001010000000001"); err != nil {
		t.Fatal(err)
	}
}
