package procedures

import (
	"context"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// abortRecorder records the UDM / PCF cleanup calls of ReleaseUERegistration.
type abortRecorder struct {
	regAudUDM
	uecm, amPol, uePol []string
}

func (r *abortRecorder) DeregisterUECM(_ context.Context, supi string) error {
	r.uecm = append(r.uecm, supi)
	return nil
}
func (r *abortRecorder) DeleteAMPolicyAssociation(_ context.Context, id string) error {
	r.amPol = append(r.amPol, id)
	return nil
}
func (r *abortRecorder) CreateAMPolicyAssociation(context.Context, string, string, string, string) (string, int, *amfctx.ServiceAreaRestriction, error) {
	return "", 0, nil, nil
}
func (r *abortRecorder) CreateUEPolicyAssociation(context.Context, string, string) (string, []byte, error) {
	return "", nil, nil
}
func (r *abortRecorder) DeleteUEPolicyAssociation(_ context.Context, id string) error {
	r.uePol = append(r.uePol, id)
	return nil
}

// TestReleaseUERegistration: UDM UECM deregistration and both PCF associations are
// released and cleared on the UE (TS 23.502 §4.2.2.3.2 step 3).
func TestReleaseUERegistration(t *testing.T) {
	rec := &abortRecorder{}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01", AMFRegionID: 2, AMFSetID: 1, AMFID: 1}, nil, nil, nil)
	h := NewRegistrationHandler(mgr, nil, rec, nil, "nf", "001", "01", lg)
	h.WithPCF(rec)
	h.WithAMPolicy(rec)
	ue := mgr.AllocateUEContext(7)
	mgr.SetSUPI(ue, "imsi-001010000000001")
	ue.AMPolicyAssocID, ue.PolicyAssociationID = "am-1", "ue-1"

	h.ReleaseUERegistration(context.Background(), ue, "InitialRegistration")

	if len(rec.uecm) != 1 || rec.uecm[0] != "imsi-001010000000001" {
		t.Fatalf("UECM deregistrations = %v", rec.uecm)
	}
	if len(rec.amPol) != 1 || rec.amPol[0] != "am-1" || len(rec.uePol) != 1 || rec.uePol[0] != "ue-1" {
		t.Fatalf("PCF releases am=%v ue=%v", rec.amPol, rec.uePol)
	}
	if ue.AMPolicyAssocID != "" || ue.PolicyAssociationID != "" {
		t.Fatal("policy association IDs not cleared")
	}
	// Idempotent: a second run has nothing left to release at the PCF.
	h.ReleaseUERegistration(context.Background(), ue, "InitialRegistration")
	if len(rec.amPol) != 1 || len(rec.uePol) != 1 {
		t.Fatalf("second run released again: am=%v ue=%v", rec.amPol, rec.uePol)
	}
}
