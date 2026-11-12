package procedures

// aud_registration20_test.go - AUD-registration-20: every registration SBI step
// runs under its own budget below T3510 (TS 24.501 §10.2 Table 10.2.1, 15 s);
// optional peers run in parallel and degrade non-fatally, a mandatory peer
// timeout rejects with #22. Budgets are injected small (no multi-second sleeps).
//
// Also AUD-registration-17 mapping: RejectCauseForUDMError.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// blockNSSF, blockAMPol and blockUEPol block until their context is done.
type blockNSSF struct{}

func (blockNSSF) NSSelection(ctx context.Context, _, _ string, _ []amfctx.SNSSAISubscribed) ([]amfctx.SNSSAISubscribed, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type blockAMPol struct{}

func (blockAMPol) CreateAMPolicyAssociation(ctx context.Context, _, _, _, _ string) (string, int, *amfctx.ServiceAreaRestriction, error) {
	<-ctx.Done()
	return "", 0, nil, ctx.Err()
}
func (blockAMPol) DeleteAMPolicyAssociation(context.Context, string) error { return nil }

type blockUEPol struct{}

func (blockUEPol) CreateUEPolicyAssociation(ctx context.Context, _, _ string) (string, []byte, error) {
	<-ctx.Done()
	return "", nil, ctx.Err()
}
func (blockUEPol) DeleteUEPolicyAssociation(context.Context, string) error { return nil }

// hangUDM blocks RegisterAMF (UECM) until its context is done.
type hangUDM struct{ regAudUDM }

func (hangUDM) RegisterAMF(ctx context.Context, _, _, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

func newAUD20Env(t *testing.T, udm UDMClient) (*RegistrationHandler, *amfctx.UEContext) {
	t.Helper()
	h, mgr := newRegAudRegistration(t, nil, udm)
	h.WithBudgets(Budgets{UECM: 100 * time.Millisecond, Optional: 100 * time.Millisecond, Phase3: time.Second})
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, "imsi-001010000000001")
	ue.RequestedNSSAI = []amfctx.SNSSAISubscribed{{SST: 1}}
	return h, ue
}

// TestAUDRegistration20_OptionalPeersBoundedAndParallel: NSSF, PCF AM and PCF UE
// all block until their context ends; Phase3 still returns the Accept well under
// T3510, after about one optional budget (parallel), using the local fallback.
func TestAUDRegistration20_OptionalPeersBoundedAndParallel(t *testing.T) {
	h, ue := newAUD20Env(t, regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}})
	h.WithNSSF(blockNSSF{})
	h.WithAMPolicy(blockAMPol{})
	h.WithPCF(blockUEPol{})

	start := time.Now()
	ra, err := h.Phase3_ProcessSMCComplete(context.Background(), ue)
	elapsed := time.Since(start)
	if err != nil || ra == nil {
		t.Fatalf("ra=%v err=%v; optional-peer timeouts must be non-fatal", ra, err)
	}
	if elapsed >= T3510/10 {
		t.Fatalf("Phase3 took %v, want far below T3510 (%v)", elapsed, T3510)
	}
	if elapsed >= 280*time.Millisecond { // 3 serial 100 ms budgets would be >= 300 ms
		t.Fatalf("Phase3 took %v: optional peers did not run in parallel", elapsed)
	}
	if len(ue.AllowedNSSAI) != 1 || ue.AMPolicyAssocID != "" || ue.PolicyAssociationID != "" {
		t.Fatalf("fallback state wrong: allowed=%v am=%q ue=%q", ue.AllowedNSSAI, ue.AMPolicyAssocID, ue.PolicyAssociationID)
	}
}

// TestAUDRegistration20_MandatoryPeerTimeoutRejects22: a hanging UECM is cut at
// its budget and rejects with #22 (T3346 is attached by the NAS reject path).
func TestAUDRegistration20_MandatoryPeerTimeoutRejects22(t *testing.T) {
	h, ue := newAUD20Env(t, hangUDM{regAudUDM{allowed: []amfctx.SNSSAISubscribed{{SST: 1}}}})
	start := time.Now()
	ra, err := h.Phase3_ProcessSMCComplete(context.Background(), ue)
	var rc *ErrRejectCause
	if !errors.As(err, &rc) || ra != nil || rc.Cause != nas.CauseCongestion {
		t.Fatalf("ra=%v err=%v; want ErrRejectCause #22", ra, err)
	}
	if d := time.Since(start); d >= T3510/10 {
		t.Fatalf("took %v, want bounded by the UECM budget", d)
	}
}

// TestAUDRegistration20_BudgetTable pins the documented values: the sequential
// steps stay below RegistrationNetworkBudget, which stays below T3510.
func TestAUDRegistration20_BudgetTable(t *testing.T) {
	b := DefaultBudgets()
	sum := b.AUSFInit + b.AUSFConfirm + b.Phase3
	if sum > RegistrationNetworkBudget || RegistrationNetworkBudget >= T3510 {
		t.Fatalf("sum %v / budget %v / T3510 %v inconsistent", sum, RegistrationNetworkBudget, T3510)
	}
	if t3510 := 15 * time.Second; T3510 != t3510 {
		t.Fatalf("T3510 = %v", T3510)
	}
}

// TestAUDRegistration17_CauseMapping documents the SBI-error -> 5GMM cause map.
func TestAUDRegistration17_CauseMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want nas.Cause5GMM
	}{
		{"403 roaming not allowed", &UDMError{Status: http.StatusForbidden, Cause: UDMCauseRoamingNotAllowed}, nas.CausePLMNNotAllowed},
		{"403 other", &UDMError{Status: http.StatusForbidden, Cause: "X"}, nas.Cause5GSServicesNotAllowed},
		{"404 user not found", &UDMError{Status: http.StatusNotFound, Cause: UDMCauseUserNotFound}, nas.Cause5GSServicesNotAllowed},
		{"503", &UDMError{Status: http.StatusServiceUnavailable}, nas.CauseCongestion},
		{"400", &UDMError{Status: http.StatusBadRequest}, nas.CauseCongestion},
		{"transport", &UDMError{Err: errors.New("dial: refused")}, nas.CauseCongestion},
		{"timeout", fmt.Errorf("wrapped: %w", context.DeadlineExceeded), nas.CauseCongestion},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, ref := RejectCauseForUDMError(tc.err); got != tc.want || ref == "" {
				t.Fatalf("cause = %d (ref %q), want %d", got, ref, tc.want)
			}
		})
	}
}
