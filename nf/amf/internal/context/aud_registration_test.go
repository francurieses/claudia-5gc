package context

// aud_registration_test.go — failing-by-design reproductions for the
// registration spec audit (dev/campaigns/results/audit-registration.md).
// Fixed findings (15, 21) run as normal regression tests; a still-open finding
// is skipped unless the opt-in flag is given:
//
//	GOWORK=off go test ./nf/amf/internal/context/ -run TestAUDRegistration -v -args -aud-registration-repro
//
// Ref: TS 24.501 §5.5.1.2.4, §5.5.1.3.8 a)

import (
	"context"
	"flag"
	"testing"
)

// regAudRepro opts in to the AUD-registration reproductions below; without it
// they are skipped (command in the file header).
var regAudRepro = flag.Bool("aud-registration-repro", false, "run the AUD-registration failing-by-design reproductions")

// TestAUDRegistration15_ReallocatedGUTIReleasesOldTMSI: AssignGUTI adds a
// 5G-TMSI index entry on every (re)allocation and never drops the previous one,
// and Remove deletes only the current one. Every periodic/mobility update leaks
// an index entry, and an old 5G-TMSI keeps resolving to the context even after
// it was removed. TS 24.501 §5.5.1.3.8 a) 1) i): once the new 5G-GUTI is used,
// the AMF shall consider the old 5G-GUTI as invalid.
func TestAUDRegistration15_ReallocatedGUTIReleasesOldTMSI(t *testing.T) {
	ctx := context.Background()
	m := NewManager(AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	ue := m.AllocateUEContext(1)
	old := m.AssignGUTI(ctx, ue).TMSI
	_ = m.AssignGUTI(ctx, ue) // periodic/mobility registration update reallocates the 5G-GUTI

	m.Remove(ctx, ue)
	if got, ok := m.GetByTMSI(old); ok {
		t.Fatalf("old 5G-TMSI %08x still resolves to a removed context (%p): index entry leaked", old, got)
	}
}

// TestAUDRegistration21_CorrelationIDNoPanic: CorrelationID slices the last 8
// characters of the SUCI. extractIdentity stores "unknown" (7 characters) for a
// REGISTRATION REQUEST carrying an IMEI or no identity, so the first caller
// panics (index -1). No caller exists today; nothing recovers if one is added.
func TestAUDRegistration21_CorrelationIDNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CorrelationID panicked: %v", r)
		}
	}()
	u := &UEContext{SUCI: "unknown"}
	_ = u.CorrelationID()
}
