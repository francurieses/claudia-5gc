package nasmsg

// registration_time_test.go — Registration Complete stamps RegistrationTime.
// Ref: TS 23.502 §4.2.2.2.2 step 21

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
)

func TestRegistrationTimeSet(t *testing.T) {
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, lg)
	reg := procedures.NewRegistrationHandler(mgr, nil, nil, nil, "nf", "001", "01", lg)
	h := &Handler{reg: reg, logger: lg}
	ue := &amfctx.UEContext{SUPI: "imsi-001010000000001"}

	before := time.Now()
	if err := h.handleRegistrationComplete(context.Background(), ue); err != nil {
		t.Fatalf("handleRegistrationComplete: %v", err)
	}
	first := ue.Snapshot().RegistrationTime
	if first.IsZero() || first.Before(before) {
		t.Fatalf("RegistrationTime not set: %v", first)
	}

	// A re-registration refreshes the timestamp.
	time.Sleep(2 * time.Millisecond)
	if err := h.handleRegistrationComplete(context.Background(), ue); err != nil {
		t.Fatalf("second handleRegistrationComplete: %v", err)
	}
	if !ue.Snapshot().RegistrationTime.After(first) {
		t.Error("RegistrationTime not refreshed on re-registration")
	}
}
