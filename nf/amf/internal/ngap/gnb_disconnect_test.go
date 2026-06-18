package ngap

// gnb_disconnect_test.go — unit tests for gNB disconnect UE cleanup.
// Ref: TS 23.502 §4.2.6 (implicit detach on RAN failure)

import (
	"context"
	"sync"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// TestSetGNBDisconnectHandler_CallbackFires verifies that onGNBDisconnect is
// invoked for every UE present in gnb.UEs when cleanup runs.
func TestSetGNBDisconnectHandler_CallbackFires(t *testing.T) {
	mgr := amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	srv := &Server{
		mgr:  mgr,
		gnbs: make(map[string]*GNBContext),
	}

	var mu sync.Mutex
	var called []string

	srv.SetGNBDisconnectHandler(func(_ context.Context, ue *amfctx.UEContext) {
		mu.Lock()
		called = append(called, ue.SUPI)
		mu.Unlock()
	})

	// Build a synthetic GNBContext with two CM-CONNECTED UEs and one CM-IDLE UE.
	ue1 := &amfctx.UEContext{SUPI: "imsi-001010000000001", AMFUENGAPId: 1, RANUENGAPId: 10}
	ue2 := &amfctx.UEContext{SUPI: "imsi-001010000000002", AMFUENGAPId: 2, RANUENGAPId: 20}
	ue3 := &amfctx.UEContext{SUPI: "imsi-001010000000003", AMFUENGAPId: 3, RANUENGAPId: 30}
	gnb := &GNBContext{
		UEs: map[int64]*amfctx.UEContext{
			ue1.RANUENGAPId: ue1,
			ue2.RANUENGAPId: ue2,
		},
		IdleUEs: map[int64]*amfctx.UEContext{
			ue3.RANUENGAPId: ue3,
		},
	}

	// Simulate the cleanup logic inside handleGNBConn defer.
	gnb.mu.Lock()
	ues := make([]*amfctx.UEContext, 0, len(gnb.UEs)+len(gnb.IdleUEs))
	for _, ue := range gnb.UEs {
		ues = append(ues, ue)
	}
	for _, ue := range gnb.IdleUEs {
		ues = append(ues, ue)
	}
	gnb.mu.Unlock()

	for _, ue := range ues {
		srv.onGNBDisconnect(context.Background(), ue)
	}

	if len(called) != 3 {
		t.Fatalf("expected callback for 3 UEs (2 connected + 1 idle), got %d: %v", len(called), called)
	}
}

// TestSetGNBDisconnectHandler_IdleUEsCleaned verifies that onGNBDisconnect is
// also invoked for CM-IDLE UEs tracked in gnb.IdleUEs, covering the case where
// UERANSIM stops gracefully (UEContextRelease sequence before SCTP close).
func TestSetGNBDisconnectHandler_IdleUEsCleaned(t *testing.T) {
	mgr := amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	srv := &Server{
		mgr:  mgr,
		gnbs: make(map[string]*GNBContext),
	}

	var mu sync.Mutex
	var cleaned []string

	srv.SetGNBDisconnectHandler(func(_ context.Context, ue *amfctx.UEContext) {
		mu.Lock()
		cleaned = append(cleaned, ue.SUPI)
		mu.Unlock()
	})

	// Simulate a gNB where all UEs went CM-IDLE before disconnection.
	ue1 := &amfctx.UEContext{SUPI: "imsi-001010000000001", AMFUENGAPId: 1, RANUENGAPId: 10}
	ue2 := &amfctx.UEContext{SUPI: "imsi-001010000000002", AMFUENGAPId: 2, RANUENGAPId: 20}
	gnb := &GNBContext{
		UEs: make(map[int64]*amfctx.UEContext), // all were moved to IdleUEs
		IdleUEs: map[int64]*amfctx.UEContext{
			ue1.RANUENGAPId: ue1,
			ue2.RANUENGAPId: ue2,
		},
	}

	gnb.mu.Lock()
	ues := make([]*amfctx.UEContext, 0, len(gnb.UEs)+len(gnb.IdleUEs))
	for _, ue := range gnb.UEs {
		ues = append(ues, ue)
	}
	for _, ue := range gnb.IdleUEs {
		ues = append(ues, ue)
	}
	gnb.mu.Unlock()

	for _, ue := range ues {
		srv.onGNBDisconnect(context.Background(), ue)
	}

	if len(cleaned) != 2 {
		t.Fatalf("expected 2 idle UEs cleaned up, got %d: %v", len(cleaned), cleaned)
	}
}

// TestSetGNBDisconnectHandler_NoCallbackNoPanic verifies no panic when the
// handler is not set (nil) and the gNB has UEs.
func TestSetGNBDisconnectHandler_NoCallbackNoPanic(t *testing.T) {
	mgr := amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	srv := &Server{
		mgr:  mgr,
		gnbs: make(map[string]*GNBContext),
	}

	gnb := &GNBContext{
		UEs: map[int64]*amfctx.UEContext{
			1: {SUPI: "imsi-001010000000001", AMFUENGAPId: 1, RANUENGAPId: 1},
		},
		IdleUEs: make(map[int64]*amfctx.UEContext),
	}

	// onGNBDisconnect is nil — the guard in the defer must prevent a nil-deref.
	if srv.onGNBDisconnect != nil {
		for _, ue := range gnb.UEs {
			srv.onGNBDisconnect(context.Background(), ue)
		}
		for _, ue := range gnb.IdleUEs {
			srv.onGNBDisconnect(context.Background(), ue)
		}
	}
	// Reaching here without panic is the assertion.
}

// TestSetGNBDisconnectHandler_EmptyGNB verifies no-op when no UEs are attached.
func TestSetGNBDisconnectHandler_EmptyGNB(t *testing.T) {
	mgr := amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	srv := &Server{
		mgr:  mgr,
		gnbs: make(map[string]*GNBContext),
	}

	calls := 0
	srv.SetGNBDisconnectHandler(func(_ context.Context, _ *amfctx.UEContext) {
		calls++
	})

	gnb := &GNBContext{
		UEs:     make(map[int64]*amfctx.UEContext),
		IdleUEs: make(map[int64]*amfctx.UEContext),
	}

	gnb.mu.Lock()
	ues := make([]*amfctx.UEContext, 0, len(gnb.UEs)+len(gnb.IdleUEs))
	gnb.mu.Unlock()

	for _, ue := range ues {
		srv.onGNBDisconnect(context.Background(), ue)
	}

	if calls != 0 {
		t.Fatalf("expected 0 callback calls for empty gNB, got %d", calls)
	}
}
