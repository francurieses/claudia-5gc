package registry_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/nrf/internal/registry"
)

func newSilentLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestInMemory_RegisterGet(t *testing.T) {
	r := registry.NewInMemory(newSilentLogger())
	p := &registry.NFProfile{
		NFInstanceID: "11111111-1111-1111-1111-111111111111",
		NFType:       registry.NFTypeAMF,
	}
	if err := r.Register(p); err != nil {
		t.Fatalf("register: %v", err)
	}
	got, ok := r.Get(p.NFInstanceID)
	if !ok || got.NFType != registry.NFTypeAMF {
		t.Fatalf("get: %+v ok=%v", got, ok)
	}
	if got.NFStatus != registry.NFStatusRegistered {
		t.Errorf("expected default status REGISTERED, got %s", got.NFStatus)
	}
}

func TestInMemory_RegisterRequiresFields(t *testing.T) {
	r := registry.NewInMemory(newSilentLogger())

	if err := r.Register(&registry.NFProfile{NFType: registry.NFTypeAMF}); err == nil {
		t.Errorf("expected error when nfInstanceId missing")
	}
	if err := r.Register(&registry.NFProfile{NFInstanceID: "abc"}); err == nil {
		t.Errorf("expected error when nfType missing")
	}
}

func TestInMemory_DiscoverByType(t *testing.T) {
	r := registry.NewInMemory(newSilentLogger())
	_ = r.Register(&registry.NFProfile{NFInstanceID: "amf-1", NFType: registry.NFTypeAMF})
	_ = r.Register(&registry.NFProfile{NFInstanceID: "amf-2", NFType: registry.NFTypeAMF})
	_ = r.Register(&registry.NFProfile{NFInstanceID: "smf-1", NFType: registry.NFTypeSMF})

	results := r.Discover(registry.DiscoveryFilter{TargetNFType: registry.NFTypeAMF})
	if len(results) != 2 {
		t.Fatalf("expected 2 AMFs, got %d", len(results))
	}

	results = r.Discover(registry.DiscoveryFilter{TargetNFType: registry.NFTypeUDM})
	if len(results) != 0 {
		t.Errorf("expected 0 UDMs, got %d", len(results))
	}
}

func TestInMemory_DiscoverByService(t *testing.T) {
	r := registry.NewInMemory(newSilentLogger())
	_ = r.Register(&registry.NFProfile{
		NFInstanceID: "amf-1",
		NFType:       registry.NFTypeAMF,
		NFServices: []registry.NFService{
			{ServiceName: "namf-comm"},
			{ServiceName: "namf-evts"},
		},
	})

	results := r.Discover(registry.DiscoveryFilter{
		TargetNFType: registry.NFTypeAMF,
		ServiceNames: []string{"namf-comm"},
	})
	if len(results) != 1 {
		t.Errorf("expected 1, got %d", len(results))
	}

	results = r.Discover(registry.DiscoveryFilter{
		TargetNFType: registry.NFTypeAMF,
		ServiceNames: []string{"namf-mt"}, // not advertised
	})
	if len(results) != 0 {
		t.Errorf("expected 0 (no service match), got %d", len(results))
	}
}

func TestInMemory_DiscoverBySNSSAI(t *testing.T) {
	r := registry.NewInMemory(newSilentLogger())
	_ = r.Register(&registry.NFProfile{
		NFInstanceID: "smf-eMBB",
		NFType:       registry.NFTypeSMF,
		SNSSAIs:      []registry.SNSSAI{{SST: 1, SD: "000001"}},
	})
	_ = r.Register(&registry.NFProfile{
		NFInstanceID: "smf-URLLC",
		NFType:       registry.NFTypeSMF,
		SNSSAIs:      []registry.SNSSAI{{SST: 2, SD: "000002"}},
	})

	results := r.Discover(registry.DiscoveryFilter{
		TargetNFType: registry.NFTypeSMF,
		SNSSAIs:      []registry.SNSSAI{{SST: 1, SD: "000001"}},
	})
	if len(results) != 1 || results[0].NFInstanceID != "smf-eMBB" {
		t.Errorf("expected eMBB SMF, got %+v", results)
	}
}

func TestInMemory_UpdateAndDeregister(t *testing.T) {
	r := registry.NewInMemory(newSilentLogger())
	p := &registry.NFProfile{NFInstanceID: "amf-1", NFType: registry.NFTypeAMF, Capacity: 100}
	_ = r.Register(p)

	_ = r.Update("amf-1", &registry.NFProfile{NFType: registry.NFTypeAMF, Capacity: 50})
	got, _ := r.Get("amf-1")
	if got.Capacity != 50 {
		t.Errorf("expected capacity=50 after update, got %d", got.Capacity)
	}

	if err := r.Deregister("amf-1"); err != nil {
		t.Fatalf("deregister: %v", err)
	}
	if _, ok := r.Get("amf-1"); ok {
		t.Errorf("expected absent after deregister")
	}

	if err := r.Deregister("amf-1"); err == nil {
		t.Errorf("expected error on double deregister")
	}
}
