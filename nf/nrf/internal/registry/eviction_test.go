package registry_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/nrf/internal/registry"
)

func TestEviction_RemovesStaleNF(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reg := registry.NewInMemory(logger)

	p := &registry.NFProfile{NFInstanceID: "test-evict-001", NFType: registry.NFTypeAMF}
	if err := reg.Register(p); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, ok := reg.Get("test-evict-001"); !ok {
		t.Fatal("expected NF to be present after register")
	}

	// Start eviction with a very short timeout so it fires quickly in tests.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg.StartEviction(ctx, 100*time.Millisecond)

	// Wait long enough for eviction to run (timeout + two tick intervals).
	time.Sleep(350 * time.Millisecond)

	if _, ok := reg.Get("test-evict-001"); ok {
		t.Error("expected stale NF to be evicted")
	}
}

func TestEviction_KeepsActiveNF(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reg := registry.NewInMemory(logger)

	p := &registry.NFProfile{NFInstanceID: "test-active-001", NFType: registry.NFTypeSMF}
	if err := reg.Register(p); err != nil {
		t.Fatalf("register: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg.StartEviction(ctx, 200*time.Millisecond)

	// Send heartbeats while eviction is running.
	for i := 0; i < 5; i++ {
		time.Sleep(80 * time.Millisecond)
		if err := reg.Heartbeat("test-active-001"); err != nil {
			t.Fatalf("heartbeat %d: %v", i, err)
		}
	}

	if _, ok := reg.Get("test-active-001"); !ok {
		t.Error("expected active NF (with heartbeats) to survive eviction")
	}
}

func TestHeartbeat_UpdatesLastSeen(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	reg := registry.NewInMemory(logger)

	p := &registry.NFProfile{NFInstanceID: "test-hb-001", NFType: registry.NFTypeUDM}
	if err := reg.Register(p); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Heartbeat("test-hb-001"); err != nil {
		t.Errorf("heartbeat: %v", err)
	}
	if err := reg.Heartbeat("unknown-id"); err == nil {
		t.Error("expected error for unknown NF")
	}
}
