package session

import (
	"io"
	"log/slog"
	"sync"
	"testing"
)

func testManager() *Manager {
	return NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestRegisterDeregisterNoLeak(t *testing.T) {
	m := testManager()
	s := m.Register("1.2.3.4:5555", "test-agent")
	if m.Count() != 1 {
		t.Fatalf("count after register: got %d, want 1", m.Count())
	}
	if _, ok := m.Get(s.ID); !ok {
		t.Fatal("session not retrievable")
	}
	m.Deregister(s.ID)
	if m.Count() != 0 {
		t.Fatalf("count after deregister: got %d, want 0 (leak)", m.Count())
	}
	// Channel must be closed exactly once; second deregister is a no-op.
	m.Deregister(s.ID)
	if _, open := <-s.Events(); open {
		t.Fatal("session channel should be closed after deregister")
	}
}

func TestSendToTargetsOneSession(t *testing.T) {
	m := testManager()
	a := m.Register("a", "ua")
	b := m.Register("b", "ub")

	if !m.SendTo(a.ID, Event{Name: "message", Data: []byte("for-a")}) {
		t.Fatal("SendTo a failed")
	}
	// b must not have received anything.
	select {
	case ev := <-a.Events():
		if string(ev.Data) != "for-a" {
			t.Errorf("a got %q", ev.Data)
		}
	default:
		t.Fatal("a did not receive its event")
	}
	select {
	case ev := <-b.Events():
		t.Fatalf("b received an event meant for a: %q", ev.Data)
	default:
	}
}

func TestBroadcastReachesAll(t *testing.T) {
	m := testManager()
	a := m.Register("a", "ua")
	b := m.Register("b", "ub")
	if n := m.Broadcast(Event{Name: "message", Data: []byte("hi")}); n != 2 {
		t.Fatalf("broadcast reached %d, want 2", n)
	}
	for _, s := range []*Session{a, b} {
		select {
		case ev := <-s.Events():
			if string(ev.Data) != "hi" {
				t.Errorf("session got %q", ev.Data)
			}
		default:
			t.Errorf("session %s missed broadcast", s.ID)
		}
	}
}

func TestSendToMissingSession(t *testing.T) {
	m := testManager()
	if m.SendTo("nope", Event{Name: "message", Data: []byte("x")}) {
		t.Fatal("SendTo to missing session should return false")
	}
}

// TestConcurrentRegisterDeregister exercises the sync.Map under -race.
func TestConcurrentRegisterDeregister(t *testing.T) {
	m := testManager()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := m.Register("addr", "ua")
			m.SendTo(s.ID, Event{Name: "message", Data: []byte("x")})
			m.Deregister(s.ID)
		}()
	}
	wg.Wait()
	if m.Count() != 0 {
		t.Fatalf("residual sessions after concurrent churn: %d", m.Count())
	}
}
