package ngap

// gnb_registry_test.go — gNB registry snapshots, history and NG Reset recording.
// Ref: TS 38.413 §8.7.1, §8.7.4; TS 38.412 §7.

import (
	"sync"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// fakeClock is a mutable time source for the registry clock seam.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newRegistryServer(clk *fakeClock) *Server {
	return &Server{
		cfg:    AMFConfig{Name: "amf"},
		addr:   "0.0.0.0:38412",
		logger: discardLogger(),
		gnbs:   make(map[string]*GNBContext),
		now:    clk.now,
	}
}

// newTestGNB builds a GNBContext with a nil Conn: snapshots must never touch it.
func newTestGNB(clk *fakeClock, name string, id uint32) *GNBContext {
	return &GNBContext{
		Name:        name,
		RANNode:     GlobalRANNode{Type: RANNodeTypeGNB, MCC: "001", MNC: "01", GNBID: id, GNBIDBitLen: 32},
		RemoteAddrs: []string{"172.30.1.20"},
		RemotePort:  48211,
		ConnectedAt: clk.now(),
		State:       GNBStateSCTPUp,
		UEs:         map[int64]*amfctx.UEContext{},
		IdleUEs:     map[int64]*amfctx.UEContext{},
	}
}

func TestGNBSnapshots_Empty(t *testing.T) {
	s := newRegistryServer(&fakeClock{t: time.Unix(1000, 0)})
	if got := s.GNBSnapshots(); got == nil || len(got) != 0 {
		t.Fatalf("snapshots = %#v, want empty non-nil", got)
	}
}

func TestGNBSnapshots_StatesAndFields(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newRegistryServer(clk)

	up := newTestGNB(clk, "gnb-up", 2)
	ready := newTestGNB(clk, "gnb-ready", 1)
	ready.SupportedTAs = []SupportedTA{{TAC: 1, BroadcastPLMNs: []PLMNSlice{{
		MCC: "001", MNC: "01",
		SliceSupport: []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}},
	}}}}
	ready.UEs[10] = &amfctx.UEContext{}
	ready.IdleUEs[11] = &amfctx.UEContext{}
	s.gnbs["172.30.1.21:1"] = up
	s.gnbs["172.30.1.20:48211"] = ready
	s.markGNBReady(ready)

	snaps := s.GNBSnapshots()
	if len(snaps) != 2 {
		t.Fatalf("len = %d, want 2", len(snaps))
	}
	if snaps[0].RANNodeName != "gnb-ready" || snaps[0].State != GNBStateNGReady {
		t.Fatalf("first = %+v, want NG_READY gnb-ready first", snaps[0])
	}
	r := snaps[0]
	if r.RANNode.GNBIDHex != "00000001" || r.RANNode.GNBIDBitLen != 32 {
		t.Errorf("ran_node = %+v", r.RANNode)
	}
	if r.NGSetupAt == nil || r.UEs.Connected != 1 || r.UEs.Idle != 1 {
		t.Errorf("ng_setup_at/ues = %v / %+v", r.NGSetupAt, r.UEs)
	}
	if len(r.SupportedTAs) != 1 || r.SupportedTAs[0].BroadcastPLMNs[0].Slices[0].SD != "000001" {
		t.Errorf("supported_tas = %+v", r.SupportedTAs)
	}
	if snaps[1].State != GNBStateSCTPUp || snaps[1].NGSetupAt != nil {
		t.Errorf("second = %+v, want SCTP_UP", snaps[1])
	}
}

func TestGNBHistory_RetentionAndPrune(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newRegistryServer(clk)
	g := newTestGNB(clk, "gnb-a", 1)

	s.mu.Lock()
	s.recordGNBDisconnectLocked(g, "172.30.1.20:48211", GNBDisconnectSCTPClosed)
	s.mu.Unlock()

	snaps := s.GNBSnapshots()
	if len(snaps) != 1 || snaps[0].State != GNBStateDisconnected ||
		snaps[0].DisconnectReason != GNBDisconnectSCTPClosed || snaps[0].DisconnectedAt == nil {
		t.Fatalf("snaps = %+v", snaps)
	}
	clk.advance(gnbHistoryRetention + time.Minute)
	if got := s.GNBSnapshots(); len(got) != 0 {
		t.Fatalf("after retention: %d entries, want 0", len(got))
	}
}

func TestGNBHistory_BoundedByMax(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newRegistryServer(clk)
	for i := 0; i < gnbHistoryMax+5; i++ {
		g := newTestGNB(clk, "gnb", uint32(i))
		s.mu.Lock()
		s.recordGNBDisconnectLocked(g, "id", GNBDisconnectReadError)
		s.mu.Unlock()
	}
	if got := len(s.GNBSnapshots()); got != gnbHistoryMax {
		t.Fatalf("history = %d, want %d", got, gnbHistoryMax)
	}
}

func TestGNBHistory_ReconnectDedupe(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newRegistryServer(clk)

	old := newTestGNB(clk, "gnb-a", 1)
	s.mu.Lock()
	s.recordGNBDisconnectLocked(old, "172.30.1.20:48211", GNBDisconnectSCTPClosed)
	s.mu.Unlock()

	fresh := newTestGNB(clk, "gnb-a", 1)
	s.gnbs["172.30.1.20:48999"] = fresh
	s.markGNBReady(fresh)

	snaps := s.GNBSnapshots()
	if len(snaps) != 1 || snaps[0].State != GNBStateNGReady {
		t.Fatalf("snaps = %+v, want a single NG_READY row", snaps)
	}
}

func TestObserveNGReset_RecordsWithoutStateChange(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newRegistryServer(clk)
	g := newTestGNB(clk, "gnb-a", 1)
	s.gnbs["a"] = g
	s.markGNBReady(g)

	s.observeNGReset(g)

	snaps := s.GNBSnapshots()
	if snaps[0].State != GNBStateNGReady || snaps[0].NGResetCount != 1 || snaps[0].LastNGResetAt == nil {
		t.Fatalf("snap = %+v", snaps[0])
	}
}

func TestGNBSnapshots_ConcurrentWithNGSetup(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newRegistryServer(clk)
	g := newTestGNB(clk, "gnb-a", 1)
	s.gnbs["a"] = g

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = s.GNBSnapshots()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.markGNBReady(g)
				s.observeNGReset(g)
			}
		}()
	}
	wg.Wait()
}

func TestN2ListenAddr(t *testing.T) {
	s := newRegistryServer(&fakeClock{t: time.Unix(1, 0)})
	if s.N2ListenAddr() != "0.0.0.0:38412" {
		t.Errorf("N2ListenAddr = %q", s.N2ListenAddr())
	}
}
