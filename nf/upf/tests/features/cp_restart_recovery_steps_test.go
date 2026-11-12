//go:build functional

// Step definitions for cp_restart_recovery.feature: an in-process pfcp.Server on
// loopback UDP, driven with real PFCP messages (go-pfcp) playing the SMF.
// Ref: TS 29.244 §6.2.6, §7.4.4.1.
package features

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/cucumber/godog"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
)

type cpWorld struct {
	table  *pfcp.SessionTable
	srv    *pfcp.Server
	cancel context.CancelFunc
	addr   *net.UDPAddr
	seq    uint32
}

// cpRTS maps the symbolic stamps of the feature to times: T<n> = base + n minutes.
func cpRTS(name string) time.Time {
	var n int
	_, _ = fmt.Sscanf(name, "T%d", &n)
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(n) * time.Minute)
}

func (w *cpWorld) rt(msg pfcpmsg.Message) error {
	conn, err := net.DialUDP("udp", nil, w.addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	b := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(b); err != nil {
		return err
	}
	if _, err := conn.Write(b); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	_, err = conn.Read(buf)
	return err
}

func (w *cpWorld) given(rts string) error {
	w.table = pfcp.NewSessionTable()
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	a, err := freeUDPAddr()
	if err != nil {
		return err
	}
	if w.srv, err = pfcp.New(pfcp.Config{Address: a, NodeIP: "127.0.0.1", RAInterval: time.Hour}, log, w.table); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	go func() { _ = w.srv.Start(ctx) }()
	if w.addr, err = net.ResolveUDPAddr("udp", a); err != nil {
		return err
	}
	return w.assoc(rts)
}

func (w *cpWorld) assoc(rts string) error {
	w.seq++
	return w.rt(pfcpmsg.NewAssociationSetupRequest(w.seq, pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewRecoveryTimeStamp(cpRTS(rts))))
}

func (w *cpWorld) heartbeat(rts string) error {
	w.seq++
	return w.rt(pfcpmsg.NewHeartbeatRequest(w.seq, pfcpie.NewRecoveryTimeStamp(cpRTS(rts)), nil))
}

func (w *cpWorld) establish(n int) error {
	for i := 0; i < n; i++ {
		w.seq++
		seid := uint64(0x500 + i)
		err := w.rt(pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, w.seq, 0,
			pfcpie.NewNodeID("", "", "smf"),
			pfcpie.NewFSEID(seid, net.ParseIP("127.0.0.1"), nil),
			pfcpie.NewCreatePDR(pfcpie.NewPDRID(1), pfcpie.NewPrecedence(100),
				pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
					pfcpie.NewFTEID(0x01, uint32(0x600+i), net.ParseIP("127.0.0.1"), nil, 0),
					pfcpie.NewUEIPAddress(0x02, fmt.Sprintf("10.60.0.%d", 10+i), "", 0, 0),
					pfcpie.NewNetworkInstance("internet")),
				pfcpie.NewOuterHeaderRemoval(0, 0), pfcpie.NewFARID(1)),
			pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02))))
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *cpWorld) count(n int) error {
	if got := len(w.table.Snapshot()); got != n {
		return fmt.Errorf("UPF holds %d PFCP sessions, want %d", got, n)
	}
	return nil
}

func registerCPRecoverySteps(sc *godog.ScenarioContext) {
	w := &cpWorld{}
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if w.cancel != nil {
			w.cancel()
		}
		*w = cpWorld{}
		return ctx, nil
	})
	sc.Step(`^a UPF PFCP server with an SMF associated with Recovery Time Stamp "(T\d+)"$`, w.given)
	sc.Step(`^the SMF has (\d+) established PFCP sessions$`, w.establish)
	sc.Step(`^the SMF sends a PFCP Association Setup Request with Recovery Time Stamp "(T\d+)"$`, w.assoc)
	sc.Step(`^the SMF sends a PFCP Heartbeat Request with Recovery Time Stamp "(T\d+)"$`, w.heartbeat)
	sc.Step(`^the UPF holds (\d+) PFCP sessions$`, w.count)
}
