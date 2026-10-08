//go:build functional

// gnb_registry_steps_test.go — in-process godog steps for gnb_registry.feature
// (gNB registry: NG Setup decode state and TNL association lifecycle,
// TS 38.413 §8.7.1 / §8.7.4, TS 38.412 §7). Drives the real ngap.Server
// registry through its test seams and the real mgmt handler through httptest;
// no SCTP association is opened.
package features_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/cucumber/godog"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/mgmt"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
)

type gnbRegistryWorld struct {
	srv  *amfngap.Server
	now  time.Time
	gnbs map[string]*amfngap.GNBContext // by name
	addr map[string]string              // name → remote addr key
	rec  *httptest.ResponseRecorder
}

var gnbW gnbRegistryWorld

func (w *gnbRegistryWorld) reset() {
	w.now = time.Unix(1_700_000_000, 0)
	w.srv = amfngap.NewServer("0.0.0.0:38412", nil, nil,
		amfngap.AMFConfig{Name: "5GC-AMF", MCC: "001", MNC: "01"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.srv.SetClockForTest(func() time.Time { return w.now })
	w.gnbs = map[string]*amfngap.GNBContext{}
	w.addr = map[string]string{}
	w.rec = nil
}

func (w *gnbRegistryWorld) find(name string) (amfngap.GNBSnapshot, error) {
	for _, s := range w.srv.GNBSnapshots() {
		if s.RANNodeName == name {
			return s, nil
		}
	}
	return amfngap.GNBSnapshot{}, fmt.Errorf("gNB %q not in the list", name)
}

func (w *gnbRegistryWorld) connect(name, ip string, port int, id uint32) {
	g := &amfngap.GNBContext{
		Name:        name,
		RANNode:     amfngap.NewGlobalGNBForTest("001", "01", id, 32),
		RemoteAddrs: []string{ip},
		RemotePort:  port,
		UEs:         map[int64]*amfctx.UEContext{},
		IdleUEs:     map[int64]*amfctx.UEContext{},
	}
	key := fmt.Sprintf("%s:%d", ip, port)
	w.srv.AddGNBForTest(key, g)
	w.gnbs[name] = g
	w.addr[name] = key
}

func initGNBRegistrySteps(sc *godog.ScenarioContext) {
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		gnbW.reset()
		return ctx, nil
	})

	sc.Step(`^the AMF gNB registry is empty$`, func() error {
		if n := len(gnbW.srv.GNBSnapshots()); n != 0 {
			return fmt.Errorf("registry has %d entries, want 0", n)
		}
		return nil
	})

	sc.Step(`^a gNB with ID (\d+) \((\d+) bits\) named "([^"]+)" connects from "([^"]+)" port (\d+)$`,
		func(id int, _ int, name, ip string, port int) error {
			gnbW.connect(name, ip, port, uint32(id))
			return nil
		})

	sc.Step(`^a gNB named "([^"]+)" connects from "([^"]+)" port (\d+)$`,
		func(name, ip string, port int) error {
			gnbW.connect(name, ip, port, 1)
			return nil
		})

	sc.Step(`^the gNB completes NG Setup with TAC (\d+) and slice SST (\d+) SD "([^"]*)"$`,
		func(tac int, sst int, sd string) error {
			g := gnbW.gnbs["gnb-a"]
			if g == nil {
				return fmt.Errorf("no gNB connected")
			}
			g.SupportedTAs = []amfngap.SupportedTA{{TAC: uint32(tac), BroadcastPLMNs: []amfngap.PLMNSlice{{
				MCC: "001", MNC: "01",
				SliceSupport: []amfctx.SNSSAISubscribed{{SST: uint8(sst), SD: sd}},
			}}}}
			gnbW.srv.CompleteNGSetupForTest(g)
			return nil
		})

	sc.Step(`^a gNB named "([^"]+)" is NG_READY$`, func(name string) error {
		gnbW.connect(name, "172.30.1.20", 48211, 1)
		gnbW.srv.CompleteNGSetupForTest(gnbW.gnbs[name])
		return nil
	})

	sc.Step(`^the SCTP association closes with reason "([^"]+)"$`, func(reason string) error {
		gnbW.srv.DisconnectGNBForTest(gnbW.addr["gnb-a"], reason)
		return nil
	})

	sc.Step(`^(\d+) minutes pass$`, func(m int) error {
		gnbW.now = gnbW.now.Add(time.Duration(m) * time.Minute)
		return nil
	})

	sc.Step(`^a gNB with the same ID reconnects and completes NG Setup$`, func() error {
		gnbW.connect("gnb-a", "172.30.1.20", 48999, 1)
		gnbW.srv.CompleteNGSetupForTest(gnbW.gnbs["gnb-a"])
		return nil
	})

	sc.Step(`^the gNB sends an NG Reset$`, func() error {
		gnbW.srv.ObserveNGResetForTest(gnbW.gnbs["gnb-a"])
		return nil
	})

	sc.Step(`^the gNB list contains (\d+) gNBs?$`, func(want int) error {
		if got := len(gnbW.srv.GNBSnapshots()); got != want {
			return fmt.Errorf("gNB list has %d entries, want %d", got, want)
		}
		return nil
	})

	sc.Step(`^gNB "([^"]+)" has state "([^"]+)"$`, func(name, state string) error {
		s, err := gnbW.find(name)
		if err != nil {
			return err
		}
		if string(s.State) != state {
			return fmt.Errorf("gNB %q state = %s, want %s", name, s.State, state)
		}
		return nil
	})

	sc.Step(`^gNB "([^"]+)" has state "([^"]+)" with reason "([^"]+)"$`, func(name, state, reason string) error {
		s, err := gnbW.find(name)
		if err != nil {
			return err
		}
		if string(s.State) != state || s.DisconnectReason != reason {
			return fmt.Errorf("gNB %q = %s/%q, want %s/%q", name, s.State, s.DisconnectReason, state, reason)
		}
		return nil
	})

	sc.Step(`^gNB "([^"]+)" reports PLMN "([^"]+)"/"([^"]+)", gNB ID (\d+) with bit length (\d+) and TAC (\d+) with slice SST (\d+) SD "([^"]*)"$`,
		func(name, mcc, mnc string, id, bits, tac, sst int, sd string) error {
			s, err := gnbW.find(name)
			if err != nil {
				return err
			}
			if s.RANNode.PLMN.MCC != mcc || s.RANNode.PLMN.MNC != mnc || s.RANNode.GNBID != uint32(id) || int(s.RANNode.GNBIDBitLen) != bits {
				return fmt.Errorf("ran_node = %+v", s.RANNode)
			}
			if len(s.SupportedTAs) != 1 || s.SupportedTAs[0].TAC != uint32(tac) {
				return fmt.Errorf("supported_tas = %+v", s.SupportedTAs)
			}
			sl := s.SupportedTAs[0].BroadcastPLMNs[0].Slices
			if len(sl) != 1 || int(sl[0].SST) != sst || sl[0].SD != sd {
				return fmt.Errorf("slices = %+v", sl)
			}
			return nil
		})

	sc.Step(`^gNB "([^"]+)" reports remote address "([^"]+)" port (\d+)$`, func(name, ip string, port int) error {
		s, err := gnbW.find(name)
		if err != nil {
			return err
		}
		if len(s.SCTP.RemoteAddrs) != 1 || s.SCTP.RemoteAddrs[0] != ip || s.SCTP.RemotePort != port {
			return fmt.Errorf("sctp = %+v", s.SCTP)
		}
		return nil
	})

	sc.Step(`^gNB "([^"]+)" reports (\d+) NG Resets?$`, func(name string, n int) error {
		s, err := gnbW.find(name)
		if err != nil {
			return err
		}
		if s.NGResetCount != n || s.LastNGResetAt == nil {
			return fmt.Errorf("ng_reset_count = %d (last=%v), want %d", s.NGResetCount, s.LastNGResetAt, n)
		}
		return nil
	})

	sc.Step(`^I request the gNB list from the management API$`, func() error {
		h := mgmt.GNBListHandler(gnbW.srv, mgmt.AMFInfo{Name: "5GC-AMF", MCC: "001", MNC: "01"},
			slog.New(slog.NewTextHandler(io.Discard, nil)))
		gnbW.rec = httptest.NewRecorder()
		h(gnbW.rec, httptest.NewRequest(http.MethodGet, "/amf/v1/ran/gnbs", nil))
		return nil
	})

	sc.Step(`^the gNB list response status is (\d+)$`, func(want int) error {
		if gnbW.rec == nil || gnbW.rec.Code != want {
			return fmt.Errorf("status = %v, want %d", gnbW.rec, want)
		}
		return nil
	})

	sc.Step(`^the gNB list response has an empty "gnbs" array$`, func() error {
		body := gnbW.rec.Body.String()
		var v struct {
			GNBs []json.RawMessage `json:"gnbs"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			return err
		}
		if v.GNBs == nil || len(v.GNBs) != 0 || !strings.Contains(body, `"gnbs":[]`) {
			return fmt.Errorf("body = %s", body)
		}
		return nil
	})
}
