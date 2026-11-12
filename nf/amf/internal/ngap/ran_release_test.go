package ngap

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/capability"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

func TestInferRANRelease(t *testing.T) {
	ie := func(id int64) ngapType.NGSetupRequestIEs {
		return ngapType.NGSetupRequestIEs{Id: ngapType.ProtocolIEID{Value: id}}
	}
	withExt := func(ids ...int64) ngapType.NGSetupRequestIEs {
		var tx []ngapType.SupportedTAItemExtIEs
		var bpx []ngapType.BroadcastPLMNItemExtIEs
		for _, id := range ids {
			tx = append(tx, ngapType.SupportedTAItemExtIEs{Id: ngapType.ProtocolExtensionID{Value: id}})
			bpx = append(bpx, ngapType.BroadcastPLMNItemExtIEs{Id: ngapType.ProtocolExtensionID{Value: id}})
		}
		item := ngapType.SupportedTAItem{
			IEExtensions: &ngapType.ProtocolExtensionContainerSupportedTAItemExtIEs{List: tx},
			BroadcastPLMNList: ngapType.BroadcastPLMNList{List: []ngapType.BroadcastPLMNItem{{
				IEExtensions: &ngapType.ProtocolExtensionContainerBroadcastPLMNItemExtIEs{List: bpx},
			}}},
		}
		v := ie(ngapType.ProtocolIEIDSupportedTAList)
		v.Value.SupportedTAList = &ngapType.SupportedTAList{List: []ngapType.SupportedTAItem{item}}
		return v
	}
	base := []ngapType.NGSetupRequestIEs{
		ie(ngapType.ProtocolIEIDGlobalRANNodeID), ie(ngapType.ProtocolIEIDRANNodeName),
		ie(ngapType.ProtocolIEIDSupportedTAList), ie(ngapType.ProtocolIEIDDefaultPagingDRX),
	}
	tests := []struct {
		name string
		ies  []ngapType.NGSetupRequestIEs
		want capability.Release
	}{
		{"rel-17 mandatory IEs only", base, capability.Rel17},
		{"no IEs at all floors at Rel-17", nil, capability.Rel17},
		{"Extended RAN Node Name is Rel-17", append(append([]ngapType.NGSetupRequestIEs{}, base...), ie(ngapType.ProtocolIEIDExtendedRANNodeName)), capability.Rel17},
		{"AIoT Support is Rel-19", append(append([]ngapType.NGSetupRequestIEs{}, base...), ie(ngapType.ProtocolIEIDAIoTSupport)), capability.Rel19},
		{"Additional ULI is Rel-19", append(append([]ngapType.NGSetupRequestIEs{}, base...), ie(ngapType.ProtocolIEIDAdditionalULI)), capability.Rel19},
		{"unknown top-level id capped at Rel-19", append(append([]ngapType.NGSetupRequestIEs{}, base...), ie(60000)), capability.Rel19},
		{"known Rel-17 extension IEs", []ngapType.NGSetupRequestIEs{withExt(ngapType.ProtocolIEIDRATInformation, ngapType.ProtocolIEIDNPNSupport, ngapType.ProtocolIEIDTAINSAGSupportList)}, capability.Rel17},
		{"unknown extension id capped at Rel-19", []ngapType.NGSetupRequestIEs{withExt(ngapType.ProtocolIEIDRATInformation, 60001)}, capability.Rel19},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &ngapType.NGSetupRequest{ProtocolIEs: ngapType.ProtocolIEContainerNGSetupRequestIEs{List: tc.ies}}
			if got := InferRANRelease(req); got != tc.want {
				t.Errorf("InferRANRelease = %v, want %v", got, tc.want)
			}
		})
	}
	if got := InferRANRelease(nil); got != capability.Rel17 {
		t.Errorf("nil request = %v, want Rel-17", got)
	}
}

func TestParseRANRelease(t *testing.T) {
	for in, want := range map[string]capability.Release{
		"Rel-17": capability.Rel17, "rel18": capability.Rel18, "Rel19": capability.Rel19, " 17 ": capability.Rel17,
	} {
		if got, err := ParseRANRelease(in); err != nil || got != want {
			t.Errorf("ParseRANRelease(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "Rel-16", "Rel-20", "latest", "Rel-"} {
		if _, err := ParseRANRelease(in); err == nil {
			t.Errorf("ParseRANRelease(%q): want error", in)
		}
	}
}

func TestNewRANProfiles_Validation(t *testing.T) {
	tests := []struct {
		name string
		cfg  RANProfileConfig
		want string
	}{
		{"neither selector", RANProfileConfig{MaxRelease: "Rel-17"}, "exactly one"},
		{"both selectors", RANProfileConfig{GlobalRANNodeID: "01/24", GNBName: "x", MaxRelease: "Rel-17"}, "exactly one"},
		{"bad release", RANProfileConfig{GNBName: "x", MaxRelease: "Rel-16"}, "ran release"},
		{"missing release", RANProfileConfig{GNBName: "x"}, "ran release"},
		{"bad pattern", RANProfileConfig{GNBName: "[", MaxRelease: "Rel-17"}, "pattern"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRANProfiles([]RANProfileConfig{tc.cfg}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
	dupID := []RANProfileConfig{{GlobalRANNodeID: "01/24", MaxRelease: "Rel-17"}, {GlobalRANNodeID: "01/24", MaxRelease: "Rel-18"}}
	if _, err := NewRANProfiles(dupID); err == nil || !strings.Contains(err.Error(), "duplicate selector") {
		t.Errorf("duplicate id: err = %v, want duplicate selector", err)
	}
	dupName := []RANProfileConfig{{GNBName: "g*", MaxRelease: "Rel-17"}, {GNBName: "g*", MaxRelease: "Rel-19"}}
	if _, err := NewRANProfiles(dupName); err == nil || !strings.Contains(err.Error(), "duplicate selector") {
		t.Errorf("duplicate name: err = %v, want duplicate selector", err)
	}
	if _, err := NewRANProfiles(nil); err != nil {
		t.Errorf("empty config: %v", err)
	}
}

func TestRANProfiles_Resolve(t *testing.T) {
	node := NewGlobalGNBForTest("001", "01", 0x1, 24) // IDString "000001/24"
	p, err := NewRANProfiles([]RANProfileConfig{
		{GNBName: "lab-*", MaxRelease: "Rel-17"},
		{GlobalRANNodeID: "000001/24", MaxRelease: "Rel-18"},
		{GNBName: "lab-gnb-1", MaxRelease: "Rel-19"},
	})
	if err != nil {
		t.Fatal(err)
	}
	other := NewGlobalGNBForTest("001", "01", 0x2, 24)
	tests := []struct {
		name     string
		node     GlobalRANNode
		gnbName  string
		inferred capability.Release
		want     capability.Release
		matched  bool
	}{
		{"id beats earlier name entry, caps Rel-19 to Rel-18", node, "lab-gnb-1", capability.Rel19, capability.Rel18, true},
		{"first name entry wins over later one", other, "lab-gnb-1", capability.Rel19, capability.Rel17, true},
		{"cap never raises", node, "x", capability.Rel17, capability.Rel17, true},
		{"no match keeps inference", other, "prod-1", capability.Rel19, capability.Rel19, false},
		{"empty name never matches a glob", other, "", capability.Rel19, capability.Rel19, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, matched := p.Resolve(tc.node, tc.gnbName, tc.inferred)
			if got != tc.want || matched != tc.matched {
				t.Errorf("Resolve = %v,%v want %v,%v", got, matched, tc.want, tc.matched)
			}
		})
	}
	var nilP *RANProfiles
	if got, m := nilP.Resolve(node, "a", capability.Rel18); got != capability.Rel18 || m {
		t.Errorf("nil table = %v,%v", got, m)
	}
}

func TestGNBContextPeerRAN_DefaultsToRel17(t *testing.T) {
	g := &GNBContext{}
	if got := g.PeerRAN(); got.Release != capability.Rel17 {
		t.Errorf("unset = %v, want Rel-17", got.Release)
	}
	g.release = capability.Rel18
	if got := g.PeerRAN(); got.Release != capability.Rel18 {
		t.Errorf("Rel-18 = %v", got.Release)
	}
}

func runNGSetup(t *testing.T, s *Server, name string, id uint32, extraIEs ...ngapType.NGSetupRequestIEs) (*GNBContext, *Message) {
	t.Helper()
	raw := buildNGSetupRequestPDU(t, []byte{byte(id >> 16), byte(id >> 8), byte(id)}, 24, name)
	pdu, err := libngap.Decoder(raw)
	if err != nil {
		t.Fatal(err)
	}
	req := pdu.InitiatingMessage.Value.NGSetupRequest
	req.ProtocolIEs.List = append(req.ProtocolIEs.List, extraIEs...)
	gnb := &GNBContext{
		RemoteAddrs: []string{"10.0.0.1"},
		State:       GNBStateSCTPUp,
		UEs:         map[int64]*amfctx.UEContext{},
		IdleUEs:     map[int64]*amfctx.UEContext{},
	}
	gnb.SetTransportForTest("10.0.0.1:1", func([]byte, *sctp.SndRcvInfo) (int, error) { return 0, nil })
	msg := &Message{Value: extractNGSetupRequest(req)}
	s.handleNGSetup(context.Background(), gnb, msg)
	return gnb, msg
}

func TestHandleNGSetup_StoresRelease(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	aiot := ngapType.NGSetupRequestIEs{Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAIoTSupport}}

	t.Run("legacy request is Rel-17", func(t *testing.T) {
		s := newRegistryServer(clk)
		gnb, _ := runNGSetup(t, s, "gnb-a", 1)
		if got := gnb.PeerRAN().Release; got != capability.Rel17 {
			t.Errorf("release = %v, want Rel-17", got)
		}
		s.AddGNBForTest("10.0.0.1:1", gnb)
		snaps := s.GNBSnapshots()
		if len(snaps) != 1 || snaps[0].Release != "Rel-17" || snaps[0].InferredRelease != "Rel-17" || snaps[0].ReleaseOverride {
			t.Errorf("snapshot = %+v", snaps)
		}
	})
	t.Run("Rel-19 evidence is inferred", func(t *testing.T) {
		s := newRegistryServer(clk)
		gnb, _ := runNGSetup(t, s, "gnb-b", 2, aiot)
		if got := gnb.PeerRAN().Release; got != capability.Rel19 {
			t.Errorf("release = %v, want Rel-19", got)
		}
	})
	t.Run("override caps the inference", func(t *testing.T) {
		s := newRegistryServer(clk)
		p, err := NewRANProfiles([]RANProfileConfig{{GNBName: "gnb-c*", MaxRelease: "Rel-17"}})
		if err != nil {
			t.Fatal(err)
		}
		s.WithRANProfiles(p)
		gnb, _ := runNGSetup(t, s, "gnb-c1", 3, aiot)
		if got := gnb.PeerRAN().Release; got != capability.Rel17 {
			t.Errorf("release = %v, want Rel-17 (capped)", got)
		}
		s.AddGNBForTest("10.0.0.1:1", gnb)
		snaps := s.GNBSnapshots()
		if len(snaps) != 1 || snaps[0].Release != "Rel-17" || snaps[0].InferredRelease != "Rel-19" || !snaps[0].ReleaseOverride {
			t.Errorf("snapshot = %+v", snaps)
		}
	})
}
