package pfcpx

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
)

func TestTypeValues(t *testing.T) {
	cases := map[uint16]uint16{
		272: PartialFailureInformation, 275: RATType, 291: GroupID, 300: MBSSessionN4mbControlInformation,
		323: TrafficParameterMeasurementControlInformation, 330: MPQUICControlInformation,
		347: MTSDTControlInformation, 353: UELevelMeasurementsConfiguration,
		277: L2TPSessionInformation, 279: CreatedL2TPSession, 311: MBSSessionN4Information,
		315: PeerUPRestartReport, 354: N6DelayMeasurementProtocols, 380: HeaderHandlingReportingIndication,
		382: SMFChangeReason, 403: PDUSetImportanceForN6UnmarkedPDUs,
	}
	for want, got := range cases {
		if want != got {
			t.Errorf("const = %d, want %d", got, want)
		}
		if Name(want) == "" {
			t.Errorf("no name for %d", want)
		}
	}
	if KnownByGoPFCP(272) || !KnownByGoPFCP(271) {
		t.Error("KnownByGoPFCP boundary wrong")
	}
	// Table 8.1.2-1: 273 is Spare, 381 is "Can be used"; every other value
	// 272..lastSpecType is assigned.
	for tp := uint16(272); tp <= lastSpecType; tp++ {
		unassigned := tp == 273 || tp == 381
		if (Name(tp) == "") != unassigned {
			t.Errorf("type %d: name %q, unassigned=%v", tp, Name(tp), unassigned)
		}
	}
	if Name(lastSpecType+1) != "" || len(ieNames) != int(lastSpecType)-271-2 {
		t.Errorf("table size %d", len(ieNames))
	}
	// Grouped per Table 8.1.2-1 (clause 7 table reference) and scalar spot checks.
	for _, tp := range []uint16{PartialFailureInformation, PeerUPRestartReport, ProtocolDescription,
		HeaderHandlingControlInformation, ProtocolSpecificConfigurationParameters, RemoteN3N9TunnelInformation} {
		if !IsGrouped(tp) {
			t.Errorf("type %d should be grouped", tp)
		}
	}
	for _, tp := range []uint16{OffendingIEInformation, RATType, DSCPToPPIMappingInformation,
		MPQUICControlInformation, MTSDTControlInformation, URI} {
		if IsGrouped(tp) {
			t.Errorf("type %d should not be grouped", tp)
		}
	}
	if len(groupedTypes) != 33 {
		t.Errorf("grouped count %d, want 33", len(groupedTypes))
	}
	for tp := range groupedTypes {
		if tp <= 271 || Name(tp) == "" {
			t.Errorf("grouped type %d out of table", tp)
		}
	}
}

func TestScalarRoundTrip(t *testing.T) {
	b, err := NewMaximumReceiveUnit(1500).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ie.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := MaximumReceiveUnitValue(p); err != nil || v != 1500 {
		t.Fatalf("MRU = %d, %v", v, err)
	}
	if _, err := RATTypeValue(p); err == nil {
		t.Error("wrong type accepted")
	}
	if _, err := MaximumReceiveUnitValue(ie.New(MaximumReceiveUnit, []byte{1})); err == nil {
		t.Error("short payload accepted")
	}
	if v, _ := RATTypeValue(NewRATType(6)); v != 6 {
		t.Error("RAT")
	}
	if v, _ := URIValue(NewURI("http://x/y")); v != "http://x/y" {
		t.Error("URI")
	}
	if v, _ := GroupIDValue(NewGroupID([]byte{1, 2})); len(v) != 2 {
		t.Error("GroupID")
	}
}

func TestGroupedUnknownTypeRoundTrip(t *testing.T) {
	g, err := NewGrouped(MPQUICParameters, NewRATType(6), NewURI("a"), NewMaximumReceiveUnit(9))
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// header (type 331 = 0x014b, len 16) + RAT(5) + URI(5) + MRU(6)
	want := []byte{0x01, 0x4b, 0, 16, 0x01, 0x13, 0, 1, 6, 0x01, 0x60, 0, 1, 'a', 0x01, 0x1f, 0, 2, 0, 9}
	if string(b) != string(want) {
		t.Fatalf("bytes % x", b)
	}
	p, err := ie.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	kids, err := ParseGrouped(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(kids) != 3 || kids[0].Type != RATType || kids[2].Type != MaximumReceiveUnit {
		t.Fatalf("kids %v", kids)
	}
	if k, _ := FindChild(p, URI); k == nil || string(k.Payload) != "a" {
		t.Error("FindChild")
	}
	// truncated child
	bad := ie.New(MPQUICParameters, []byte{0x01, 0x13, 0, 5, 1})
	if _, err := ParseGrouped(bad); err == nil {
		t.Error("truncated child accepted")
	}
}

func TestGroupedKnownTypeUsesGoPFCP(t *testing.T) {
	g, err := NewGrouped(ie.CreatePDR, ie.NewPDRID(1))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ie.NewCreatePDR(ie.NewPDRID(1)).Marshal()
	got, _ := g.Marshal()
	if string(got) != string(want) {
		t.Error("known grouped type differs from go-pfcp")
	}
}

// TestFeaturesMatchGoPFCP keeps the table compatible with go-pfcp v0.0.14.
func TestFeaturesMatchGoPFCP(t *testing.T) {
	has := map[string]func(*ie.IE) bool{
		"BUCP": (*ie.IE).HasBUCP, "DDND": (*ie.IE).HasDDND, "DLBD": (*ie.IE).HasDLBD, "TRST": (*ie.IE).HasTRST,
		"FTUP": (*ie.IE).HasFTUP, "PFDM": (*ie.IE).HasPFDM, "HEEU": (*ie.IE).HasHEEU, "TREU": (*ie.IE).HasTREU,
		"EMPU": (*ie.IE).HasEMPU, "PDIU": (*ie.IE).HasPDIU, "UDBC": (*ie.IE).HasUDBC, "QUOAC": (*ie.IE).HasQUOAC,
		"TRACE": (*ie.IE).HasTRACE, "FRRT": (*ie.IE).HasFRRT, "PFDE": (*ie.IE).HasPFDE, "EPFAR": (*ie.IE).HasEPFAR,
		"DPDRA": (*ie.IE).HasDPDRA, "ADPDP": (*ie.IE).HasADPDP, "UEIP": (*ie.IE).HasUEIP, "SSET": (*ie.IE).HasSSET,
		"MNOP": (*ie.IE).HasMNOP, "MTE": (*ie.IE).HasMTE, "BUNDL": (*ie.IE).HasBUNDL, "GCOM": (*ie.IE).HasGCOM,
		"MPAS": (*ie.IE).HasMPAS, "RTTL": (*ie.IE).HasRTTL, "VTIME": (*ie.IE).HasVTIME,
	}
	for name, fn := range has {
		f, ok := UPFeature(name)
		if !ok {
			t.Fatalf("missing UP bit %s", name)
		}
		i, _ := NewUPFunctionFeatures(name)
		if !fn(i) {
			t.Errorf("UP %s: go-pfcp does not see bit set by pfcpx (octet %d mask %#x)", name, f.Octet, f.Mask)
		}
		// no other go-pfcp helper may fire on a different bit
		other, _ := NewUPFunctionFeatures()
		if fn(other) {
			t.Errorf("UP %s set on empty IE", name)
		}
	}
	for _, name := range []string{"EPFAR", "SSET", "BUNDL", "MPAS"} {
		i, _ := NewCPFunctionFeatures(name)
		if !map[string]func(*ie.IE) bool{"EPFAR": (*ie.IE).HasEPFAR, "SSET": (*ie.IE).HasSSET,
			"BUNDL": (*ie.IE).HasBUNDL, "MPAS": (*ie.IE).HasMPAS}[name](i) {
			t.Errorf("CP %s mismatch", name)
		}
	}
	// byte-identical with go-pfcp for the legacy 4-octet form
	a, _ := NewUPFunctionFeatures("FTUP", "UEIP", "MPAS")
	b := ie.NewUPFunctionFeatures(0x10, 0x00, 0x04, 0x01)
	am, _ := a.Marshal()
	bm, _ := b.Marshal()
	if string(am) != string(bm) {
		t.Errorf("% x vs % x", am, bm)
	}
}

func TestFeatureTableInvariants(t *testing.T) {
	for _, tab := range [][]Feature{UPFeatures, CPFeatures} {
		seen := map[[2]int]string{}
		for _, f := range tab {
			if f.Mask == 0 || f.Mask&(f.Mask-1) != 0 {
				t.Errorf("%s: mask %#x not a single bit", f.Name, f.Mask)
			}
			k := [2]int{f.Octet, int(f.Mask)}
			if p, dup := seen[k]; dup {
				t.Errorf("%s duplicates %s", f.Name, p)
			}
			seen[k] = f.Name
		}
	}
	// Table 8.2.25-1: octets 5-14 full, octet 15 bits 1-7; Table 8.2.58-1: 11 bits.
	if len(UPFeatures) != 87 || len(CPFeatures) != 11 {
		t.Errorf("table sizes %d/%d", len(UPFeatures), len(CPFeatures))
	}
	f, _ := UPFeature("ULM")
	i, unk := NewUPFunctionFeatures("ULM", "NOPE")
	if len(i.Payload) != 11 || !f.Set(i.Payload) || len(unk) != 1 || i.Payload[10] != 0x04 {
		t.Errorf("rel-19 octet: % x %v", i.Payload, unk)
	}
	if got := SetUPFeatures(i); len(got) != 1 || got[0] != "ULM" {
		t.Errorf("SetUPFeatures %v", got)
	}
	if f.Bit() != 3 {
		t.Error("Bit")
	}
	// Spec octet/bit spot checks (octet numbers as in the TS, payload index + 5).
	for _, c := range []struct {
		cp        bool
		name      string
		octet, bt int
	}{
		{false, "MTE", 7, 6}, {false, "ATSSS-LL", 9, 1}, {false, "MT-EDT", 9, 4}, {false, "PSUPRM", 11, 3},
		{false, "EPPPI", 11, 4}, {false, "MPQUIC-UDP", 11, 8}, {false, "CN-TL", 13, 2}, {false, "MT-SDT", 13, 5},
		{false, "UMN6IP", 13, 7}, {false, "UN6TU", 13, 8}, {false, "UN6DM", 14, 2}, {false, "PAPFD", 15, 7},
		{true, "RPGUR", 6, 2}, {true, "PAPFD", 6, 3},
	} {
		look := UPFeature
		if c.cp {
			look = CPFeature
		}
		f, ok := look(c.name)
		if !ok || f.Octet+5 != c.octet || f.Bit() != c.bt {
			t.Errorf("%s: got %d/%d, want %d/%d", c.name, f.Octet+5, f.Bit(), c.octet, c.bt)
		}
	}
	if len(SetUPFeatures(ie.New(ie.CPFunctionFeatures, []byte{1}))) != 0 {
		t.Error("wrong type")
	}
}

// TestTsharkDecodesCraftedIEs writes a pcap with a Heartbeat-sized PFCP message
// carrying extension IEs and asserts tshark flags nothing malformed.
func TestTsharkDecodesCraftedIEs(t *testing.T) {
	ts, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("tshark not installed")
	}
	grp, err := NewGrouped(MPQUICParameters, NewRATType(6))
	if err != nil {
		t.Fatal(err)
	}
	upf, _ := NewUPFunctionFeatures("FTUP", "UEIP", "ULM")
	cpf, _ := NewCPFunctionFeatures("LOAD", "PSUCC")
	var ies []byte
	for _, i := range []*ie.IE{ie.NewRecoveryTimeStamp(testTime), upf, cpf, NewMaximumReceiveUnit(1400), NewGroupID([]byte{1, 2, 3}), grp} {
		b, err := i.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		ies = append(ies, b...)
	}
	// PFCP header (no SEID): ver=1, type 5 (Association Setup Request), len, seq(3), spare
	pfcp := []byte{0x20, 0x05, 0, byte(4 + len(ies)), 0, 0, 1, 0}
	pfcp = append(pfcp, ies...)
	pcap := buildPcap(pfcp)
	path := filepath.Join(t.TempDir(), "crafted.pcap")
	if err := os.WriteFile(path, pcap, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(ts, "-r", path, "-V").CombinedOutput()
	if err != nil {
		t.Fatalf("tshark: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "PFCP") {
		t.Fatalf("no PFCP layer:\n%s", s)
	}
	for _, bad := range []string{"Malformed", "Expert Info (Error", "Short"} {
		if strings.Contains(s, bad) {
			t.Fatalf("tshark reports %q:\n%s", bad, s)
		}
	}
	for _, want := range []string{"Maximum Receive Unit", "Group ID", "UP Function Features", "CP Function Features"} {
		if !strings.Contains(s, want) {
			t.Errorf("tshark did not decode %q", want)
		}
	}
}
