package pfcp

import (
	"encoding/json"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// describeFixture builds session "S" of the feature file: CP=UP SEID 9,
// UE 10.60.0.7, QER 1 (Session-AMBR, no QFI) and QER 2 (QFI 1, no MBR).
func describeFixture(seid uint64, ip string) *Session {
	return &Session{
		CPSEID: seid, UPSEID: seid, ULTEID: 0x1001, DLTEID: 0x2002,
		UEIP: net.ParseIP(ip).To4(), GNBIP: net.ParseIP("172.30.3.10").To4(),
		DNN:     "internet",
		SMFAddr: &net.UDPAddr{IP: net.ParseIP("172.30.4.2"), Port: 8805},
		QERs: map[uint32]*QERState{
			2: {QERID: 2, QFI: 1, HasQFI: true},
			1: {QERID: 1, HasMBR: true, MBRULKbps: 8000, MBRDLKbps: 8000},
		},
		PDRs: map[uint16]*PDRState{
			1: {PDRID: 1, SourceInterface: srcInterfaceAccess, Precedence: noPrecedence, QERIDs: []uint32{1, 2}},
		},
	}
}

func TestDescribeFields(t *testing.T) {
	tbl := NewSessionTable()
	tbl.Add(describeFixture(9, "10.60.0.7"))
	got := tbl.Describe(DescribeFilter{})
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	d := got[0]
	if d.CPSEID != 9 || d.UPSEID != 9 || d.UEIPv4 != "10.60.0.7" || d.DNN != "internet" ||
		d.ULTEID != 0x1001 || d.DLTEID != 0x2002 || d.GNBN3IP != "172.30.3.10" || d.SMFAddr != "172.30.4.2:8805" {
		t.Fatalf("unexpected description %+v", d)
	}
	if d.UEIPv6 != "" || d.URR.Installed {
		t.Fatalf("ipv6/urr should be empty: %+v", d)
	}
	if len(d.QERs) != 2 || d.QERs[0].QERID != 1 || d.QERs[1].QERID != 2 {
		t.Fatalf("qers %+v", d.QERs)
	}
	q1, q2 := d.QERs[0], d.QERs[1]
	if !q1.HasMBR || q1.MBRULKbps != 8000 || q1.MBRDLKbps != 8000 || q1.QFI != nil {
		t.Fatalf("q1 %+v", q1)
	}
	if q2.HasMBR || q2.QFI == nil || *q2.QFI != 1 || q2.GateUL != "OPEN" || q2.GateDL != "OPEN" {
		t.Fatalf("q2 %+v", q2)
	}
	p := d.PDRs[0]
	if p.SourceInterface != "ACCESS" || p.Precedence != nil || !reflect.DeepEqual(p.QERIDs, []uint32{1, 2}) {
		t.Fatalf("pdr %+v", p)
	}
	b, _ := json.Marshal(d)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["ue_ipv6"]; ok {
		t.Fatal("ue_ipv6 must be omitted")
	}
	qm := m["qers"].([]any)[0].(map[string]any)
	if _, ok := qm["qfi"]; ok {
		t.Fatal("qfi must be omitted on QER 1")
	}
}

func TestDescribeGatesAndPrecedence(t *testing.T) {
	s := describeFixture(9, "10.60.0.7")
	s.QERs[2].GateUL = gateClosed
	s.QERs[1].GateDL = 2 // spare
	s.PDRs[1].Precedence = 100
	s.PDRs[1].SourceInterface = 7
	tbl := NewSessionTable()
	tbl.Add(s)
	d := tbl.Describe(DescribeFilter{})[0]
	if d.QERs[1].GateUL != "CLOSED" || d.QERs[1].GateDL != "OPEN" || d.QERs[0].GateDL != "CLOSED" {
		t.Fatalf("gates %+v", d.QERs)
	}
	if d.PDRs[0].Precedence == nil || *d.PDRs[0].Precedence != 100 || d.PDRs[0].SourceInterface != "UNKNOWN(7)" {
		t.Fatalf("pdr %+v", d.PDRs[0])
	}
}

func TestDescribeFilters(t *testing.T) {
	tbl := NewSessionTable()
	tbl.Add(describeFixture(9, "10.60.0.7"))
	tbl.Add(describeFixture(0x77, "10.60.0.8"))
	split := &Session{CPSEID: 0x100, UPSEID: 0x200}
	tbl.Add(split)
	tbl.Add(&Session{CPSEID: 0x55, UPSEID: 0x55, UEIPv6: net.ParseIP("2001:db8:60:1::1")})

	cases := []struct {
		name string
		f    DescribeFilter
		want []uint64
	}{
		{"any", DescribeFilter{}, []uint64{9, 0x55, 0x77, 0x200}},
		{"cp seid", DescribeFilter{SEID: 0x100}, []uint64{0x200}},
		{"up seid", DescribeFilter{SEID: 0x200}, []uint64{0x200}},
		{"seid 9", DescribeFilter{SEID: 9}, []uint64{9}},
		{"no match seid", DescribeFilter{SEID: 999}, nil},
		{"ipv4", DescribeFilter{UEIP: net.ParseIP("10.60.0.8")}, []uint64{0x77}},
		{"ipv4 4byte", DescribeFilter{UEIP: net.ParseIP("10.60.0.8").To4()}, []uint64{0x77}},
		{"ipv4 none", DescribeFilter{UEIP: net.ParseIP("10.60.0.99")}, nil},
		{"ipv6 in /64", DescribeFilter{UEIP: net.ParseIP("2001:db8:60:1:aaaa:bbbb:cccc:dddd")}, []uint64{0x55}},
		{"ipv6 outside", DescribeFilter{UEIP: net.ParseIP("2001:db8:60:2::1")}, nil},
		{"and ok", DescribeFilter{SEID: 9, UEIP: net.ParseIP("10.60.0.7")}, []uint64{9}},
		{"and none", DescribeFilter{SEID: 9, UEIP: net.ParseIP("10.60.0.8")}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := tbl.Describe(c.f)
			if got == nil {
				t.Fatal("nil result")
			}
			var ids []uint64
			for _, d := range got {
				ids = append(ids, d.UPSEID)
			}
			if !reflect.DeepEqual(ids, c.want) {
				t.Fatalf("got %v want %v", ids, c.want)
			}
		})
	}
	for _, d := range tbl.Describe(DescribeFilter{SEID: 0x55}) {
		if d.UEIPv6 != "2001:db8:60:1::1" {
			t.Fatalf("ue_ipv6 %q", d.UEIPv6)
		}
	}
}

func TestDescribeDeepCopy(t *testing.T) {
	live := describeFixture(9, "10.60.0.7")
	tbl := NewSessionTable()
	tbl.Add(live)
	first := tbl.Describe(DescribeFilter{})

	// Mutating the returned value must not touch live state.
	first[0].PDRs[0].QERIDs[0] = 99
	first[0].QERs[0].MBRDLKbps = 1
	first[0].QERs = nil
	if live.PDRs[1].QERIDs[0] != 1 || live.QERs[1].MBRDLKbps != 8000 {
		t.Fatal("live state mutated through description")
	}
	again := tbl.Describe(DescribeFilter{})
	if again[0].PDRs[0].QERIDs[0] != 1 || len(again[0].QERs) != 2 {
		t.Fatalf("second description changed: %+v", again[0])
	}

	// A later live change must not alter a kept description.
	kept := tbl.Describe(DescribeFilter{})
	tbl.mu.Lock()
	live.QERs[1].MBRULKbps = 4000
	live.QERs[1].MBRDLKbps = 4000
	live.UEIP[3] = 200
	live.PDRs[1].QERIDs[1] = 42
	tbl.mu.Unlock()
	if kept[0].QERs[0].MBRULKbps != 8000 || kept[0].UEIPv4 != "10.60.0.7" || kept[0].PDRs[0].QERIDs[1] != 2 {
		t.Fatalf("kept description changed: %+v", kept[0])
	}
}

func TestDescribeURR(t *testing.T) {
	s := describeFixture(9, "10.60.0.7")
	s.URRState.URRID = 1
	s.URRState.MeasureVolume = true
	s.URRState.TriggerVOLTH = true
	s.URRState.VolumeThreshold = 1000000
	s.URRState.MeasurementPeriod = 90 * time.Second
	s.URRState.Installed = true
	tbl := NewSessionTable()
	tbl.Add(s)
	for i := 0; i < 3; i++ {
		s.AddULVolume(1000)
	}
	s.AddDLVolume(600)
	s.AddDLVolume(600)
	s.URRState.URSeqn.Store(4)
	u := tbl.Describe(DescribeFilter{})[0].URR
	want := URRDescription{
		Installed: true, URRID: 1, MeasureVolume: true, TriggerVOLTH: true,
		VolumeThresholdBytes: 1000000, MeasurementPeriodSecs: 90,
		ULVolumeBytes: 3000, ULPackets: 3, DLVolumeBytes: 1200, DLPackets: 2, URSeqn: 4,
	}
	if u != want {
		t.Fatalf("urr %+v want %+v", u, want)
	}
}

func TestDescribeRace(t *testing.T) {
	tbl := NewSessionTable()
	s := describeFixture(9, "10.60.0.7")
	s.URRState.Installed = true
	tbl.Add(s)

	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				s.AddULVolume(100)
				s.AddDLVolume(100)
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			seid := uint64(0x1000 + i)
			for !stop.Load() {
				tbl.Add(describeFixture(seid, "10.60.1.1"))
				tbl.delete(seid)
			}
		}(i)
	}
	for i := 0; i < 200; i++ {
		got := tbl.Describe(DescribeFilter{})
		if len(got) < 1 {
			t.Fatal("fixture session missing")
		}
	}
	stop.Store(true)
	wg.Wait()
}
