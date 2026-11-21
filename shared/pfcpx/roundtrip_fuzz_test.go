package pfcpx

// roundtrip_fuzz_test.go — round-trip property for grouped-IE parsing, and no-panic parsing of N4
// datagrams (CI-003). For any payload
// ParseGrouped accepts, rebuilding the IE with NewGrouped from the parsed children reproduces the
// payload octet for octet, and ParseGrouped never panics. Run for an extension grouped type
// (above go-pfcp's table, children serialised by NewGrouped) and for a type go-pfcp knows.
// Ref: TS 29.244 §8.1.1 (IE format, grouped IEs), Table 8.1.2-1.

import (
	"bytes"
	"encoding/binary"
	"sort"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// extGroupedType returns the lowest extension grouped IE type in groupedTypes.
func extGroupedType(tb testing.TB) uint16 {
	var ts []int
	for t := range groupedTypes {
		ts = append(ts, int(t))
	}
	if len(ts) == 0 {
		tb.Fatal("groupedTypes is empty")
	}
	sort.Ints(ts)
	return uint16(ts[0])
}

func FuzzParseGrouped(f *testing.F) {
	ext := extGroupedType(f)
	child := func(i *ie.IE) []byte {
		b, err := i.Marshal()
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	f.Add(child(ie.NewPDRID(7)), false)
	f.Add(append(child(ie.NewPDRID(1)), child(ie.NewPrecedence(255))...), true)
	f.Add(child(ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100))), false)
	f.Add(child(NewRaw(ext, []byte{1, 2, 3})), false)
	f.Add([]byte{0x00, 0x38, 0x00, 0x05}, false) // truncated child
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, payload []byte, knownType bool) {
		typ := ext
		if knownType {
			typ = ie.CreatePDR
		}
		kids, err := ParseGrouped(NewRaw(typ, bytes.Clone(payload)))
		if err != nil {
			return
		}
		g, err := NewGrouped(typ, kids...)
		if err != nil {
			t.Fatalf("NewGrouped rejects children ParseGrouped returned: %v\n payload %x", err, payload)
		}
		b, err := g.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v\n payload %x", err, payload)
		}
		if len(b) < 4 || !bytes.Equal(b[4:], payload) {
			t.Fatalf("grouped IE type %d does not round-trip\n payload %x\n rebuilt %x", typ, payload, b)
		}
	})
}

// truncatedVendorHeartbeat is a Heartbeat Request whose last IE is vendor-specific (type 0x8030)
// with length 0: no room for the Enterprise ID. go-pfcp v0.0.14 message.Parse panics on it.
func truncatedVendorHeartbeat(tb testing.TB) []byte {
	b, err := message.NewHeartbeatRequest(1, ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)), nil).Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	b = append(b, 0x80, 0x30, 0x00, 0x00)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-4))
	return b
}

// TestParseMessageTruncatedVendorIE is the regression for the N4 crash found by FuzzParseGrouped.
func TestParseMessageTruncatedVendorIE(t *testing.T) {
	if _, err := ParseMessage(truncatedVendorHeartbeat(t)); err == nil {
		t.Fatal("ParseMessage accepted a truncated vendor-specific IE")
	}
	if _, err := ParseGrouped(NewRaw(ie.CreatePDR, []byte{0x80, 0x30, 0x00, 0x00})); err == nil {
		t.Fatal("ParseGrouped accepted a truncated vendor-specific IE")
	}
}

// FuzzParseMessage: ParseMessage never panics on an arbitrary N4 datagram.
func FuzzParseMessage(f *testing.F) {
	hb, err := message.NewHeartbeatRequest(1, ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)), nil).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(hb)
	f.Add(truncatedVendorHeartbeat(f))
	est, err := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100)), ie.NewFSEID(1, nil, nil)).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(est)
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseMessage(b) })
}
