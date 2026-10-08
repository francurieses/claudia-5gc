package gtpu

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
)

// tcpV4 builds a minimal IPv4+TCP packet with the given stored TCP checksum.
func tcpV4(csum uint16) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], 40)
	p[8], p[9] = 64, 6
	copy(p[12:], []byte{1, 1, 1, 1})
	copy(p[16:], []byte{10, 60, 0, 3})
	binary.BigEndian.PutUint16(p[20:], 80)
	binary.BigEndian.PutUint16(p[22:], 58924)
	p[32] = 5 << 4
	p[33] = 0x12
	binary.BigEndian.PutUint16(p[36:], csum)
	return p
}

func TestRepairDownlinkChecksum(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dst := net.IPv4(10, 60, 0, 3)
	tests := []struct {
		name     string
		enabled  bool
		wantHook bool
		wantFix  bool
	}{
		{"enabled repairs and fires hook", true, true, true},
		{"disabled leaves packet untouched", false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: Config{L4ChecksumRepair: tc.enabled}, logger: log}
			var gotProto, gotIP string
			calls := 0
			s.SetL4RepairHook(func(p, v string) { calls++; gotProto, gotIP = p, v })
			pkt := tcpV4(0xf76c)
			s.repairDownlinkChecksum(pkt, dst, "internet")
			changed := binary.BigEndian.Uint16(pkt[36:]) != 0xf76c
			if changed != tc.wantFix {
				t.Fatalf("changed = %v, want %v", changed, tc.wantFix)
			}
			if (calls == 1) != tc.wantHook || calls > 1 {
				t.Fatalf("hook calls = %d, want hook=%v", calls, tc.wantHook)
			}
			if tc.wantHook && (gotProto != "tcp" || gotIP != "v4") {
				t.Fatalf("hook args = %q,%q", gotProto, gotIP)
			}
			// Valid packet: no hook, no change.
			if tc.enabled {
				calls = 0
				s.repairDownlinkChecksum(pkt, dst, "internet")
				if calls != 0 {
					t.Fatal("hook fired for an already-valid packet")
				}
			}
		})
	}
	// nil hook must be safe.
	s := &Server{cfg: Config{L4ChecksumRepair: true}, logger: log}
	s.repairDownlinkChecksum(tcpV4(0xf76c), dst, "internet")
}
