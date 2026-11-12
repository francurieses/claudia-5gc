package gtpu

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// legacyDLContainer is the hard-coded pre-REL19-6.3 PDU Session Container block.
func legacyDLContainer(qfi uint8) []byte {
	return []byte{0, 0, 0, 0x85, 0x01, 0x00, qfi & 0x3F, 0x00}
}

// legacyDLHeader is the hard-coded pre-REL19-6.3 16-octet header.
func legacyDLHeader(teid uint32, qfi uint8, innerLen int) []byte {
	h := []byte{0x34, 0xFF, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(h[2:4], uint16(8+innerLen))
	binary.BigEndian.PutUint32(h[4:8], teid)
	return append(h, legacyDLContainer(qfi)...)
}

func TestDLContainerLegacyIdentical(t *testing.T) {
	qfis := []uint8{0xFF}
	for q := 0; q < 64; q++ {
		qfis = append(qfis, uint8(q))
	}
	optSets := []*DLHeaderOptions{nil, {}, {PDUSet: nil}}
	for _, qfi := range qfis {
		for _, o := range optSets {
			if got, want := buildDLPDUSessionContainerOpts(qfi, o), legacyDLContainer(qfi); !bytes.Equal(got, want) {
				t.Fatalf("container qfi=%#x opts=%v: got %x want %x", qfi, o, got, want)
			}
		}
		if got := buildDLPDUSessionContainer(qfi); !bytes.Equal(got, legacyDLContainer(qfi)) {
			t.Fatalf("buildDLPDUSessionContainer qfi=%#x: got %x", qfi, got)
		}
		for _, n := range []int{0, 1, 28, 1400, 1456, 65000} {
			want := legacyDLHeader(0xDEADBEEF, qfi, n)
			h := make([]byte, dlHeadroom)
			putDLHeader(h, 0xDEADBEEF, qfi, n)
			if !bytes.Equal(h, want) {
				t.Fatalf("putDLHeader qfi=%#x n=%d: got %x want %x", qfi, n, h, want)
			}
			for _, o := range optSets {
				h2 := make([]byte, dlHeadroom)
				if l := putDLHeaderOpts(h2, 0xDEADBEEF, qfi, n, o); l != dlHeadroom || dlHeaderLen(o) != dlHeadroom {
					t.Fatalf("len = %d/%d, want %d", l, dlHeaderLen(o), dlHeadroom)
				}
				if !bytes.Equal(h2, want) {
					t.Fatalf("putDLHeaderOpts qfi=%#x n=%d: got %x want %x", qfi, n, h2, want)
				}
			}
		}
	}
}

func TestDLHeaderPDUSetLayout(t *testing.T) {
	tests := []struct {
		name string
		qfi  uint8
		p    PDUSetInfo
		want []byte // PDU Set Information Container (length octet .. next-type)
	}{
		{"no PSSize, padded 6", 9, PDUSetInfo{EPDU: true, PSI: 5, PSSN: 0x2A5, PSN: 7},
			[]byte{0x02, 0x04, 9<<2 | 0x02, 0xA5, 0x05, 0x07, 0x00, 0x00}},
		{"EDB only", 5, PDUSetInfo{EDB: true},
			[]byte{0x02, 0x08, 5 << 2, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"PSSize padded 10", 1, PDUSetInfo{HasPSSize: true, PSSize: 0xABCDEF, PSN: 1, PSSN: 1},
			[]byte{0x03, 0x02, 1 << 2, 0x01, 0x00, 0x01, 0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00}},
		{"all set", 63, PDUSetInfo{EDB: true, EPDU: true, HasPSSize: true, PSSize: 1, PSI: 15, PSSN: 0x3FF, PSN: 0xFF},
			[]byte{0x03, 0x0E, 63<<2 | 0x03, 0xFF, 0x0F, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := &DLHeaderOptions{PDUSet: &tc.p}
			const inner = 100
			h := make([]byte, dlHeaderLen(o))
			n := putDLHeaderOpts(h, 0x01020304, tc.qfi, inner, o)
			if n != len(h) || n != dlHeadroom+len(tc.want) {
				t.Fatalf("len %d, want %d", n, dlHeadroom+len(tc.want))
			}
			// content (excluding length octet and next-type) is 4n-2 octets
			if (len(tc.want)-2)%4 != 2 {
				t.Fatalf("test vector content not 4n-2")
			}
			if !bytes.Equal(h[dlHeadroom:], tc.want) {
				t.Fatalf("pdu set container % x, want % x", h[dlHeadroom:], tc.want)
			}
			// PDU Session Container unchanged except the next-ext-type chain
			if h[11] != 0x85 || h[15] != 0x04 || h[len(h)-1] != 0x00 {
				t.Fatalf("ext chain %#x -> %#x -> %#x", h[11], h[15], h[len(h)-1])
			}
			if h[14] != tc.qfi&0x3F || h[12] != 1 || h[13] != 0 {
				t.Fatalf("PDU Session Container % x", h[12:15])
			}
			if got, want := binary.BigEndian.Uint16(h[2:4]), uint16(8+len(tc.want)+inner); got != want {
				t.Fatalf("GTP-U length %d, want %d", got, want)
			}
			if got := buildDLPDUSessionContainerOpts(tc.qfi, o); !bytes.Equal(got, h[gtpuMinHdr:]) {
				t.Fatalf("container builder % x", got)
			}
		})
	}
}

func TestDLHeaderPDUSetMasksRanges(t *testing.T) {
	o := &DLHeaderOptions{PDUSet: &PDUSetInfo{PSI: 0xFF, PSSN: 0xFFFF, HasPSSize: true, PSSize: 0xFFFFFFFF}}
	if o.Validate() == nil {
		t.Fatal("Validate accepted out-of-range fields")
	}
	h := make([]byte, dlHeaderLen(o))
	putDLHeaderOpts(h, 1, 0xFF, 0, o)
	c := h[dlHeadroom:]
	if c[2] != 0x3F<<2|0x03 || c[3] != 0xFF || c[4] != 0x0F || c[6] != 0xFF || c[7] != 0xFF || c[8] != 0xFF {
		t.Fatalf("masked container % x", c)
	}
	if c[1]&1 != 0 || c[4]&0xF0 != 0 {
		t.Fatalf("spare bits set: % x", c)
	}
	if err := (&DLHeaderOptions{PDUSet: &PDUSetInfo{PSI: 15, PSSN: 1023, HasPSSize: true, PSSize: 1<<24 - 1}}).Validate(); err != nil {
		t.Fatalf("boundary values rejected: %v", err)
	}
	if (*DLHeaderOptions)(nil).Validate() != nil {
		t.Fatal("nil options must validate")
	}
}
