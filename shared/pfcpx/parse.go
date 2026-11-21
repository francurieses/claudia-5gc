package pfcpx

import (
	"fmt"

	"github.com/wmnsk/go-pfcp/message"
)

// ParseMessage is go-pfcp's message.Parse, but it returns an error instead of panicking on
// malformed IE framing. go-pfcp v0.0.14 ie.ParseMultiIEs, used by every message and grouped-IE
// parser, slices past the buffer when a vendor-specific IE (type bit 15 set) is shorter than its
// 2-octet Enterprise ID (TS 29.244 §8.1.1): one such datagram on N4 would crash the NF. Every PFCP
// read path in the SMF and UPF parses through here (CI-003, found by FuzzParseGrouped).
func ParseMessage(b []byte) (m message.Message, err error) {
	defer func() {
		if r := recover(); r != nil {
			m, err = nil, fmt.Errorf("pfcpx: parse message: malformed IE framing: %v", r)
		}
	}()
	return message.Parse(b)
}
