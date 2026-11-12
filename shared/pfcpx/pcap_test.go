package pfcpx

import (
	"encoding/binary"
	"time"
)

var testTime = time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)

// buildPcap wraps one PFCP payload in Ethernet/IPv4/UDP(8805) in a classic
// little-endian pcap (link type 1). Checksums are left zero.
func buildPcap(pfcp []byte) []byte {
	udpLen := 8 + len(pfcp)
	ipLen := 20 + udpLen
	frame := make([]byte, 14+ipLen)
	copy(frame[0:6], []byte{0, 0, 0, 0, 0, 2})
	copy(frame[6:12], []byte{0, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(frame[12:], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(ipLen))
	ip[8], ip[9] = 64, 17
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:], 8805)
	binary.BigEndian.PutUint16(udp[2:], 8805)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], pfcp)

	out := make([]byte, 24+16, 24+16+len(frame))
	binary.LittleEndian.PutUint32(out[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(out[4:], 2)
	binary.LittleEndian.PutUint16(out[6:], 4)
	binary.LittleEndian.PutUint32(out[16:], 65535)
	binary.LittleEndian.PutUint32(out[20:], 1)
	binary.LittleEndian.PutUint32(out[24:], uint32(testTime.Unix()))
	binary.LittleEndian.PutUint32(out[32:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(out[36:], uint32(len(frame)))
	return append(out, frame...)
}
