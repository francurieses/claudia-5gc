package nas

import (
	"fmt"
	"io"
	"strings"
)

// UL NAS Transport message (TS 24.501 §8.7.1)
type ULNASTransport struct {
	PayloadContainerType uint8   // Payload Container Type
	PayloadContainer     []byte  // N1 SM container (5GSM PDU)
	PDUSessionID         *uint8  // Optional
	RequestType          *uint8  // Optional
	SNSSAI               *SNSSAITransport // Optional
	DNN                  *string // Optional
}

// DL NAS Transport message (TS 24.501 §8.7.2)
type DLNASTransport struct {
	PayloadContainerType uint8
	PayloadContainer     []byte
	PDUSessionID         *uint8 // Optional
	Cause5GSM            *uint8 // Optional
	// Cause5GMM is set when the AMF does not forward the 5GSM payload to the
	// SMF (e.g. the requested S-NSSAI is not in the Allowed NSSAI). The
	// payload container then echoes back the 5GSM message that was not
	// forwarded. Ref: TS 24.501 §5.4.5.2.5.
	Cause5GMM *uint8 // Optional
}

// SNSSAITransport carries SNSSAI in DL/UL NAS Transport context
type SNSSAITransport struct {
	SST uint8
	SD  *uint32 // Optional, 3 bytes if present
}

// Payload Container Type values (TS 24.501 §9.11.3.40, Table 9.11.3.40.1)
const (
	PayloadContainerTypeN1SM     uint8 = 0x01 // N1 SM information
	PayloadContainerTypeSMS      uint8 = 0x02 // SMS
	PayloadContainerTypeLPP      uint8 = 0x03 // LTE Positioning Protocol
	PayloadContainerTypeSOR      uint8 = 0x04 // SOR transparent container
	PayloadContainerTypeUEPolicy uint8 = 0x05 // UE policy container (URSP delivery)
)

// IEI values for Transport messages
const (
	IEIPayloadContainerType uint8 = 0x70
	IEIPDUSessionID         uint8 = 0x12 // TV format (2 bytes: IEI + value)
	IEIRequestTypeNibble    uint8 = 0x80 // Nibble IEI: high nibble = 0x8, low nibble = value (TV, 1 byte)
	IEISNSSAITransport      uint8 = 0x22
	IEIDNN                  uint8 = 0x25
	IEICause5GMM            uint8 = 0x58 // TV format (2 bytes: IEI + value)
)

// DecodeULNASTransport decodes an UL NAS Transport message body.
// Ref: TS 24.501 §8.7.1, table 8.7.1.2-2
func DecodeULNASTransport(b []byte) (*ULNASTransport, error) {
	if len(b) < 3 {
		return nil, fmt.Errorf("nas: UL NAS Transport too short")
	}
	r := NewReader(b)

	// Payload Container Type (1 byte)
	pctByte, _ := r.ReadByte()
	msg := &ULNASTransport{
		PayloadContainerType: pctByte,
	}

	// Payload Container (LV-E format: 2 bytes of length, big-endian)
	// TS 24.501 §9.10.1 defines container as LV-E (up to 65535 bytes)
	hi, _ := r.ReadByte()
	lo, _ := r.ReadByte()
	containerLen := (int(hi) << 8) | int(lo)
	if r.Len() < containerLen {
		return nil, fmt.Errorf("nas: payload container length invalid")
	}
	msg.PayloadContainer, _ = r.ReadBytes(containerLen)

	// Parse optional IEs
	for r.Len() > 0 {
		iei, err := r.PeekByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Handle Request Type (nibble IEI 0x8-: TV format, 1 byte)
		// TS 24.501 Table 8.7.1.2-2: IEI nibble high = 0x8, value = nibble low
		if iei&0xF0 == 0x80 {
			r.ReadByte() // consume the byte
			rtVal := iei & 0x0F
			msg.RequestType = &rtVal
			continue
		}

		switch iei {
		case IEIPDUSessionID:
			// TV format (2 bytes: IEI + value)
			// TS 24.501 Table 8.7.1.2-2: IEI 0x12, TV format
			r.ReadByte() // skip IEI
			psi, _ := r.ReadByte()
			msg.PDUSessionID = &psi

		case IEISNSSAITransport:
			r.ReadByte() // skip IEI
			lenByte, _ := r.ReadByte()
			// Valid S-NSSAI value lengths per TS 24.501 §9.11.2.8: 1 (SST),
			// 2 (SST+mapped SST), 4 (SST+SD), 5 (SST+SD+mapped SST), 8 (+mapped SD).
			if lenByte < 1 || lenByte > 8 {
				return nil, fmt.Errorf("nas: SNSSAI length invalid")
			}
			val, err := r.ReadBytes(int(lenByte))
			if err != nil {
				return nil, fmt.Errorf("nas: SNSSAI truncated: %w", err)
			}
			sst := val[0]
			var sd *uint32
			if len(val) >= 4 {
				// SD present only for lengths 4, 5, 8 (immediately after SST).
				sdVal := (uint32(val[1]) << 16) | (uint32(val[2]) << 8) | uint32(val[3])
				sd = &sdVal
			}
			msg.SNSSAI = &SNSSAITransport{SST: sst, SD: sd}

		case IEIDNN:
			r.ReadByte() // skip IEI
			lenByte, _ := r.ReadByte()
			dnnBytes, _ := r.ReadBytes(int(lenByte))
			// Decode APN label format (TS 23.003 §9.1): each label is length-prefixed.
			// PacketRusher sends DNN as "\x08internet"; plain-string senders (UERANSIM)
			// send "internet". decodeAPN handles both.
			dnnStr := decodeAPN(dnnBytes)
			msg.DNN = &dnnStr

		default:
			// Unknown IEI, skip it
			r.ReadByte()
			if r.Len() > 0 {
				lenByte, _ := r.ReadByte()
				if lenByte > 0 && r.Len() >= int(lenByte) {
					r.ReadBytes(int(lenByte))
				}
			}
		}
	}

	return msg, nil
}

// EncodeDLNASTransport encodes a DL NAS Transport message body.
// Ref: TS 24.501 §8.7.2
func EncodeDLNASTransport(msg *DLNASTransport) ([]byte, error) {
	out := make([]byte, 0, len(msg.PayloadContainer)+10)

	// Payload Container Type
	out = append(out, msg.PayloadContainerType)

	// Payload Container (LV-E format: 2 bytes of length, big-endian)
	containerLen := len(msg.PayloadContainer)
	if containerLen > 65535 {
		return nil, fmt.Errorf("nas: payload container too long")
	}
	out = append(out, byte(containerLen>>8), byte(containerLen&0xFF))
	out = append(out, msg.PayloadContainer...)

	// Optional IEs
	if msg.PDUSessionID != nil {
		// TV format: IEI + value (2 bytes total)
		out = append(out, IEIPDUSessionID)
		out = append(out, *msg.PDUSessionID)
	}

	// 5GMM cause (TV: IEI + value). Per Table 8.7.2.1.1 it precedes the
	// back-off timer IE.
	if msg.Cause5GMM != nil {
		out = append(out, IEICause5GMM)
		out = append(out, *msg.Cause5GMM)
	}

	if msg.Cause5GSM != nil {
		out = append(out, IEICause5GSM)
		out = append(out, 0x01) // length
		out = append(out, *msg.Cause5GSM)
	}

	return out, nil
}

// decodeAPN converts a DNN value from APN label format (TS 23.003 §9.1) to a
// plain dot-separated string. Plain-string encodings (first byte is a printable
// ASCII char) are returned as-is so UERANSIM interop is preserved.
//
// APN label format example: "\x08internet" → "internet"
// Multi-label: "\x08internet\x05mnc01" → "internet.mnc01"
func decodeAPN(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// Heuristic: if the first byte is a printable ASCII character (>= 0x20), treat
	// the entire value as a plain string — no length-prefix decoding needed.
	if b[0] >= 0x20 {
		return string(b)
	}
	// APN label format: each label is preceded by its length byte.
	var labels []string
	for i := 0; i < len(b); {
		l := int(b[i])
		i++
		if l == 0 || i+l > len(b) {
			break
		}
		labels = append(labels, string(b[i:i+l]))
		i += l
	}
	if len(labels) == 0 {
		return string(b)
	}
	return strings.Join(labels, ".")
}

// encodeAPN converts a plain DNN string to APN label format (TS 23.003 §9.1).
// Each dot-separated label is preceded by its length byte.
// "gaming" → [0x06,'g','a','m','i','n','g']
// "internet.mnc01" → [0x08,'i','n','t','e','r','n','e','t',0x06,'m','n','c','0','1']
func encodeAPN(dnn string) []byte {
	labels := strings.Split(dnn, ".")
	var out []byte
	for _, label := range labels {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	return out
}

// EncodeULNASTransport encodes a UL NAS Transport message body.
// Ref: TS 24.501 §8.7.1
func EncodeULNASTransport(msg *ULNASTransport) ([]byte, error) {
	out := make([]byte, 0, len(msg.PayloadContainer)+20)

	// Payload Container Type
	out = append(out, msg.PayloadContainerType)

	// Payload Container (LV-E format: 2 bytes of length, big-endian)
	containerLen := len(msg.PayloadContainer)
	if containerLen > 65535 {
		return nil, fmt.Errorf("nas: payload container too long")
	}
	out = append(out, byte(containerLen>>8), byte(containerLen&0xFF))
	out = append(out, msg.PayloadContainer...)

	// Optional IEs
	if msg.PDUSessionID != nil {
		// TV format: IEI + value (2 bytes total)
		// TS 24.501 Table 8.7.1.2-2: IEI 0x12, TV format
		out = append(out, IEIPDUSessionID)
		out = append(out, *msg.PDUSessionID)
	}

	if msg.RequestType != nil {
		// TV nibble format: IEI nibble high = 0x8, value = nibble low (1 byte total)
		// TS 24.501 Table 8.7.1.2-2: nibble IEI 0x8-, TV format
		out = append(out, 0x80|(*msg.RequestType&0x0F))
	}

	if msg.SNSSAI != nil {
		out = append(out, IEISNSSAITransport)
		var snssaiBytes []byte
		snssaiBytes = append(snssaiBytes, msg.SNSSAI.SST)
		if msg.SNSSAI.SD != nil {
			sd := *msg.SNSSAI.SD
			snssaiBytes = append(snssaiBytes,
				byte((sd>>16)&0xFF),
				byte((sd>>8)&0xFF),
				byte(sd&0xFF),
			)
		}
		out = append(out, byte(len(snssaiBytes)))
		out = append(out, snssaiBytes...)
	}

	if msg.DNN != nil {
		dnnBytes := []byte(*msg.DNN)
		if len(dnnBytes) > 255 {
			return nil, fmt.Errorf("nas: DNN too long")
		}
		out = append(out, IEIDNN)
		out = append(out, byte(len(dnnBytes)))
		out = append(out, dnnBytes...)
	}

	return out, nil
}
