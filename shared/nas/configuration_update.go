package nas

import "fmt"

// ---- Configuration Update Command (TS 24.501 §8.2.29) -------------------

// ConfigurationUpdateCommand is the 5GMM Configuration Update Command message
// sent downlink from the AMF to the UE.
//
// The AMF sends this for GUTI reallocation, NSSAI changes, or TAI list updates.
// When the ACK bit is set in ConfigUpdateIndication the UE replies with
// ConfigurationUpdateComplete.
//
// NOTE: URSP / UE policies are NOT carried in this message. They are delivered
// via the UE policy delivery service over DL NAS TRANSPORT (payload container
// type "UE policy container", 0x05). IEI 0x7B in this message is "S-NSSAI
// location validity information", not a UE policy container.
//
// Ref: TS 24.501 §8.2.29
type ConfigurationUpdateCommand struct {
	// IEI 0xD- — Configuration update indication (TV, 1 byte, high nibble 0xD)
	// Bit 1 (ACKS): 1 = ACK requested from UE (ConfigurationUpdateComplete expected)
	// Ref: TS 24.501 §9.11.3.18
	ConfigUpdateIndication *byte
	// IEI 0x77 — 5G-GUTI (TLV-E, 2-byte length) — optional GUTI reallocation
	FiveGGUTI *MobileIdentity
	// IEI 0x54 — TAI list (TLV, 1-byte length)
	TAIList []byte
	// IEI 0x15 — Allowed NSSAI (TLV, 1-byte length)
	AllowedNSSAI *NSSAI
	// IEI 0x31 — Configured NSSAI (TLV, 1-byte length)
	ConfiguredNSSAI *NSSAI
	// IEI 0x9A — Network slicing indication (TV, 1 byte, high nibble 0x9)
	NetworkSlicingIndication *byte
}

// ConfigUpdateIndicationACK is the Configuration Update Indication value with ACK
// bit set, requesting a ConfigurationUpdateComplete from the UE.
// Ref: TS 24.501 §9.11.3.18 — bit 1 (ACKS) = 1
const ConfigUpdateIndicationACK byte = 0x01

// EncodeConfigurationUpdateCommand serialises the message body.
// Ref: TS 24.501 §8.2.29.1 Figure 8.2.29.1.1
func EncodeConfigurationUpdateCommand(c *ConfigurationUpdateCommand) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("nas: nil ConfigurationUpdateCommand")
	}
	var out []byte

	// IEI 0xD- — Configuration update indication (TV, 1 byte)
	// High nibble = 0xD, low nibble = indication value
	if c.ConfigUpdateIndication != nil {
		out = append(out, 0xD0|(*c.ConfigUpdateIndication&0x0F))
	}

	// IEI 0x77 — 5G-GUTI (TLV-E, 2-byte length)
	if c.FiveGGUTI != nil && c.FiveGGUTI.GUTI != nil {
		gutiBytes := Encode5GGUTI(c.FiveGGUTI.GUTI)
		length := len(gutiBytes)
		out = append(out, 0x77, byte(length>>8), byte(length))
		out = append(out, gutiBytes...)
	}

	// IEI 0x54 — TAI list (TLV, 1-byte length)
	if len(c.TAIList) > 0 {
		out = append(out, 0x54, byte(len(c.TAIList)))
		out = append(out, c.TAIList...)
	}

	// IEI 0x15 — Allowed NSSAI (TLV, 1-byte length)
	if c.AllowedNSSAI != nil {
		nssaiBytes := EncodeNSSAI(*c.AllowedNSSAI)
		out = append(out, 0x15, byte(len(nssaiBytes)))
		out = append(out, nssaiBytes...)
	}

	// IEI 0x31 — Configured NSSAI (TLV, 1-byte length)
	if c.ConfiguredNSSAI != nil {
		nssaiBytes := EncodeNSSAI(*c.ConfiguredNSSAI)
		out = append(out, 0x31, byte(len(nssaiBytes)))
		out = append(out, nssaiBytes...)
	}

	// IEI 0x9A — Network slicing indication (TV, 1 byte, high nibble 0x9)
	if c.NetworkSlicingIndication != nil {
		out = append(out, 0x90|(*c.NetworkSlicingIndication&0x0F))
	}

	return out, nil
}

// DecodeConfigurationUpdateCommand parses the message body bytes.
// Ref: TS 24.501 §8.2.29.1
func DecodeConfigurationUpdateCommand(b []byte) (*ConfigurationUpdateCommand, error) {
	c := &ConfigurationUpdateCommand{}
	rdr := NewReader(b)

	for rdr.Len() > 0 {
		iei, err := rdr.ReadByte()
		if err != nil {
			break
		}

		// Half-byte (TV) IEs: high nibble is the IEI
		switch iei >> 4 {
		case 0xD: // Configuration update indication
			v := iei & 0x0F
			c.ConfigUpdateIndication = &v
			continue
		case 0x9: // Network slicing indication
			v := iei & 0x0F
			c.NetworkSlicingIndication = &v
			continue
		}

		switch iei {
		case 0x77: // 5G-GUTI — TLV-E (2-byte length)
			hi, _ := rdr.ReadByte()
			lo, _ := rdr.ReadByte()
			length := int(hi)<<8 | int(lo)
			gutiBytes, _ := rdr.ReadBytes(length)
			mi, _ := DecodeMobileIdentity(gutiBytes)
			c.FiveGGUTI = mi
		case 0x54: // TAI list — TLV (1-byte length)
			l, _ := rdr.ReadByte()
			c.TAIList, _ = rdr.ReadBytes(int(l))
		case 0x15: // Allowed NSSAI — TLV (1-byte length)
			l, _ := rdr.ReadByte()
			nssaiBytes, _ := rdr.ReadBytes(int(l))
			nssai, _ := DecodeNSSAI(nssaiBytes)
			c.AllowedNSSAI = &nssai
		case 0x31: // Configured NSSAI — TLV (1-byte length)
			l, _ := rdr.ReadByte()
			nssaiBytes, _ := rdr.ReadBytes(int(l))
			nssai, _ := DecodeNSSAI(nssaiBytes)
			c.ConfiguredNSSAI = &nssai
		default:
			// Skip unknown optional TLV IEs; skip half-byte TV IEs already handled above
			if iei >= 0x80 {
				continue // single-byte TV IE (no length byte)
			}
			l, err := rdr.ReadByte()
			if err != nil {
				break
			}
			_, _ = rdr.ReadBytes(int(l))
		}
	}
	return c, nil
}

// ---- Configuration Update Complete (TS 24.501 §8.2.30) ------------------

// ConfigurationUpdateComplete is sent uplink by the UE to acknowledge a
// ConfigurationUpdateCommand that had the ACK bit set.
// The body carries no IEs.
// Ref: TS 24.501 §8.2.30
type ConfigurationUpdateComplete struct{}

// EncodeConfigurationUpdateComplete serialises the (empty) message body.
func EncodeConfigurationUpdateComplete(_ *ConfigurationUpdateComplete) ([]byte, error) {
	return []byte{}, nil
}

// DecodeConfigurationUpdateComplete parses the (empty) message body.
func DecodeConfigurationUpdateComplete(_ []byte) (*ConfigurationUpdateComplete, error) {
	return &ConfigurationUpdateComplete{}, nil
}
