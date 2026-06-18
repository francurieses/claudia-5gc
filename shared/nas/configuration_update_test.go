package nas_test

import (
	"bytes"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// ---- ConfigurationUpdateCommand -----------------------------------------
//
// Note: URSP / UE policies are NOT carried in the Configuration Update Command.
// They are delivered via the UE policy delivery service over DL NAS TRANSPORT
// (payload container type "UE policy container", 0x05). See transport_test.go.

func TestConfigurationUpdateCommand_Empty(t *testing.T) {
	// Empty CUC (no IEs set) should encode to zero bytes body.
	cuc := &nas.ConfigurationUpdateCommand{}
	encoded, err := nas.EncodeConfigurationUpdateCommand(cuc)
	if err != nil {
		t.Fatalf("Encode empty CUC: %v", err)
	}
	if len(encoded) != 0 {
		t.Errorf("Empty CUC should encode to 0 bytes, got %d: %x", len(encoded), encoded)
	}
}

func TestConfigurationUpdateCommand_ConfigUpdateIndication(t *testing.T) {
	// ConfigUpdateIndication is TV (half-byte): high nibble 0xD, low nibble = value
	ackBit := nas.ConfigUpdateIndicationACK // 0x01
	cuc := &nas.ConfigurationUpdateCommand{
		ConfigUpdateIndication: &ackBit,
	}
	encoded, err := nas.EncodeConfigurationUpdateCommand(cuc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Expect exactly 1 byte: 0xD1 (0xD0 | 0x01)
	if len(encoded) != 1 {
		t.Fatalf("Expected 1 byte for ConfigUpdateIndication, got %d: %x", len(encoded), encoded)
	}
	if encoded[0] != 0xD1 {
		t.Errorf("ConfigUpdateIndication byte: got %x, want D1 (0xD0|ACK)", encoded[0])
	}
}

func TestConfigurationUpdateCommand_Roundtrip(t *testing.T) {
	ackBit := nas.ConfigUpdateIndicationACK
	orig := &nas.ConfigurationUpdateCommand{
		ConfigUpdateIndication: &ackBit,
		TAIList:                []byte{0x01, 0x02, 0x03},
	}

	encoded, err := nas.EncodeConfigurationUpdateCommand(orig)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := nas.DecodeConfigurationUpdateCommand(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if decoded.ConfigUpdateIndication == nil || *decoded.ConfigUpdateIndication != nas.ConfigUpdateIndicationACK {
		t.Errorf("ConfigUpdateIndication: got %v, want %d",
			decoded.ConfigUpdateIndication, nas.ConfigUpdateIndicationACK)
	}
	if !bytes.Equal(decoded.TAIList, orig.TAIList) {
		t.Errorf("TAIList: got %x, want %x", decoded.TAIList, orig.TAIList)
	}
}

// ---- ConfigurationUpdateComplete ----------------------------------------

func TestConfigurationUpdateComplete_EmptyBody(t *testing.T) {
	// The Complete message has no IEs — body must be empty.
	cuc := &nas.ConfigurationUpdateComplete{}
	encoded, err := nas.EncodeConfigurationUpdateComplete(cuc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(encoded) != 0 {
		t.Errorf("ConfigurationUpdateComplete body should be empty, got %d bytes", len(encoded))
	}
	decoded, err := nas.DecodeConfigurationUpdateComplete(nil)
	if err != nil {
		t.Fatalf("Decode nil: %v", err)
	}
	if decoded == nil {
		t.Error("Decoded ConfigurationUpdateComplete should not be nil")
	}
}

// ---- NAS Encode/Decode full PDU -----------------------------------------

func TestEncodeDecodeConfigurationUpdateCommand_FullPDU(t *testing.T) {
	// End-to-end: wrap CUC in a NAS PDU and round-trip through nas.Encode/nas.Decode
	ackBit := nas.ConfigUpdateIndicationACK
	cuc := &nas.ConfigurationUpdateCommand{
		ConfigUpdateIndication: &ackBit,
	}

	pdu := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			SecurityHeaderType:            nas.SecurityHeaderPlainNAS,
			MessageType:                   nas.MsgTypeConfigurationUpdateCommand,
		},
		Body: cuc,
	}

	encoded, err := nas.Encode(pdu)
	if err != nil {
		t.Fatalf("Encode PDU: %v", err)
	}

	// Plain NAS: EPD(1) | SHT(1) | MsgType(1) | body...
	if len(encoded) < 3 {
		t.Fatalf("Encoded PDU too short: %d bytes", len(encoded))
	}
	if encoded[2] != 0x54 {
		t.Errorf("Message type: got %x, want 54 (ConfigurationUpdateCommand)", encoded[2])
	}

	decoded, err := nas.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode PDU: %v", err)
	}
	if decoded.Header.MessageType != nas.MsgTypeConfigurationUpdateCommand {
		t.Errorf("MessageType: got %x, want 54", decoded.Header.MessageType)
	}
	if _, ok := decoded.Body.(*nas.ConfigurationUpdateCommand); !ok {
		t.Fatalf("Body type: got %T, want *ConfigurationUpdateCommand", decoded.Body)
	}
}

func TestEncodeDecodeConfigurationUpdateComplete_FullPDU(t *testing.T) {
	// End-to-end for the Complete message (empty body, message type 0x55)
	pdu := &nas.Message{
		Header: nas.Header{
			ExtendedProtocolDiscriminator: nas.PDMobilityManagement,
			SecurityHeaderType:            nas.SecurityHeaderPlainNAS,
			MessageType:                   nas.MsgTypeConfigurationUpdateComplete,
		},
		Body: &nas.ConfigurationUpdateComplete{},
	}

	encoded, err := nas.Encode(pdu)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Plain NAS header is 3 bytes; body is empty → total 3 bytes
	if len(encoded) != 3 {
		t.Errorf("ConfigurationUpdateComplete PDU: got %d bytes, want 3", len(encoded))
	}
	if encoded[2] != 0x55 {
		t.Errorf("Message type byte: got %x, want 55 (ConfigurationUpdateComplete)", encoded[2])
	}

	decoded, err := nas.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Header.MessageType != nas.MsgTypeConfigurationUpdateComplete {
		t.Errorf("MessageType: got %x, want 55", decoded.Header.MessageType)
	}
	if _, ok := decoded.Body.(*nas.ConfigurationUpdateComplete); !ok {
		t.Errorf("Body type: got %T, want *ConfigurationUpdateComplete", decoded.Body)
	}
}
