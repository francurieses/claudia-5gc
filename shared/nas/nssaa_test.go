package nas

import (
	"bytes"
	"testing"
)

func TestEncodeNSSAAuthCommand_ByteExact(t *testing.T) {
	// EAP-Request/Identity: code=1, id=7, length=5, type=1 (Identity)
	eap := []byte{0x01, 0x07, 0x00, 0x05, 0x01}
	cmd := &NSSAAuthCommand{
		SNSSAI:     SNSSAI{SST: 1, SD: 0x000003},
		EAPMessage: eap,
	}
	got, err := EncodeNSSAAuthCommand(cmd)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// S-NSSAI LV: len=4, SST=1, SD=00 00 03
	// EAP LV-E: len=00 05, then the 5 EAP bytes
	want := []byte{0x04, 0x01, 0x00, 0x00, 0x03, 0x00, 0x05, 0x01, 0x07, 0x00, 0x05, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("command bytes\n got=% x\nwant=% x", got, want)
	}
}

func TestEncodeNSSAAuthCommand_SSTOnly(t *testing.T) {
	cmd := &NSSAAuthCommand{
		SNSSAI:     SNSSAI{SST: 2, SD: SDNotPresent},
		EAPMessage: []byte{0x03, 0x09, 0x00, 0x04}, // EAP-Success
	}
	got, _ := EncodeNSSAAuthCommand(cmd)
	want := []byte{0x01, 0x02, 0x00, 0x04, 0x03, 0x09, 0x00, 0x04}
	if !bytes.Equal(got, want) {
		t.Fatalf("sst-only bytes\n got=% x\nwant=% x", got, want)
	}
}

func TestNSSAARoundTrip(t *testing.T) {
	eap := []byte{0x02, 0x07, 0x00, 0x0A, 0x01, 'a', 'l', 'i', 'c', 'e'}
	sn := SNSSAI{SST: 1, SD: 0x000003}

	t.Run("command", func(t *testing.T) {
		b, _ := EncodeNSSAAuthCommand(&NSSAAuthCommand{SNSSAI: sn, EAPMessage: eap})
		dec, err := DecodeNSSAAuthCommand(b)
		if err != nil {
			t.Fatal(err)
		}
		if dec.SNSSAI != sn || !bytes.Equal(dec.EAPMessage, eap) {
			t.Fatalf("roundtrip mismatch: %+v", dec)
		}
	})
	t.Run("complete", func(t *testing.T) {
		b, _ := EncodeNSSAAuthComplete(&NSSAAuthComplete{SNSSAI: sn, EAPMessage: eap})
		dec, err := DecodeNSSAAuthComplete(b)
		if err != nil {
			t.Fatal(err)
		}
		if dec.SNSSAI != sn || !bytes.Equal(dec.EAPMessage, eap) {
			t.Fatalf("roundtrip mismatch: %+v", dec)
		}
	})
	t.Run("result", func(t *testing.T) {
		b, _ := EncodeNSSAAuthResult(&NSSAAuthResult{SNSSAI: sn, EAPMessage: eap})
		dec, err := DecodeNSSAAuthResult(b)
		if err != nil {
			t.Fatal(err)
		}
		if dec.SNSSAI != sn || !bytes.Equal(dec.EAPMessage, eap) {
			t.Fatalf("roundtrip mismatch: %+v", dec)
		}
	})
}

func TestNSSAAFullMessageDispatch(t *testing.T) {
	// Encode through the top-level Encode/Decode (with the 3-octet 5GMM header)
	// to confirm the dispatch wiring in nas.go.
	sn := SNSSAI{SST: 1, SD: 0x000003}
	eap := []byte{0x01, 0x01, 0x00, 0x05, 0x01}
	msg := &Message{
		Header: Header{
			ExtendedProtocolDiscriminator: PDMobilityManagement,
			SecurityHeaderType:            SecurityHeaderPlainNAS,
			MessageType:                   MsgTypeNetworkSliceSpecificAuthCommand,
		},
		Body: &NSSAAuthCommand{SNSSAI: sn, EAPMessage: eap},
	}
	raw, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	body, ok := dec.Body.(*NSSAAuthCommand)
	if !ok {
		t.Fatalf("body type = %T, want *NSSAAuthCommand", dec.Body)
	}
	if body.SNSSAI != sn || !bytes.Equal(body.EAPMessage, eap) {
		t.Fatalf("dispatch roundtrip mismatch: %+v", body)
	}
}

func TestDecodeNSSAATruncated(t *testing.T) {
	if _, err := DecodeNSSAAuthCommand([]byte{0x04, 0x01}); err == nil {
		t.Fatal("expected error on truncated S-NSSAI")
	}
	if _, err := DecodeNSSAAuthCommand([]byte{0x01, 0x01, 0x00}); err == nil {
		t.Fatal("expected error on truncated EAP length")
	}
	if _, err := DecodeNSSAAuthCommand([]byte{0x01, 0x01, 0x00, 0x05, 0x01}); err == nil {
		t.Fatal("expected error on EAP shorter than its length")
	}
}
