package nas_test

// ietable_decoders_test.go — the Service Request/Accept, Configuration Update
// Command, UL NAS Transport, Authentication Request/Response and Security
// Mode Command/Complete decoders skip unhandled optional IEs through the IE
// table / TS 24.007 §11.2.4 rule (REL19-5.1 follow-up): unknown type 1/2, TLV
// and TLV-E IEs, table-known fixed-length TV IEs, and a truncated trailing IE
// must neither shift the IEs that follow nor panic.
// Ref: TS 24.007 §11.2.4, TS 24.501 §7.6.1, §7.7.1, Tables 8.2.1.1.1,
// 8.2.2.1.1, 8.2.10.1.1, 8.2.16.1.1, 8.2.17.1.1, 8.2.19.1.1, 8.2.25.1.1,
// 8.2.26.1.1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

var (
	// unknownTLVE is IEI 0x7F (TLV-E by the 0x70-0x7F rule), 3 value octets.
	unknownTLVE = []byte{0x7F, 0x00, 0x03, 0xAA, 0xBB, 0xCC}
	// unknownTLV is IEI 0x3F (TLV by the rule), 2 value octets.
	unknownTLV = []byte{0x3F, 0x02, 0xAA, 0xBB}
	// unknownTV1 is a high-nibble-0xA IEI, one octet (type 1/2 by the rule).
	unknownTV1 = []byte{0xA5}
	// truncatedTLVE declares 9 value octets but carries 1.
	truncatedTLVE = []byte{0x7E, 0x00, 0x09, 0x01}
	// truncatedTLV declares 9 value octets but carries 1.
	truncatedTLV = []byte{0x3E, 0x09, 0x01}
	// truncatedHdr is a TLV-E IEI with a one-octet length field cut short.
	truncatedHdr = []byte{0x7E, 0x00}
)

func TestServiceRequestSkipsIEs(t *testing.T) {
	head := []byte{0x01, 0x00, 0x07, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	uds := []byte{0x40, 0x02, 0x80, 0x00}
	// Allowed PDU session status 0x25, UE request type 0x29 are table-known TLVs.
	known := []byte{0x25, 0x02, 0x00, 0x00, 0x29, 0x01, 0x01}
	cases := []struct {
		name string
		body []byte
	}{
		{"unknown TLV-E before", cat(head, unknownTLVE, uds)},
		{"unknown TLV before", cat(head, unknownTLV, uds)},
		{"unknown type1 before", cat(head, unknownTV1, uds)},
		{"table-known TLVs before", cat(head, known, uds)},
		{"all mixed", cat(head, unknownTV1, unknownTLVE, known, unknownTLV, uds)},
		{"truncated TLV-E after", cat(head, uds, truncatedTLVE)},
		{"truncated TLV after", cat(head, uds, truncatedTLV)},
		{"truncated header after", cat(head, uds, truncatedHdr)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := nas.DecodeServiceRequest(c.body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if r.UplinkDataStatus == nil || *r.UplinkDataStatus != 0x8000 {
				t.Errorf("UplinkDataStatus = %v, want 0x8000", r.UplinkDataStatus)
			}
		})
	}
}

func TestServiceAcceptSkipsIEs(t *testing.T) {
	status := []byte{0x50, 0x02, 0x10, 0x00}
	cases := []struct {
		name string
		body []byte
	}{
		{"TLV-E error cause and EAP before", cat([]byte{0x72, 0x00, 0x02, 0xAA, 0xBB, 0x78, 0x00, 0x01, 0xCC}, status)},
		{"unknown TLV-E before", cat(unknownTLVE, status)},
		{"unknown TLV before", cat(unknownTLV, status)},
		{"unknown type1 before", cat(unknownTV1, status)},
		{"T3448 before", cat([]byte{0x6B, 0x01, 0x21}, status)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := nas.DecodeServiceAccept(c.body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if a.PDUSessionStatus == nil || *a.PDUSessionStatus != 0x1000 {
				t.Errorf("PDUSessionStatus = %v, want 0x1000", a.PDUSessionStatus)
			}
		})
	}
	// Existing contract: a truncated IE is reported as an error.
	for name, tail := range map[string][]byte{"TLV-E": truncatedTLVE, "TLV": truncatedTLV} {
		t.Run("truncated "+name, func(t *testing.T) {
			a, err := nas.DecodeServiceAccept(cat(status, tail))
			if err == nil {
				t.Fatal("want error for truncated IE")
			}
			if !errors.Is(err, nas.ErrIETruncated) {
				t.Errorf("error %v does not wrap ErrIETruncated", err)
			}
			if a == nil || a.PDUSessionStatus == nil {
				t.Error("fields decoded before the truncated IE must be kept")
			}
		})
	}
}

func TestConfigurationUpdateCommandSkipsIEs(t *testing.T) {
	tai := []byte{0x54, 0x03, 0x01, 0x02, 0x03}
	cases := []struct {
		name string
		body []byte
	}{
		// Local time zone 0x46 is a fixed TV (2 octets); the old ad-hoc skip
		// read the next octet as a length.
		{"fixed TV local time zone before", cat([]byte{0x46, 0x23}, tai)},
		{"fixed TV universal time before", cat([]byte{0x47, 1, 2, 3, 4, 5, 6, 0x23}, tai)},
		{"table-known type1 before", cat([]byte{0xF0, 0x80}, tai)},
		{"extended LADN TLV-E 0x78 before", cat([]byte{0x78, 0x00, 0x02, 0xAA, 0xBB}, tai)},
		{"unknown TLV-E before", cat(unknownTLVE, tai)},
		{"unknown TLV before", cat(unknownTLV, tai)},
		{"truncated TLV-E after", cat(tai, truncatedTLVE)},
		{"truncated TLV after", cat(tai, truncatedTLV)},
		{"truncated header after", cat(tai, truncatedHdr)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd, err := nas.DecodeConfigurationUpdateCommand(c.body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(cmd.TAIList, []byte{1, 2, 3}) {
				t.Errorf("TAIList = %x, want 010203", cmd.TAIList)
			}
		})
	}
}

func TestULNASTransportSkipsIEs(t *testing.T) {
	head := []byte{0x01, 0x00, 0x02, 0x11, 0x22}
	psi := []byte{0x12, 0x05}
	cases := []struct {
		name string
		body []byte
	}{
		// Old PDU session ID 0x59 is a fixed TV (2 octets).
		{"fixed TV old PDU session ID before", cat(head, []byte{0x59, 0x07}, psi)},
		{"unknown TLV-E before", cat(head, unknownTLVE, psi)},
		{"unknown TLV before", cat(head, unknownTLV, psi)},
		{"table-known type1 MA PDU info before", cat(head, []byte{0xA0}, psi)},
		{"truncated TLV-E after", cat(head, psi, truncatedTLVE)},
		{"truncated TLV after", cat(head, psi, truncatedTLV)},
		{"truncated header after", cat(head, psi, truncatedHdr)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := nas.DecodeULNASTransport(c.body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if m.PDUSessionID == nil || *m.PDUSessionID != 5 {
				t.Errorf("PDUSessionID = %v, want 5", m.PDUSessionID)
			}
		})
	}
}

func TestAuthenticationRequestSkipsIEs(t *testing.T) {
	head := []byte{0x01, 0x02, 0x00, 0x00}
	rand := cat([]byte{0x21}, bytes.Repeat([]byte{0x11}, 16))
	autn := cat([]byte{0x20, 0x10}, bytes.Repeat([]byte{0x22}, 16))
	cases := []struct {
		name string
		body []byte
	}{
		{"unknown TLV-E before RAND", cat(head, unknownTLVE, rand, autn)},
		{"unknown TLV before RAND", cat(head, unknownTLV, rand, autn)},
		{"unknown type1 before RAND", cat(head, unknownTV1, rand, autn)},
		{"truncated TLV-E after AUTN", cat(head, rand, autn, truncatedTLVE)},
		{"truncated TLV after AUTN", cat(head, rand, autn, truncatedTLV)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := nas.DecodeAuthenticationRequest(c.body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if a.RAND[0] != 0x11 || a.AUTN[0] != 0x22 {
				t.Errorf("RAND[0]=%x AUTN[0]=%x, want 11 22", a.RAND[0], a.AUTN[0])
			}
		})
	}
}

func TestAuthenticationResponseSkipsIEs(t *testing.T) {
	res := []byte{0x2D, 0x02, 0x01, 0x02}
	cases := []struct {
		name string
		body []byte
	}{
		{"unknown TLV-E before", cat(unknownTLVE, res)},
		{"unknown TLV before", cat(unknownTLV, res)},
		{"unknown type1 before", cat(unknownTV1, res)},
		{"truncated TLV-E after", cat(res, truncatedTLVE)},
		{"truncated TLV after", cat(res, truncatedTLV)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := nas.DecodeAuthenticationResponse(c.body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(a.RES, []byte{1, 2}) {
				t.Errorf("RES = %x, want 0102", a.RES)
			}
		})
	}
}

func TestSecurityModeCommandSkipsIEs(t *testing.T) {
	base, err := nas.EncodeSecurityModeCommand(&nas.SecurityModeCommand{
		SelectedNASSecurityAlgorithms:  nas.NASSecurityAlgorithms{CipheringAlgorithmID: 2, IntegrityAlgorithmID: 2},
		NGKSI:                          nas.NGKSI{KeySetIdentifier: 1},
		ReplayedUESecurityCapabilities: nas.UESecurityCapability{EA0: true, EA2: true, IA0: true, IA2: true},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	addInfo := []byte{0x36, 0x01, 0x02}
	cases := []struct {
		name string
		body []byte
	}{
		// Selected EPS NAS security algorithms 0x57 is a fixed TV (2 octets).
		{"fixed TV EPS algorithms before", cat(base, []byte{0x57, 0x22}, addInfo)},
		{"ABBA TLV before", cat(base, []byte{0x38, 0x02, 0x00, 0x00}, addInfo)},
		{"unknown TLV-E before", cat(base, unknownTLVE, addInfo)},
		{"unknown TLV before", cat(base, unknownTLV, addInfo)},
		{"unknown type1 before", cat(base, unknownTV1, addInfo)},
		{"truncated TLV-E after", cat(base, addInfo, truncatedTLVE)},
		{"truncated TLV after", cat(base, addInfo, truncatedTLV)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			smc, err := nas.DecodeSecurityModeCommand(c.body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if smc.Additional5GSecurityInfo == nil || *smc.Additional5GSecurityInfo != 0x02 {
				t.Errorf("Additional5GSecurityInfo = %v, want 2", smc.Additional5GSecurityInfo)
			}
		})
	}
}

func TestSecurityModeCompleteSkipsIEs(t *testing.T) {
	container := []byte{0x71, 0x00, 0x02, 0x01, 0x02}
	cases := []struct {
		name string
		body []byte
	}{
		{"unknown TLV-E before", cat(unknownTLVE, container)},
		{"unknown TLV before", cat(unknownTLV, container)},
		{"unknown type1 before", cat(unknownTV1, container)},
		{"truncated TLV-E after", cat(container, truncatedTLVE)},
		{"truncated TLV after", cat(container, truncatedTLV)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			smc, err := nas.DecodeSecurityModeComplete(c.body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(smc.NASMessageContainer, []byte{1, 2}) {
				t.Errorf("NASMessageContainer = %x, want 0102", smc.NASMessageContainer)
			}
		})
	}
}

// TestIETableMigratedMessagesRegistered pins the table coverage that the
// migrated decoders rely on: every message has a non-empty table whose
// entries have a valid format and a fixed length for TV IEs.
func TestIETableMigratedMessagesRegistered(t *testing.T) {
	for _, m := range []nas.IEMessage{
		nas.IEMsgServiceRequest, nas.IEMsgServiceAccept, nas.IEMsgConfigurationUpdateCommand,
		nas.IEMsgULNASTransport, nas.IEMsgDLNASTransport, nas.IEMsgAuthenticationRequest,
		nas.IEMsgAuthenticationResponse, nas.IEMsgSecurityModeCommand, nas.IEMsgSecurityModeComplete,
	} {
		tab := nas.IETable(m)
		if len(tab) == 0 {
			t.Errorf("%s: empty IE table", m)
		}
		for _, d := range tab {
			if d.Format == nas.IEFormatTV && d.Len < 2 {
				t.Errorf("%s: TV IE 0x%02X without total length", m, d.IEI)
			}
			if d.Introduced == 0 {
				t.Errorf("%s: IE 0x%02X without Introduced", m, d.IEI)
			}
		}
	}
}
