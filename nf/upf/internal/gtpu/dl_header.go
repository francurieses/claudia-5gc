package gtpu

import "fmt"

// Constants for the optional PDU Set Information Container (REL19-6.3).
const (
	// extHdrTypePDUSetInfo is the Next Extension Header Type for the PDU Set
	// Information Container that a UPF/gNB of this release shall use
	// (TS 29.281 V19.2.0 Figure 5.2.1-3, NOTE 7). The legacy value 0x86 is
	// receive-only (NOTE 8) and is never emitted.
	extHdrTypePDUSetInfo = 0x04

	// pduSetInfoPDUTypeDL is PDU Type 0 "DL PDU SET INFORMATION" in bits 7-4 of
	// the first content octet (TS 38.415 V19.1.0 §6.5.2.1, §6.5.3.1).
	pduSetInfoPDUTypeDL = 0x00

	// Bit positions in content octet 0 (TS 38.415 §6.5.2.1 Figure 6.5.2.1-1, resolved from the
	// 38415-j10 docx table: gridSpan 4 PDU Type | EDB | EPDU | PSSI | Spare).
	pduSetInfoEDBBit   = 1 << 3 // End of Data Burst, §6.5.3.8
	pduSetInfoEPDUBit  = 1 << 2 // End PDU of the PDU Set, §6.5.3.7
	pduSetInfoPSSIBit  = 1 << 1 // PDU Set Size Indicator, §6.5.3.5
	pduSetInfoPSSNMask = 0x03FF // PSSN is 10 bits, §6.5.3.10
	pduSetInfoPSIMask  = 0x0F   // PSI is 4 bits, §6.5.3.9
	pduSetInfoPSSMask  = 0xFFFFFF

	// pduSetInfoBaseContent is the content length without PSSize: PDU Type/flags
	// (1) + QFI/PSSN-hi (1) + PSSN-lo (1) + spare/PSI (1) + PSN (1).
	pduSetInfoBaseContent = 5
	// pduSetInfoPSSizeLen is the optional PSSize field length (§6.5.3.12).
	pduSetInfoPSSizeLen = 3
)

// PDUSetInfo carries the TS 38.415 §6.5 DL PDU SET INFORMATION fields. PDU Set
// information and End of Data Burst are NOT part of the PDU Session Container;
// they travel in the separate PDU Set Information Container extension header
// (TS 29.281 §5.2.2.8).
type PDUSetInfo struct {
	EDB  bool   // End of Data Burst
	EPDU bool   // last PDU of the PDU Set
	PSI  uint8  // PDU Set Importance, 4 bits (0 = undefined)
	PSSN uint16 // PDU Set Sequence Number, 10 bits
	PSN  uint8  // PDU sequence number within the PDU Set
	// HasPSSize sets PSSI=1 and appends PSSize.
	HasPSSize bool
	PSSize    uint32 // PDU Set Size in bytes, 24 bits; used only if HasPSSize
}

// DLHeaderOptions selects optional DL encapsulation fields. A nil pointer or a
// zero value yields the legacy 16-octet header.
type DLHeaderOptions struct {
	PDUSet *PDUSetInfo
}

// Validate reports fields outside their TS 38.415 §6.5.3 ranges. The writer
// masks them regardless; Validate lets a caller reject instead.
func (o *DLHeaderOptions) Validate() error {
	if o == nil || o.PDUSet == nil {
		return nil
	}
	p := o.PDUSet
	switch {
	case p.PSI > pduSetInfoPSIMask:
		return fmt.Errorf("gtpu: PSI %d exceeds 4 bits", p.PSI)
	case p.PSSN > pduSetInfoPSSNMask:
		return fmt.Errorf("gtpu: PSSN %d exceeds 10 bits", p.PSSN)
	case p.HasPSSize && p.PSSize > pduSetInfoPSSMask:
		return fmt.Errorf("gtpu: PSSize %d exceeds 24 bits", p.PSSize)
	}
	return nil
}

// pduSetContainerLen returns the total PDU Set Information Container extension
// header length in octets (length octet + content + padding + next-type), a
// multiple of 4 as required by TS 29.281 §5.2.2.8. The content incl. padding is
// 4n-2 octets (TS 38.415 §6.5.3.13).
func pduSetContainerLen(p *PDUSetInfo) int {
	content := pduSetInfoBaseContent
	if p.HasPSSize {
		content += pduSetInfoPSSizeLen
	}
	return (content + 2 + 3) &^ 3 // round 1+content+1 up to a multiple of 4
}

// dlHeaderLen returns the DL encapsulation length written by putDLHeaderOpts:
// 16 octets with no options.
func dlHeaderLen(o *DLHeaderOptions) int {
	if o == nil || o.PDUSet == nil {
		return dlHeadroom
	}
	return dlHeadroom + pduSetContainerLen(o.PDUSet)
}

// putDLHeaderOpts writes the DL GTP-U encapsulation into h (len(h) >= dlHeaderLen(o))
// and returns the header length. With no options it is putDLHeader unchanged.
// With PDU Set options the PDU Session Container's next-ext-type is 0x04 and the
// PDU Set Information Container follows as the second extension header
// (TS 29.281 §5.2.1 Figure 5.2.1-3 NOTE 5/6/7, §5.2.2.8); the QFI is the same in
// both. The GTP-U Length covers the added octets. Out-of-range fields are masked.
func putDLHeaderOpts(h []byte, dlTEID uint32, qfi uint8, innerLen int, o *DLHeaderOptions) int {
	if o == nil || o.PDUSet == nil {
		putDLHeader(h, dlTEID, qfi, innerLen)
		return dlHeadroom
	}
	p := o.PDUSet
	extLen := pduSetContainerLen(p)
	putDLHeader(h, dlTEID, qfi, innerLen+extLen)
	h[15] = extHdrTypePDUSetInfo // PDU Session Container -> PDU Set Information Container

	// Octet layout of DL PDU SET INFORMATION (TS 38.415 Figure 6.5.2.1-1; bit
	// positions resolved from the docx table XML, 38415-j10, not the flattened text):
	//   oct0: PDU Type(7-4)=0 | EDB(3) | EPDU(2) | PSSI(1) | spare(0)
	//   oct1: QFI(7-2) | PSSN[9:8](1-0)
	//   oct2: PSSN[7:0]
	//   oct3: spare(7-4) | PSI(3-0)
	//   oct4: PSN
	//   oct5-7: PSSize (only if PSSI=1); then 0-3 padding to 4n-2 octets.
	c := h[dlHeadroom : dlHeadroom+extLen]
	clear(c)
	c[0] = byte(extLen / 4) // Length in 4-octet units
	b := byte(pduSetInfoPDUTypeDL << 4)
	if p.EDB {
		b |= pduSetInfoEDBBit
	}
	if p.EPDU {
		b |= pduSetInfoEPDUBit
	}
	if p.HasPSSize {
		b |= pduSetInfoPSSIBit
	}
	pssn := p.PSSN & pduSetInfoPSSNMask
	c[1] = b
	c[2] = (qfi&0x3F)<<2 | byte(pssn>>8)
	c[3] = byte(pssn)
	c[4] = p.PSI & pduSetInfoPSIMask
	c[5] = p.PSN
	if p.HasPSSize {
		s := p.PSSize & pduSetInfoPSSMask
		c[6], c[7], c[8] = byte(s>>16), byte(s>>8), byte(s) // PSSize, 3 octets
	}
	// c[extLen-1] stays 0: Next Extension Header Type = no more extensions.
	return dlHeadroom + extLen
}

// buildDLPDUSessionContainerOpts is buildDLPDUSessionContainer plus the optional
// PDU Set Information Container; with no options the result is identical.
func buildDLPDUSessionContainerOpts(qfi uint8, o *DLHeaderOptions) []byte {
	var h [dlHeadroom + 12]byte
	n := putDLHeaderOpts(h[:], 0, qfi, 0, o)
	return append([]byte(nil), h[gtpuMinHdr:n]...)
}
