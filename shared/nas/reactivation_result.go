// Package nas: PDU session reactivation result (0x26) and PDU session
// reactivation result error cause (0x72) helpers shared by REGISTRATION
// ACCEPT and SERVICE ACCEPT.
package nas

import "fmt"

// IEIPDUSessionReactivationResultErrorCause is the IEI of the PDU session
// reactivation result error cause IE (TLV-E).
// Ref: TS 24.501 §9.11.3.43, Table 8.2.7.1.1, Table 8.2.17.1.1
const IEIPDUSessionReactivationResultErrorCause = 0x72

// PDUSessionErrorCause is one {PDU session ID, 5GMM cause} pair of the PDU
// session reactivation result error cause IE.
// Ref: TS 24.501 §9.11.3.43
type PDUSessionErrorCause struct {
	// PDUSessionID is the PDU session ID (1 octet).
	PDUSessionID uint8
	// Cause5GMM is the 5GMM cause value (TS 24.501 §9.11.3.2).
	Cause5GMM uint8
}

// NewPDUSessionReactivationResult builds the value (2 octets) of the PDU
// session reactivation result IE (0x26) from a PSI list: bit set = user-plane
// re-establishment failed / not performed. PSI 0 and PSIs above 15 are ignored.
// Ref: TS 24.501 §9.11.3.42
func NewPDUSessionReactivationResult(psis ...uint8) []byte {
	m := PSIMask(psis...)
	return []byte{byte(m >> 8), byte(m)}
}

// EncodePDUSessionReactivationResultErrorCause encodes the full TLV-E (IEI,
// 2-octet length, pairs). An empty list returns nil (IE absent).
// Ref: TS 24.501 §9.11.3.43
func EncodePDUSessionReactivationResultErrorCause(list []PDUSessionErrorCause) []byte {
	if len(list) == 0 {
		return nil
	}
	n := 2 * len(list)
	out := make([]byte, 0, 3+n)
	out = append(out, IEIPDUSessionReactivationResultErrorCause, byte(n>>8), byte(n))
	for _, e := range list {
		out = append(out, e.PDUSessionID, e.Cause5GMM)
	}
	return out
}

// DecodePDUSessionReactivationResultErrorCause parses the IE value (the
// octets after the 2-octet length) into pairs.
// Ref: TS 24.501 §9.11.3.43
func DecodePDUSessionReactivationResultErrorCause(v []byte) ([]PDUSessionErrorCause, error) {
	if len(v) == 0 || len(v)%2 != 0 {
		return nil, fmt.Errorf("nas: reactivation result error cause: invalid length %d", len(v))
	}
	out := make([]PDUSessionErrorCause, 0, len(v)/2)
	for i := 0; i < len(v); i += 2 {
		out = append(out, PDUSessionErrorCause{PDUSessionID: v[i], Cause5GMM: v[i+1]})
	}
	return out, nil
}
