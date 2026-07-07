// Package lpp — internal X.691 BASIC-PER UNALIGNED bit codec.
//
// TS 37.355 §4 mandates that LPP is encoded with ASN.1 BASIC-PER UNALIGNED
// (ITU-T X.691). github.com/free5gc/aper implements ALIGNED PER only and is
// therefore structurally unusable for LPP; this file provides the minimal
// unaligned-PER primitive set the TS 37.355 A-GNSS subset in lpp.go needs,
// hand-rolled following the precedent of shared/nas (hand-written
// spec-faithful TLV codec for TS 24.501).
//
// Unaligned-PER rules implemented (X.691):
//   - No octet alignment, ever: every field is a bit field appended directly
//     after the previous one. Only the outer PDU is padded (with zero bits)
//     to a whole octet, because the NAS payload container carries octets.
//   - Constrained whole number in range [lb, ub]: encoded as (value − lb) in
//     ceil(log2(ub−lb+1)) bits (§11.5.7 unaligned variant).
//   - SEQUENCE preamble (§19): one extension bit iff the type has "...",
//     then one presence bit per root OPTIONAL/DEFAULT field, in declaration
//     order.
//   - CHOICE (§23): index in ceil(log2(#root alternatives)) bits; extensible
//     CHOICE carries a leading extension bit.
//   - ENUMERATED (§14): value in ceil(log2(#root values)) bits; extensible
//     ENUMERATED carries a leading extension bit; an extension value is a
//     normally-small non-negative whole number (§11.6).
//   - BIT STRING with SIZE(a..b), a≠b (§16): length determinant (n − a) in
//     ceil(log2(b−a+1)) bits, then the n bits. Fixed SIZE(n), n ≤ 16: the n
//     bits directly, no determinant.
//   - SEQUENCE OF with SIZE(a..b) (§20): same constrained length form.
//   - Extension additions of a SEQUENCE (§19.7–19.9, decode only): when the
//     extension bit is 1, after all root fields comes a normally-small
//     length (count of addition presence bits), the presence bits, and each
//     present addition as an open type (general length determinant §11.9 +
//     that many whole octets) — the decoder skips them (read-and-discard),
//     which is the well-defined "tolerate a future peer's extensions" rule
//     required by docs/procedures/LPPRelay.md.
//
// Ref: ITU-T X.691 (07/2002) — clauses cited inline; TS 37.355 §4.
package lpp

import (
	"fmt"
	"math/bits"
)

// bitWidth returns ceil(log2(n)) for n >= 1 — the number of bits needed to
// encode a constrained value with a range of n distinct values (X.691
// §11.5.7 unaligned variant). bitWidth(1) = 0 (a single-valued range costs
// no bits).
func bitWidth(n uint64) int {
	if n <= 1 {
		return 0
	}
	return bits.Len64(n - 1)
}

// ---- bit writer ----------------------------------------------------------------

// bitWriter accumulates an MSB-first unaligned bit stream.
type bitWriter struct {
	buf    []byte
	bitLen int
}

// writeBit appends a single bit (0 or 1).
func (w *bitWriter) writeBit(b uint64) {
	if w.bitLen%8 == 0 {
		w.buf = append(w.buf, 0)
	}
	if b != 0 {
		w.buf[w.bitLen/8] |= 0x80 >> (w.bitLen % 8)
	}
	w.bitLen++
}

// writeBits appends the n least-significant bits of v, MSB first.
func (w *bitWriter) writeBits(v uint64, n int) {
	for i := n - 1; i >= 0; i-- {
		w.writeBit((v >> uint(i)) & 1)
	}
}

// writeBool appends a BOOLEAN (X.691 §12: one bit).
func (w *bitWriter) writeBool(b bool) {
	if b {
		w.writeBit(1)
	} else {
		w.writeBit(0)
	}
}

// writeConstrained appends a constrained whole number in [lb, ub]
// (X.691 §11.5.7, unaligned: value − lb in ceil(log2(ub−lb+1)) bits).
func (w *bitWriter) writeConstrained(v int64, lb, ub int64) error {
	if v < lb || v > ub {
		return fmt.Errorf("lpp: uper: value %d out of range [%d, %d]", v, lb, ub)
	}
	w.writeBits(uint64(v-lb), bitWidth(uint64(ub-lb+1)))
	return nil
}

// writeEnumExt appends an extensible ENUMERATED root value (X.691 §14.3:
// extension bit 0 + index in ceil(log2(rootCount)) bits). This codec never
// encodes extension values.
func (w *bitWriter) writeEnumExt(v uint64, rootCount uint64) {
	w.writeBit(0)
	w.writeBits(v, bitWidth(rootCount))
}

// bytes returns the accumulated stream padded with zero bits to a whole
// octet (only legal for the outermost PDU).
func (w *bitWriter) bytes() []byte {
	if w.bitLen == 0 {
		return []byte{}
	}
	return w.buf
}

// ---- bit reader ----------------------------------------------------------------

// errTruncated is returned when the bit stream ends before a required field.
var errTruncated = fmt.Errorf("lpp: uper: truncated bit stream")

// bitReader consumes an MSB-first unaligned bit stream.
type bitReader struct {
	buf []byte
	pos int // bit position
}

// readBit consumes one bit.
func (r *bitReader) readBit() (uint64, error) {
	if r.pos >= len(r.buf)*8 {
		return 0, errTruncated
	}
	b := (r.buf[r.pos/8] >> (7 - uint(r.pos%8))) & 1
	r.pos++
	return uint64(b), nil
}

// readBits consumes n bits, MSB first.
func (r *bitReader) readBits(n int) (uint64, error) {
	var v uint64
	for i := 0; i < n; i++ {
		b, err := r.readBit()
		if err != nil {
			return 0, err
		}
		v = v<<1 | b
	}
	return v, nil
}

// readBool consumes a BOOLEAN.
func (r *bitReader) readBool() (bool, error) {
	b, err := r.readBit()
	return b == 1, err
}

// readConstrained consumes a constrained whole number in [lb, ub].
func (r *bitReader) readConstrained(lb, ub int64) (int64, error) {
	v, err := r.readBits(bitWidth(uint64(ub - lb + 1)))
	if err != nil {
		return 0, err
	}
	out := lb + int64(v)
	if out > ub {
		return 0, fmt.Errorf("lpp: uper: decoded value %d exceeds upper bound %d", out, ub)
	}
	return out, nil
}

// readEnumExt consumes an extensible ENUMERATED value. Root values decode to
// their index; an extension value (extension bit 1) decodes to rootCount +
// its normally-small number, so callers can detect "not a root value" without
// failing the whole PDU (tolerance rule).
func (r *bitReader) readEnumExt(rootCount uint64) (uint64, error) {
	ext, err := r.readBit()
	if err != nil {
		return 0, err
	}
	if ext == 0 {
		return r.readBits(bitWidth(rootCount))
	}
	small, err := r.readNormallySmall()
	if err != nil {
		return 0, err
	}
	return rootCount + small, nil
}

// readNormallySmall consumes a normally-small non-negative whole number
// (X.691 §11.6): bit 0 → 6-bit value (0..63); bit 1 → larger values, which
// this subset never needs (all LPP extension indices in scope are < 64).
func (r *bitReader) readNormallySmall() (uint64, error) {
	big, err := r.readBit()
	if err != nil {
		return 0, err
	}
	if big == 1 {
		return 0, fmt.Errorf("lpp: uper: normally-small number >= 64 not supported")
	}
	return r.readBits(6)
}

// readGeneralLength consumes a general (unconstrained) length determinant
// (X.691 §11.9, unaligned: same octet formats but not octet-aligned).
// Fragmented (>= 16384) lengths are out of scope for this subset.
func (r *bitReader) readGeneralLength() (int, error) {
	b, err := r.readBits(8)
	if err != nil {
		return 0, err
	}
	if b&0x80 == 0 {
		return int(b), nil
	}
	if b&0x40 == 0 {
		b2, err := r.readBits(8)
		if err != nil {
			return 0, err
		}
		return int(b&0x3F)<<8 | int(b2), nil
	}
	return 0, fmt.Errorf("lpp: uper: fragmented open-type length not supported")
}

// skipOpenType consumes and discards one open-type encoding (general length
// determinant + that many whole octets). Used to skip a present extension
// addition of a SEQUENCE (X.691 §19.9).
func (r *bitReader) skipOpenType() error {
	n, err := r.readGeneralLength()
	if err != nil {
		return err
	}
	if _, err := r.readBits(n * 8); err != nil {
		return err
	}
	return nil
}

// skipSequenceExtensions consumes and discards the extension-additions block
// of a SEQUENCE whose extension bit was 1 (X.691 §19.7–19.9): normally-small
// length (count − 1), the count presence bits, then each present addition as
// an open type. This is the decoder's "tolerate a future peer" behaviour
// required by docs/procedures/LPPRelay.md §LPP A-GNSS IE subset.
func (r *bitReader) skipSequenceExtensions() error {
	countMinus1, err := r.readNormallySmall()
	if err != nil {
		return err
	}
	count := int(countMinus1) + 1
	present := make([]bool, count)
	for i := 0; i < count; i++ {
		b, err := r.readBit()
		if err != nil {
			return err
		}
		present[i] = b == 1
	}
	for _, p := range present {
		if p {
			if err := r.skipOpenType(); err != nil {
				return err
			}
		}
	}
	return nil
}

// readPresence consumes n presence bits (the OPTIONAL/DEFAULT bitmap of a
// SEQUENCE preamble, X.691 §19.2–19.3).
func (r *bitReader) readPresence(n int) ([]bool, error) {
	out := make([]bool, n)
	for i := 0; i < n; i++ {
		b, err := r.readBit()
		if err != nil {
			return nil, err
		}
		out[i] = b == 1
	}
	return out, nil
}
