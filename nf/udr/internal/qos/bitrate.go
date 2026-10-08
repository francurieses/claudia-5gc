// Package qos holds the UDR's QoS value validators.
//
// It currently provides the TS 29.571 §5.5.2 BitRate validator used by the
// slice/DNN Session-AMBR configuration (UDR-003) for both the internal
// management endpoints and the operator.yaml seed.
package qos

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// BitRatePattern is the TS 29.571 §5.5.2 (Table 5.5.2-1) BitRate regex. The
// single space between value and unit is mandatory, e.g. "125 Mbps".
const BitRatePattern = `^\d+(\.\d+)? (bps|Kbps|Mbps|Gbps|Tbps)$`

// MaxBitRateKbps is the largest accepted rate, 1 Pbps expressed in kbit/s.
// It mirrors the SMF's maxBitRateKbps so a value accepted here is always
// parseable by the SMF (nf/smf/internal/server parseBitRateKbps).
const MaxBitRateKbps uint64 = 1_000_000_000_000

// maxBitRateLen bounds the input length so a hostile caller cannot make the
// exact-decimal arithmetic expensive.
const maxBitRateLen = 64

var bitRateRe = regexp.MustCompile(BitRatePattern)

// Sentinel errors returned (wrapped) by ValidateBitRate.
var (
	// ErrBitRateFormat means the string does not match BitRatePattern.
	ErrBitRateFormat = errors.New("qos: bit rate does not match TS 29.571 §5.5.2 pattern")
	// ErrBitRateRange means the rate is zero after rounding up, or above 1 Pbps.
	ErrBitRateRange = errors.New("qos: bit rate out of range")
)

// unit factors to kbit/s as numerator/denominator.
var kbpsPerUnit = map[string]*big.Rat{
	"bps":  big.NewRat(1, 1000),
	"Kbps": big.NewRat(1, 1),
	"Mbps": big.NewRat(1000, 1),
	"Gbps": big.NewRat(1_000_000, 1),
	"Tbps": big.NewRat(1_000_000_000, 1),
}

// ValidateBitRate validates a TS 29.571 §5.5.2 BitRate string and returns its
// canonical form (trimmed, unchanged value and unit) and its value in kbit/s,
// rounded up. The rate must be > 0 kbps (the SMF treats 0 as unparsable and
// silently falls back to its operator default) and <= 1 Pbps.
//
// The rules duplicate the SMF's parseBitRateKbps (nf/smf/internal/server/qos.go);
// an internal package cannot be imported across NFs.
func ValidateBitRate(s string) (canonical string, kbps uint64, err error) {
	t := strings.TrimSpace(s)
	if len(t) > maxBitRateLen || !bitRateRe.MatchString(t) {
		return "", 0, fmt.Errorf("%w: %q", ErrBitRateFormat, s)
	}
	idx := strings.IndexByte(t, ' ')
	val, unit := t[:idx], t[idx+1:]
	r, ok := new(big.Rat).SetString(val)
	if !ok {
		return "", 0, fmt.Errorf("%w: %q", ErrBitRateFormat, s)
	}
	r.Mul(r, kbpsPerUnit[unit])
	// ceil(num/den)
	num, den := r.Num(), r.Denom()
	q, m := new(big.Int).QuoRem(num, den, new(big.Int))
	if m.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	if q.Sign() <= 0 {
		return "", 0, fmt.Errorf("%w: %q must be greater than 0", ErrBitRateRange, s)
	}
	if !q.IsUint64() || q.Uint64() > MaxBitRateKbps {
		return "", 0, fmt.Errorf("%w: %q exceeds 1 Pbps", ErrBitRateRange, s)
	}
	return t, q.Uint64(), nil
}
