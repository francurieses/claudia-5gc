package server

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// bitRateRe is the TS 29.571 §5.5.2 BitRate pattern: a non-negative decimal
// number, one space, and a unit (bps|Kbps|Mbps|Gbps|Tbps).
var bitRateRe = regexp.MustCompile(`^(\d+(?:\.\d+)?) (bps|Kbps|Mbps|Gbps|Tbps)$`)

// maxBitRateKbps bounds a parsed rate (1 Pbps) so that conversions to bps/kbps
// and to int can never overflow.
const maxBitRateKbps uint64 = 1_000_000_000_000

// parseBitRateKbps parses a TS 29.571 §5.5.2 BitRate string ("100 Mbps",
// "1.5 Gbps", "1500 bps") into kbps, rounded UP to the next whole kbps (the
// unit of the PFCP MBR IE, TS 29.244 §8.2.8; rounding up never under-grants).
// Returns ok=false for malformed, zero, negative or out-of-range values.
func parseBitRateKbps(s string) (kbps uint64, ok bool) {
	m := bitRateRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil || v <= 0 || math.IsInf(v, 0) || math.IsNaN(v) {
		return 0, false
	}
	var perKbps float64 // multiplier to kbps
	switch m[2] {
	case "bps":
		perKbps = 1e-3
	case "Kbps":
		perKbps = 1
	case "Mbps":
		perKbps = 1e3
	case "Gbps":
		perKbps = 1e6
	case "Tbps":
		perKbps = 1e9
	}
	k := v * perKbps
	if k > float64(maxBitRateKbps) {
		return 0, false
	}
	// Subtract a tiny epsilon-free guard: ceil of exact decimal products such as
	// 1.5*1e3 is exact in float64; for others (0.1 Mbps) strconv rounding can
	// give 100.00000000000001, so snap values within 1e-6 of an integer first.
	if r := math.Round(k); math.Abs(k-r) < 1e-6 {
		k = r
	}
	return uint64(math.Ceil(k)), true
}

// kbpsToMbps converts kbps to the integer Mbps used by the NAS Session-AMBR
// IE (TS 24.501 §9.11.4.14) and NGAP PDU Session AMBR, rounding UP (min 1 Mbps
// for any non-zero rate) so a sub-Mbps rate is not announced as 0.
func kbpsToMbps(kbps uint64) int {
	if kbps == 0 {
		return 0
	}
	return int((kbps + 999) / 1000)
}

// parseAMBR parses a BitRate string into (kbps, Mbps); on failure both are the
// fallback pair. Replaces the former unit-blind parseMbps.
func parseAMBR(s string, fbKbps uint64, fbMbps int) (uint64, int) {
	k, ok := parseBitRateKbps(s)
	if !ok {
		return fbKbps, fbMbps
	}
	return k, kbpsToMbps(k)
}

// kbpsOrMbps returns the exact kbps when it is consistent with the (possibly
// overridden) Mbps value, else Mbps*1000.
func kbpsOrMbps(kbps uint64, mbps int) uint64 {
	if mbps <= 0 {
		return 0
	}
	if kbps > 0 && kbpsToMbps(kbps) == mbps {
		return kbps
	}
	return uint64(mbps) * 1000
}
