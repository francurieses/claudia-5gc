package store

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/francurieses/claudia-5gc/shared/types"
)

var seedSUPIRe = regexp.MustCompile(`^imsi-[0-9]{15}$`)

// ParseSeedSUPIs splits a comma-separated SEED_EXTRA_SUPIS value into valid
// SUPIs (imsi- followed by 15 digits) and rejected entries. Whitespace is
// trimmed, empty entries are ignored and duplicates are dropped.
func ParseSeedSUPIs(raw string) (valid, invalid []string) {
	seen := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		supi := strings.TrimSpace(part)
		if supi == "" || seen[supi] {
			continue
		}
		seen[supi] = true
		if seedSUPIRe.MatchString(supi) {
			valid = append(valid, supi)
		} else {
			invalid = append(invalid, supi)
		}
	}
	return valid, invalid
}

// SliceProfileForSUPI picks the dev multi-slice profile for a SUPI using the
// same cyclic rule as the UE_COUNT range: profiles[(msin-1) % len(profiles)],
// where msin is the numeric value of the last 10 digits of the 15-digit IMSI.
// It falls back to profiles[0] when the MSIN cannot be parsed or is < 1, and
// returns nil when profiles is empty.
func SliceProfileForSUPI(supi string, profiles [][]SNSSAISubscribed) []SNSSAISubscribed {
	if len(profiles) == 0 {
		return nil
	}
	digits := strings.TrimPrefix(supi, "imsi-")
	if len(digits) != 15 {
		return profiles[0]
	}
	msin, err := strconv.Atoi(digits[5:])
	if err != nil || msin < 1 {
		return profiles[0]
	}
	return profiles[(msin-1)%len(profiles)]
}

// DefaultSeedMSISDNPrefix is the digit prefix of the dev MSISDN derived by
// SeedMSISDN (a "country code" 49 plus a 0 separator; a dev convention, not a
// numbering-plan claim). tools/mgmt-portal (separate module) keeps the same
// literal; a test in each module pins both to the same derivation.
const DefaultSeedMSISDNPrefix = "490"

// SeedMSISDN derives the dev subscriber's GPSI from its SUPI, deterministically:
//
//	msisdn-<prefix><last 10 digits of the 15-digit IMSI>
//
// e.g. imsi-001010000000001 -> msisdn-4900000000001 with the default prefix.
// The result matches the Gpsi pattern (TS 29.571 §5.3.2, "msisdn-" + 5..15
// digits; the MSISDN is at most 15 digits, TS 23.003 §3.3). ok is false when
// supi is not imsi-<15 digits>, the prefix is not all digits, or the result
// would exceed 15 digits.
func SeedMSISDN(supi, prefix string) (gpsi string, ok bool) {
	if !seedSUPIRe.MatchString(supi) {
		return "", false
	}
	for _, c := range prefix {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	digits := prefix + strings.TrimPrefix(supi, "imsi-")[5:]
	if len(digits) < 5 || len(digits) > 15 {
		return "", false
	}
	g := "msisdn-" + digits
	if !types.StrictGpsi(g) {
		return "", false
	}
	return g, true
}

// EnsureSeedGPSI stores the SeedMSISDN GPSI on the subscriber's AM record when
// the stored list is empty, through one conditional update (Store.SetGPSIsIfEmpty)
// so a concurrent portal write is never overwritten. It reports whether it
// wrote. A subscriber without an AM row, or with GPSIs already, is (false, nil).
//
// Limitation: the schema cannot tell "cleared on purpose" from "never set", so
// a seeded subscriber whose GPSIs were cleared in the portal gets the default
// back at the next UDR restart. Use SEED_GPSI_PREFIX=off to stop that.
// Call it only for SUPIs the UDR seed itself owns (UE_COUNT range and
// SEED_EXTRA_SUPIS).
func EnsureSeedGPSI(s Store, supi, prefix string) (added bool, err error) {
	gpsi, ok := SeedMSISDN(supi, prefix)
	if !ok {
		return false, nil
	}
	added, err = s.SetGPSIsIfEmpty(supi, []string{gpsi})
	if err != nil {
		return false, fmt.Errorf("udr: seed gpsi %s: %w", supi, err)
	}
	return added, nil
}
