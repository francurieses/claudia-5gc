package store

import (
	"regexp"
	"strconv"
	"strings"
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
