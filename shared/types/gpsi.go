// gpsi.go holds the Gpsi data type validation shared by the
// UDR (Nudr_DataRepository) and UDM (Nudm_SDM) producers of
// AccessAndMobilitySubscriptionData.gpsis.

package types

import (
	"regexp"
	"strings"
)

// GpsiPattern is the Gpsi schema pattern, copied verbatim from
// TS29571_CommonData.yaml components/schemas/Gpsi
// (TS 29.571 §5.3.2, Table 5.3.2-1). The trailing ".+" alternative makes the
// pattern accept any non-empty single-line string; the msisdn-/extid- forms
// are the structured ones (MSISDN per TS 23.003 §3.3, External Identifier per
// TS 23.003 §19.7.2).
const GpsiPattern = `^(msisdn-[0-9]{5,15}|extid-[^@]+@[^@]+|.+)$`

var gpsiRE = regexp.MustCompile(GpsiPattern)

// ValidGpsi reports whether s matches the Gpsi schema pattern.
func ValidGpsi(s string) bool { return gpsiRE.MatchString(s) }

// strictMSISDNRE and strictExtIDRE are the structured Gpsi forms without the
// catch-all alternative of GpsiPattern.
var (
	strictMSISDNRE = regexp.MustCompile(`^msisdn-[0-9]{5,15}$`)
	strictExtIDRE  = regexp.MustCompile(`^extid-[^@]+@[^@]+$`)
)

// StrictGpsi is the write-side rule used by the UDR seed and the management
// portal: a value starting with "msisdn-" must match ^msisdn-[0-9]{5,15}$, a
// value starting with "extid-" must match ^extid-[^@]+@[^@]+$, and any other
// form is rejected. It is stricter than ValidGpsi, whose ".+" alternative
// (TS 29.571 §5.3.2) must keep accepting received data unchanged.
func StrictGpsi(s string) bool {
	switch {
	case strings.HasPrefix(s, "msisdn-"):
		return strictMSISDNRE.MatchString(s)
	case strings.HasPrefix(s, "extid-"):
		return strictExtIDRE.MatchString(s)
	}
	return false
}

// FilterGpsis splits in into the entries that match the Gpsi pattern (order
// preserved, duplicates dropped) and the rejected ones.
func FilterGpsis(in []string) (valid, rejected []string) {
	seen := make(map[string]bool, len(in))
	for _, g := range in {
		if !ValidGpsi(g) {
			rejected = append(rejected, g)
			continue
		}
		if seen[g] {
			continue
		}
		seen[g] = true
		valid = append(valid, g)
	}
	return valid, rejected
}
