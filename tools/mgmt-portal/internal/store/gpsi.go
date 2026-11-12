// gpsi.go: GPSI handling for portal-provisioned subscribers (AMF-020).
// subscription_am.gpsis is the column the UDR reads; the UDR serves it as
// AccessAndMobilitySubscriptionData.gpsis under the Rel-19 profile.
package store

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Strict write-side Gpsi rule, duplicated from shared/types.StrictGpsi (this
// module has no dependency on the root module; TestStrictGPSILiterals pins the
// two copies): msisdn-<5..15 digits> or extid-<local>@<domain>, nothing else.
var (
	strictMSISDN = regexp.MustCompile(`^msisdn-[0-9]{5,15}$`)
	strictExtID  = regexp.MustCompile(`^extid-[^@]+@[^@]+$`)
)

func strictGpsi(s string) bool {
	switch {
	case strings.HasPrefix(s, "msisdn-"):
		return strictMSISDN.MatchString(s)
	case strings.HasPrefix(s, "extid-"):
		return strictExtID.MatchString(s)
	}
	return false
}

// defaultMSISDNPrefix mirrors nf/udr store.DefaultSeedMSISDNPrefix ("49" plus a
// 0 separator, a dev convention) so a portal-created subscriber gets the same
// GPSI the UDR seed would give it.
const defaultMSISDNPrefix = "490"

// seedPrefixEnv is read with the same rules as the UDR: unset/empty = default,
// "off" disables the default GPSI, a non-digit prefix or one making the MSISDN
// longer than 15 digits is invalid and also disables it.
const seedPrefixEnv = "SEED_GPSI_PREFIX"

// gpsiPrefix returns the MSISDN prefix for the default GPSI; enabled is false
// when the default is switched off.
func gpsiPrefix() (prefix string, enabled bool) {
	prefix = defaultMSISDNPrefix
	if v := os.Getenv(seedPrefixEnv); v != "" {
		prefix = v
	}
	if prefix == "off" {
		return "", false
	}
	if _, ok := defaultMSISDNWith("imsi-001010000000001", prefix); !ok {
		return "", false
	}
	return prefix, true
}

// DefaultMSISDN derives the dev GPSI of a SUPI: msisdn-<prefix><last 10 digits
// of the 15-digit IMSI> (same rule as nf/udr store.SeedMSISDN, prefix from
// SEED_GPSI_PREFIX). ok is false for a SUPI that is not imsi-<15 digits> or when
// the default is disabled.
func DefaultMSISDN(supi string) (string, bool) {
	prefix, enabled := gpsiPrefix()
	if !enabled {
		return "", false
	}
	return defaultMSISDNWith(supi, prefix)
}

func defaultMSISDNWith(supi, prefix string) (string, bool) {
	d, found := strings.CutPrefix(supi, "imsi-")
	if !found || len(d) != 15 {
		return "", false
	}
	for _, c := range d + prefix {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	g := "msisdn-" + prefix + d[5:]
	if !strictGpsi(g) {
		return "", false
	}
	return g, true
}

// ValidateGPSIs reports the first entry that violates the strict Gpsi rule.
func ValidateGPSIs(gpsis []string) error {
	for _, g := range gpsis {
		if !strictGpsi(g) {
			return fmt.Errorf("store: invalid GPSI %q: want msisdn-<5..15 digits> or extid-<id>@<domain> (TS 29.571 §5.3.2, TS 23.003)", g)
		}
	}
	return nil
}

// resolveGPSIs decides what UpsertSubscriber writes. A nil list means "not
// specified": explicit is false, and the default MSISDN is used only when the
// AM row is created (INSERT); an existing row's gpsis is never touched, so a
// deliberate clear survives later non-explicit upserts. A non-nil list (even
// empty) is explicit and replaces the stored one on create and update.
func resolveGPSIs(supi string, in []string) (gpsis []string, explicit bool, err error) {
	if in != nil {
		if err := ValidateGPSIs(in); err != nil {
			return nil, true, err
		}
		return in, true, nil
	}
	if d, ok := DefaultMSISDN(supi); ok {
		return []string{d}, false, nil
	}
	return []string{}, false, nil
}
