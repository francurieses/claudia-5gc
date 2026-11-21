package store

import (
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
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

// fallbackSeedSlices is the slice set used when operator.yaml is absent or
// lists no snssais: internet, gaming, ims and bronze, one DNN each.
var fallbackSeedSlices = []operatorcfg.SNSSAIEntry{
	{SST: 1, SD: "000001", DNN: "internet"},
	{SST: 1, SD: "000002", DNN: "gaming"},
	{SST: 2, SD: "000001", DNN: "ims"},
	{SST: 3, SD: "000001", DNN: "bronze"},
}

// SeedSlices returns the dev seed slices (operator.yaml snssais, or the
// 4-slice fallback) with each per-slice DNN normalised: trimmed, lower-cased,
// "internet" stored empty (so am-data of internet-only subscribers is
// unchanged) and a DNN missing from a non-empty op.dnns[] replaced by empty
// (internet) with a WARN. Spec: TS 29.503 §6.1.6.2.9 (DnnConfiguration key).
func SeedSlices(op *operatorcfg.OperatorConfig, logger *slog.Logger) []SNSSAISubscribed {
	if logger == nil {
		logger = slog.Default()
	}
	entries := op.Slices()
	if len(entries) == 0 {
		entries = fallbackSeedSlices
	}
	known := make(map[string]bool, len(op.DNNList()))
	for _, d := range op.DNNList() {
		known[strings.ToLower(strings.TrimSpace(d.Name))] = true
	}
	out := make([]SNSSAISubscribed, 0, len(entries))
	for _, e := range entries {
		dnn := strings.ToLower(strings.TrimSpace(e.DNN))
		if dnn != "" && len(known) > 0 && !known[dnn] {
			logger.Warn("unknown seed DNN, falling back to internet",
				"procedure", "SubscriberSeed", "interface", "internal",
				"direction", "IN", "spec_ref", "TS 29.503 §6.1.6.2.9",
				"sst", e.SST, "sd", e.SD, "dnn", dnn,
				"result", "REJECT", "cause", "dnn not listed in operator dnns")
			dnn = ""
		}
		if dnn == DefaultDNN {
			dnn = ""
		}
		out = append(out, SNSSAISubscribed{SST: uint8(e.SST), SD: e.SD, DNN: dnn})
	}
	return out
}

// BuildSeedSliceProfiles builds the dev multi-slice profiles: profile 0 =
// [first slice], profile i = [first slice, slice i]. The profiles are cycled
// by UE index / SUPI MSIN (SliceProfileForSUPI).
func BuildSeedSliceProfiles(op *operatorcfg.OperatorConfig, logger *slog.Logger) [][]SNSSAISubscribed {
	slices := SeedSlices(op, logger)
	first := slices[0]
	profiles := [][]SNSSAISubscribed{{first}}
	for _, s := range slices[1:] {
		profiles = append(profiles, []SNSSAISubscribed{first, s})
	}
	return profiles
}

// FormatSeedSNSSAIs renders profile slices for the "seeded test subscriber"
// log: "SST=%d/SD=%s" plus "/DNN=%s" when the DNN is set.
func FormatSeedSNSSAIs(profile []SNSSAISubscribed) []string {
	out := make([]string, len(profile))
	for i, s := range profile {
		out[i] = fmt.Sprintf("SST=%d/SD=%s", s.SST, s.SD)
		if s.DNN != "" {
			out[i] += "/DNN=" + s.DNN
		}
	}
	return out
}
