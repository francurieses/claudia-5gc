package procedures

// Legacy byte-identity guard for the Registration Accept (REL19-5.5). The
// golden hex under testdata/legacy_regaccept/ was captured at the commit before
// the 5GS network feature support seam existed (git worktree of HEAD f0772e0 +
// UPDATE_GOLDEN=1), so the test proves the Rel-17 wire bytes did not move for
// both build sites, with a nil profile, an explicit rel17 profile and a rel19
// profile with the extended-NFS feature left at its default (off), for UEs with
// and without a decoded 5GMM capability. Regenerate only on a deliberate wire
// change with UPDATE_GOLDEN=1.
// Ref: TS 24.501 §8.2.7, §9.11.3.5.

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// legacyUDM is a fixed-subscription UDM stub for the initial-registration site.
type legacyUDM struct{}

func (legacyUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (legacyUDM) DeregisterUECM(context.Context, string) error              { return nil }
func (legacyUDM) GetAMSubscriptionData(context.Context, string) (*UDMAMSubscription, error) {
	return &UDMAMSubscription{
		AllowedNSSAI: []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}},
		AMBRUplink:   1_000_000, AMBRDownlink: 2_000_000,
	}, nil
}

func legacyRegHandler() *RegistrationHandler {
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, lg)
	return NewRegistrationHandler(mgr, nil, legacyUDM{}, nil, "nf", "001", "01", lg)
}

func legacyRegUE(withCap bool) *amfctx.UEContext {
	ue := &amfctx.UEContext{
		SUPI:           "imsi-001010000000001",
		AllowedNSSAI:   []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}},
		RequestedNSSAI: []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}},
	}
	if withCap {
		ue.Capability5GMM = &nas.FiveGMMCapability{S1Mode: true, NSSAA: true, CAG: true}
	}
	return ue
}

func legacyProfile(t *testing.T, name string) *capability.Profile {
	t.Helper()
	switch name {
	case "nil":
		return nil
	case "rel17":
		p, err := capability.NewProfile(capability.ReleaseConfig{Profile: "rel17"}, func(string) string { return "" })
		if err != nil {
			t.Fatal(err)
		}
		return p
	case "rel19-default":
		p, err := capability.NewProfile(capability.ReleaseConfig{Profile: "rel19"}, func(string) string { return "" })
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Fatalf("unknown profile %q", name)
	return nil
}

func TestRegistrationAcceptLegacyByteIdentical(t *testing.T) {
	dir := filepath.Join("testdata", "legacy_regaccept")
	for _, site := range []string{"initial", "update"} {
		for _, prof := range []string{"nil", "rel17", "rel19-default"} {
			for _, withCap := range []bool{false, true} {
				name := site + "-" + prof + "-nocap"
				if withCap {
					name = site + "-" + prof + "-cap"
				}
				t.Run(name, func(t *testing.T) {
					h := legacyRegHandler()
					ue := legacyRegUE(withCap)
					ctx := capability.WithProfile(context.Background(), legacyProfile(t, prof))
					var (
						ra  *nas.RegistrationAccept
						err error
					)
					if site == "initial" {
						ra, err = h.Phase3_ProcessSMCComplete(ctx, ue)
					} else {
						ra, err = h.BuildRegistrationUpdateAccept(ctx, ue)
					}
					if err != nil {
						t.Fatalf("build: %v", err)
					}
					b, err := nas.EncodeRegistrationAccept(ra)
					if err != nil {
						t.Fatalf("encode: %v", err)
					}
					got := hex.EncodeToString(b)
					// Golden is shared by profile/cap variants of one site:
					// every variant must produce the same legacy bytes.
					path := filepath.Join(dir, site+".hex")
					if os.Getenv("UPDATE_GOLDEN") == "1" {
						if err := os.WriteFile(path, []byte(got+"\n"), 0o644); err != nil {
							t.Fatal(err)
						}
						t.Logf("UPDATE_GOLDEN=1: rewrote %s from current code, comparison skipped", path)
						return
					}
					want, err := os.ReadFile(path)
					if err != nil {
						t.Fatalf("read golden: %v", err)
					}
					if got != strings.TrimSpace(string(want)) {
						t.Fatalf("Registration Accept bytes moved\n got %s\nwant %s", got, strings.TrimSpace(string(want)))
					}
				})
			}
		}
	}
}

func TestNetworkFeatureSupportGate(t *testing.T) {
	on := map[string]bool{FeatureNFSExtended: true}
	capNCR := &nas.FiveGMMCapability{NCR: true}
	capRSLP := &nas.FiveGMMCapability{RSLP: true}
	capUNPER := &nas.FiveGMMCapability{UNPER: true}
	capMLC := &nas.FiveGMMCapability{MLCSUP: true, LCSUPP: true}
	tests := []struct {
		name    string
		profile string
		feats   map[string]bool
		bits    nas.NetworkFeatureSupport
		ue      *nas.FiveGMMCapability
		want    string
	}{
		{"UE supports NCR -> octet 5 bit 4", "rel19", on, nas.NetworkFeatureSupport{NCR: true}, capNCR, "010008"},
		{"UE lacks NCR -> cleared", "rel19", on, nas.NetworkFeatureSupport{NCR: true}, capRSLP, "0100"},
		{"no capability IE -> cleared", "rel19", on, nas.NetworkFeatureSupport{NCR: true, RSLP: true}, nil, "0100"},
		{"UE supports RSLP -> 4 octets", "rel19", on, nas.NetworkFeatureSupport{RSLP: true}, capRSLP, "01000008"},
		{"UE supports UN-PER", "rel19", on, nas.NetworkFeatureSupport{UNPER: true}, capUNPER, "010080"},
		{"MLCSUP needs LCS-UPP operator bit", "rel19", on, nas.NetworkFeatureSupport{MLCSUP: true}, capMLC, "0100"},
		{"MLCSUP + LCS-UPP", "rel19", on, nas.NetworkFeatureSupport{MLCSUP: true, LCSUPP: true}, capMLC, "01000012"},
		{"no ext bits -> legacy", "rel19", on, nas.NetworkFeatureSupport{}, capNCR, "0100"},
		{"gate off: Rel-18 RSLP dropped", "rel19", nil, nas.NetworkFeatureSupport{RSLP: true}, capRSLP, "0100"},
		{"gate off: Rel-18 UN-PER dropped", "rel19", nil, nas.NetworkFeatureSupport{UNPER: true}, capUNPER, "0100"},
		{"gate off: Rel-17 NCR kept (UE supports)", "rel19", nil, nas.NetworkFeatureSupport{NCR: true}, capNCR, "010008"},
		{"gate off: Rel-17 5G-LCS kept (not UE-gated)", "rel19", nil, nas.NetworkFeatureSupport{LCS: true}, nil, "010001"},
		{"rel17: Rel-18 RSLP dropped", "rel17", on, nas.NetworkFeatureSupport{RSLP: true}, capRSLP, "0100"},
		{"no profile: nothing set -> legacy", "", nil, nas.NetworkFeatureSupport{}, capNCR, "0100"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := legacyRegHandler()
			h.WithNetworkFeatureSupportBits(tc.bits)
			ctx := context.Background()
			if tc.profile != "" {
				p, err := capability.NewProfile(capability.ReleaseConfig{Profile: tc.profile, Features: tc.feats}, func(string) string { return "" })
				if err != nil {
					t.Fatal(err)
				}
				ctx = capability.WithProfile(ctx, p)
			}
			ue := &amfctx.UEContext{Capability5GMM: tc.ue}
			if got := hex.EncodeToString(h.networkFeatureSupport(ctx, ue)); got != tc.want {
				t.Fatalf("NFS = %s, want %s", got, tc.want)
			}
		})
	}
}
