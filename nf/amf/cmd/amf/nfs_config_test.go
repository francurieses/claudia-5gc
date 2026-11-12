package main

// nfs_config_test.go - REL19-5.5 end-to-end: AMF YAML -> loadConfig ->
// release profile + handler wiring (as in main) -> Registration Accept bytes,
// gated by the UE's 5GMM capability. The default config must stay legacy.
// Ref: TS 24.501 §9.11.3.5, §5.5.1.2.4.

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
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

type nfsUDM struct{}

func (nfsUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (nfsUDM) DeregisterUECM(context.Context, string) error              { return nil }
func (nfsUDM) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	return &procedures.UDMAMSubscription{
		AllowedNSSAI: []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}},
		AMBRUplink:   1_000_000, AMBRDownlink: 2_000_000,
	}, nil
}

// nfsHandler wires a RegistrationHandler from the YAML exactly as main does and
// returns it with a context carrying the YAML's release profile.
func nfsHandler(t *testing.T, yaml string) (*procedures.RegistrationHandler, context.Context) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "amf.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	prof, err := capability.NewProfile(cfg.Release, func(string) string { return "" })
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, lg)
	h := procedures.NewRegistrationHandler(mgr, nfsAUSF{}, nfsUDM{}, nil, "nf", "001", "01", lg)
	h.WithIMSVoPS3GPP(true)
	h.WithNetworkFeatureSupportBits(cfg.Operator.NetworkFeatureSupport.Bits())
	return h, capability.WithProfile(context.Background(), prof)
}

type nfsAUSF struct{}

func (nfsAUSF) InitiateAuth(context.Context, string, string) (*procedures.AUSFInitResponse, error) {
	return &procedures.AUSFInitResponse{AuthCtxID: "ctx-1", SUPI: "imsi-001010000000001"}, nil
}
func (nfsAUSF) ResyncAuth(context.Context, string, string, [16]byte, []byte) (*procedures.AUSFInitResponse, error) {
	return nil, io.EOF
}
func (nfsAUSF) ConfirmAuth(context.Context, string, string) (*procedures.AUSFConfirmResponse, error) {
	return nil, io.EOF
}

// acceptContent encodes ra, decodes it again and returns the IEI 0x21 content.
func acceptContent(t *testing.T, ra *nas.RegistrationAccept) string {
	t.Helper()
	b, err := nas.EncodeRegistrationAccept(ra)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := nas.DecodeRegistrationAccept(b)
	if err != nil {
		t.Fatalf("decode accept: %v", err)
	}
	return hex.EncodeToString(dec.NetworkFeatureSupport)
}

func newNFSUE(c *nas.FiveGMMCapability) *amfctx.UEContext {
	return &amfctx.UEContext{
		SUPI:           "imsi-001010000000001",
		AllowedNSSAI:   []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}},
		RequestedNSSAI: []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}},
		Capability5GMM: c,
	}
}

// acceptNFS returns the IEI 0x21 content of the initial Registration Accept for
// a UE whose 5GMM capability is c.
func acceptNFS(t *testing.T, yaml string, c *nas.FiveGMMCapability) string {
	t.Helper()
	h, ctx := nfsHandler(t, yaml)
	ra, err := h.Phase3_ProcessSMCComplete(ctx, newNFSUE(c))
	if err != nil {
		t.Fatalf("phase3: %v", err)
	}
	return acceptContent(t, ra)
}

// regRequestRel19 is a real REGISTRATION REQUEST (TS 24.501 §8.2.6): initial
// registration, null-scheme SUCI of 001/01, UE security capability, and a
// 10-octet 5GMM capability IE (0x10) carrying S1-mode, NCR, RPR, PR (Rel-17),
// UN-PER, RSLP, LCS-UPP, SUPL (Rel-18) and MLCSUP, EF5L (Rel-19).
const regRequestRel19 = "7e004179" + // EPD, SHT 0, type 0x41, ngKSI 7 / FOR / initial
	"000d" + "0100f110" + "0000" + "00" + "00" + "0000000010" + // 5GS mobile identity LV (SUCI)
	"2e04e0e00000" + // UE security capability
	"100a01 0000d0 0000 04 1a 00 44" // 5GMM capability, 10 value octets

// TestRegistrationRequestCapabilityToAccept drives real NAS bytes through the
// AMF Registration handler: Request -> Phase1 (decode + store capability) ->
// Phase3 (Registration Accept), proving the Rel-18/19 5GMM capability bits flow
// into the IEI 0x21 content only when configured and gated.
func TestRegistrationRequestCapabilityToAccept(t *testing.T) {
	raw, err := hex.DecodeString(strings.ReplaceAll(regRequestRel19, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	const ops = "operator:\n  network_feature_support:\n    ncr: true\n    rpr: true\n    pr: true\n    un_per: true\n" +
		"    lcs_upp: true\n    supl: true\n    rslp: true\n    mlcsup: true\n    ef5l: true\n"
	const gate = "release:\n  profile: rel19\n  features:\n    NAS-NFS-EXT: true\n"
	tests := []struct{ name, yaml, want string }{
		{"default config: legacy", "", "0100"},
		{"bits, gate off: Rel-17 bits only", ops, "010068"},
		{"bits + NAS-NFS-EXT: Rel-17/18/19 bits", ops + gate, "0100e83e"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := nas.DecodeRegistrationRequest(raw[3:]) // body after EPD, SHT, message type
			if err != nil {
				t.Fatalf("decode request: %v", err)
			}
			h, ctx := nfsHandler(t, tc.yaml)
			ue := newNFSUE(nil)
			if _, err := h.Phase1_InitiateAuthentication(ctx, procedures.RegistrationInput{UE: ue, RegRequest: rr, RawRegRequest: raw}); err != nil {
				t.Fatalf("phase1: %v", err)
			}
			c := ue.Capability5GMM
			if c == nil || !c.NCR || !c.UNPER || !c.RSLP || !c.LCSUPP || !c.SUPL || !c.MLCSUP || !c.EF5L || c.PIV {
				t.Fatalf("capability not stored from wire bytes: %+v", c)
			}
			ra, err := h.Phase3_ProcessSMCComplete(ctx, ue)
			if err != nil {
				t.Fatalf("phase3: %v", err)
			}
			if got := acceptContent(t, ra); got != tc.want {
				t.Fatalf("IEI 0x21 content = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestNetworkFeatureSupportConfigEndToEnd(t *testing.T) {
	const ops = "operator:\n  network_feature_support:\n    ncr: true\n    rpr: true\n    pr: true\n    rslp: true\n"
	const gate = "release:\n  profile: rel19\n  features:\n    NAS-NFS-EXT: true\n"
	ueAll := &nas.FiveGMMCapability{NCR: true, RPR: true, PR: true, RSLP: true}
	ueRel17 := &nas.FiveGMMCapability{NCR: true, RPR: true, PR: true}
	tests := []struct {
		name string
		yaml string
		ue   *nas.FiveGMMCapability
		want string
	}{
		{"default config -> legacy 2 octets", "", ueAll, "0100"},
		{"bits configured, no gate: Rel-17 bits only (NCR|RPR|PR)", ops, ueAll, "010068"},
		{"bits + NAS-NFS-EXT + UE caps -> octets 5-6", ops + gate, ueAll, "01006808"},
		{"bits + gate, UE without RSLP -> octet 6 dropped", ops + gate, ueRel17, "010068"},
		{"bits + gate, UE without 5GMM capability IE -> legacy", ops + gate, nil, "0100"},
		{"gate on, no bits configured -> legacy", gate, ueAll, "0100"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := acceptNFS(t, tc.yaml, tc.ue); got != tc.want {
				t.Fatalf("IEI 0x21 content = %s, want %s", got, tc.want)
			}
		})
	}
}
