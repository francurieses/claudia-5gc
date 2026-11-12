package features

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func TestTables(t *testing.T) {
	tests := []struct {
		name    string
		entries []Entry
		count   int
		rel     map[int]capability.Release
		names   map[int]string
		mand    []int
	}{
		{"Nsmf_PDUSession", NsmfPDUSessionEntries(), 41,
			map[int]capability.Release{1: capability.Rel17, 21: capability.Rel17, 22: capability.Rel18, 33: capability.Rel18, 34: capability.Rel19, 41: capability.Rel19},
			map[int]string{1: "CIOT", 22: "DTSSA-Ext1", 39: "AMF-RESYNCHED", 40: "5GSAT-ACCESS"},
			[]int{7, 8, 10, 29}},
		{"Namf_Communication", NamfCommunicationEntries(), 22,
			map[int]capability.Release{1: capability.Rel17, 13: capability.Rel17, 14: capability.Rel18, 19: capability.Rel18, 20: capability.Rel17, 21: capability.Rel18, 22: capability.Rel19},
			map[int]string{13: "3GA-N3GA-HO", 17: "Ranging_SL", 22: "ProSe_Multihop"},
			[]int{7}},
		{"Nausf_UEAuthentication", NausfUEAuthenticationEntries(), 1,
			map[int]capability.Release{1: capability.Rel17},
			map[int]string{1: "ES3XX"},
			[]int{1}},
		{"Nudm_UEAU", NudmUEAUEntries(), 1,
			map[int]capability.Release{1: capability.Rel19},
			map[int]string{1: "SUBDMIG"},
			nil},
		{"Nudm_SDM", NudmSDMEntries(), 25,
			map[int]capability.Release{1: capability.Rel17, 15: capability.Rel17, 16: capability.Rel18, 18: capability.Rel18, 19: capability.Rel17,
				20: capability.Rel19, 21: capability.Rel19, 22: capability.Rel18, 23: capability.Rel19, 25: capability.Rel19},
			map[int]string{1: "SharedData", 7: "sorTransparentSupport", 12: "upuTransparentSupport", 14: "SNPN-ID", 22: "Cag-Info-With-Validity-Periods", 25: "PCPDEIVID"},
			nil},
		{"Nudm_UECM", NudmUECMEntries(), 6,
			map[int]capability.Release{1: capability.Rel17, 3: capability.Rel17, 4: capability.Rel18, 5: capability.Rel18, 6: capability.Rel19},
			map[int]string{1: "SharedData", 2: "PatchReport", 5: "DeregistrationResponseBody", 6: "SUBDMIG"},
			nil},
		{"AsSessionWithQoS", AsSessionWithQoSEntries(), 38,
			map[int]capability.Release{1: capability.Rel17, 15: capability.Rel17, 16: capability.Rel18, 29: capability.Rel18, 30: capability.Rel19, 38: capability.Rel19},
			map[int]string{1: "Notification_websocket", 9: "AppId", 15: "PacketDelayFailureReport", 24: "GMEC", 29: "L4S", 36: "ExtQoSR19", 37: "EnQoSMon_v2", 38: "SmallBurstSizes"},
			nil},
		{"Nbsf_Management", NbsfManagementEntries(), 8,
			map[int]capability.Release{1: capability.Rel17, 6: capability.Rel17, 7: capability.Rel19, 8: capability.Rel19},
			map[int]string{1: "MultiUeAddr", 4: "ES3XX", 6: "AddSnssaiDnnPair", 7: "Recovery", 8: "ExpTime"},
			nil},
		{"Nsmsf_SMService", NsmsfSMServiceEntries(), 2,
			map[int]capability.Release{1: capability.Rel17, 2: capability.Rel17},
			map[int]string{1: "ES3XX", 2: "PatchReport"},
			[]int{1}},
		{"Nlmf_Location", NlmfLocationEntries(), 9,
			map[int]capability.Release{1: capability.Rel17, 2: capability.Rel17, 3: capability.Rel17, 4: capability.Rel18, 5: capability.Rel18,
				6: capability.Rel17, 7: capability.Rel18, 8: capability.Rel19, 9: capability.Rel19},
			map[int]string{1: "ES3XX", 3: "MUTIQOS", 5: "Ranging_SL", 6: "INTRES", 7: "CIMLR", 8: "MCTX", 9: "MWAB"},
			[]int{1}},
		{"Nnssf_NSSelection", NnssfNSSelectionEntries(), 4,
			map[int]capability.Release{1: capability.Rel17, 4: capability.Rel17},
			map[int]string{1: "ES3XX", 2: "TargetNssai", 3: "RSIPCE", 4: "SIOP"},
			[]int{1}},
		{"Npcf_SMPolicyControl", NpcfSMPolicyControlEntries(), 119,
			map[int]capability.Release{1: capability.Rel17, 73: capability.Rel17, 74: capability.Rel18, 98: capability.Rel18, 99: capability.Rel19, 119: capability.Rel19},
			map[int]string{1: "TSC", 43: "ES3XX", 62: "BIUMR", 83: "UnlimitedMultiIpv6Prefix", 84: "NscSupportedFeatures", 99: "QoSMonCapRepo", 114: "MultiModaIId", 119: "CnHealthMonitor"},
			nil},
		{"Npcf_AMPolicyControl", NpcfAMPolicyControlEntries(), 24,
			map[int]capability.Release{1: capability.Rel17, 13: capability.Rel17, 14: capability.Rel18, 21: capability.Rel18, 22: capability.Rel19, 24: capability.Rel19},
			map[int]string{1: "SliceSupport", 8: "ES3XX", 14: "FeatureRenegotiation", 24: "CHFGroup"},
			nil},
		{"Npcf_UEPolicyControl", NpcfUEPolicyControlEntries(), 28,
			map[int]capability.Release{1: capability.Rel17, 9: capability.Rel17, 10: capability.Rel18, 25: capability.Rel18, 26: capability.Rel19, 28: capability.Rel19},
			map[int]string{1: "PendingTransaction", 8: "ES3XX", 25: "EnhEstRoaming", 28: "ExtDeliveryOutcome"},
			nil},
		{"Npcf_PolicyAuthorization", NpcfPolicyAuthorizationEntries(), 83,
			map[int]capability.Release{1: capability.Rel17, 41: capability.Rel17, 42: capability.Rel18, 43: capability.Rel18, 44: capability.Rel17, 45: capability.Rel18, 63: capability.Rel18, 64: capability.Rel19, 83: capability.Rel19},
			map[int]string{1: "InfluenceOnTrafficRouting", 26: "ES3XX", 44: "PacketDelayFailureReport", 46: "SignalingPathValidation", 83: "SmallBurstSizes"},
			nil},
		{"Nnrf_NFManagement", NnrfNFManagementEntries(), 10,
			map[int]capability.Release{1: capability.Rel17, 4: capability.Rel17, 5: capability.Rel18, 10: capability.Rel18},
			map[int]string{1: "Service-Map", 3: "Inter-Plmn-Fqdn", 4: "NRFSET", 5: "Complete-Profile-Subscription", 10: "Shared-Data-Retrieval"},
			[]int{1, 3}},
		{"Nnrf_NFDiscovery", NnrfNFDiscoveryEntries(), 62,
			map[int]capability.Release{1: capability.Rel17, 29: capability.Rel17, 30: capability.Rel18, 42: capability.Rel18, 43: capability.Rel17,
				44: capability.Rel18, 50: capability.Rel18, 51: capability.Rel19, 62: capability.Rel19},
			map[int]string{1: "Complex-Query", 6: "Service-Map", 42: "Query-5G-RangingSlPos", 43: "Query-eNS-PH2", 51: "NFsel_by_tPLMN", 62: "Query-BSF-NonIP"},
			[]int{6}},
		{"N32_Handshake", N32HandshakeEntries(), 5,
			map[int]capability.Release{1: capability.Rel17, 2: capability.Rel18, 3: capability.Rel18, 4: capability.Rel18, 5: capability.Rel18},
			map[int]string{1: "NFTLST", 2: "PSEPRO", 3: "PSIU", 4: "SNDN32F", 5: "TLSCOR"},
			[]int{3}},
		{"Nnrf_AccessToken", NnrfAccessTokenEntries(), 1,
			map[int]capability.Release{1: capability.Rel19},
			map[int]string{1: "Retrieve-Key"},
			nil},
		{"Nudr_DataRepository", NudrDataRepositoryEntries(), 78,
			map[int]capability.Release{1: capability.Rel17, 13: capability.Rel17, 15: capability.Rel17, 30: capability.Rel17, 31: capability.Rel18,
				41: capability.Rel18, 42: capability.Rel17, 43: capability.Rel18, 54: capability.Rel17, 58: capability.Rel18, 60: capability.Rel18,
				61: capability.Rel18, 62: capability.Rel19, 74: capability.Rel19, 75: capability.Rel18, 76: capability.Rel19, 80: capability.Rel19},
			map[int]string{1: "ResourceRemovalNotificationPolicyData", 9: "SessionManagementPolicyDataPatch", 15: "OSDResource_Create_Delete",
				40: "DCAMP_Roaming_LBO", 70: "SUBDMIG", 80: "BdtNotifUriPatch"},
			nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.entries) != tc.count {
				t.Fatalf("count=%d want %d", len(tc.entries), tc.count)
			}
			seen := map[int]Entry{}
			for _, e := range tc.entries {
				if e.Name == "" || e.Implemented {
					t.Errorf("entry %d: empty name or implemented: %+v", e.Number, e)
				}
				if _, dup := seen[e.Number]; dup {
					t.Errorf("duplicate number %d", e.Number)
				}
				seen[e.Number] = e
			}
			for n, r := range tc.rel {
				if seen[n].Release != r {
					t.Errorf("feature %d release=%v want %v", n, seen[n].Release, r)
				}
			}
			for n, name := range tc.names {
				if seen[n].Name != name {
					t.Errorf("feature %d name=%q want %q", n, seen[n].Name, name)
				}
			}
			mand := map[int]bool{}
			for _, n := range tc.mand {
				mand[n] = true
			}
			for n, e := range seen {
				if e.Mandatory != mand[n] {
					t.Errorf("feature %d Mandatory=%v want %v", n, e.Mandatory, mand[n])
				}
			}
			c, err := NewCatalog(tc.entries...)
			if err != nil {
				t.Fatalf("NewCatalog: %v", err)
			}
			if got := c.Supported(profile(t, "rel19", nil)); !got.IsEmpty() {
				t.Errorf("unimplemented table offers %q under rel19", got)
			}
			// Fresh copies: mutating one result must not leak into the next.
			tc.entries[0].Implemented = true
		})
	}
	if NsmfPDUSessionEntries()[0].Implemented || NamfCommunicationEntries()[0].Implemented ||
		NausfUEAuthenticationEntries()[0].Implemented || NudmUEAUEntries()[0].Implemented || NudmSDMEntries()[0].Implemented || NudmUECMEntries()[0].Implemented ||
		AsSessionWithQoSEntries()[0].Implemented || NbsfManagementEntries()[0].Implemented ||
		NsmsfSMServiceEntries()[0].Implemented || NlmfLocationEntries()[0].Implemented ||
		NnssfNSSelectionEntries()[0].Implemented ||
		NpcfSMPolicyControlEntries()[0].Implemented || NpcfAMPolicyControlEntries()[0].Implemented ||
		NpcfUEPolicyControlEntries()[0].Implemented || NpcfPolicyAuthorizationEntries()[0].Implemented ||
		N32HandshakeEntries()[0].Implemented || NnrfNFManagementEntries()[0].Implemented || NnrfNFDiscoveryEntries()[0].Implemented ||
		NnrfAccessTokenEntries()[0].Implemented || NudrDataRepositoryEntries()[0].Implemented {
		t.Error("tables must return fresh copies")
	}
}

// TestUdrReservedNumbersAbsent: TS 29.504 Table 6.1.8-1 reserves 14 and 59.
func TestUdrReservedNumbersAbsent(t *testing.T) {
	c := MustCatalog(NudrDataRepositoryEntries()...)
	for _, n := range []int{14, 59, 81} {
		if _, ok := c.Lookup(n); ok {
			t.Errorf("feature %d must not be in the Nudr table", n)
		}
	}
}

// TestNewTablesStructure: the Nnrf and Nudr tables list strictly increasing
// numbers, contiguous from 1 except the reserved Nudr numbers 14 and 59
// (TS 29.504 Table 6.1.8-1), with non-empty unique names.
func TestNewTablesStructure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		entries  []Entry
		reserved map[int]bool
	}{
		{"Nnrf_NFManagement", NnrfNFManagementEntries(), nil},
		{"Nnrf_NFDiscovery", NnrfNFDiscoveryEntries(), nil},
		{"N32_Handshake", N32HandshakeEntries(), nil},
		{"Nnrf_AccessToken", NnrfAccessTokenEntries(), nil},
		{"Nudr_DataRepository", NudrDataRepositoryEntries(), map[int]bool{14: true, 59: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			names := map[string]int{}
			prev := 0
			for _, e := range tc.entries {
				if e.Number <= prev {
					t.Errorf("number %d not strictly increasing after %d", e.Number, prev)
				}
				for n := prev + 1; n < e.Number; n++ {
					if !tc.reserved[n] {
						t.Errorf("gap: number %d missing before %d", n, e.Number)
					}
				}
				for n := range tc.reserved {
					if n == e.Number {
						t.Errorf("reserved number %d is listed", n)
					}
				}
				if e.Name == "" {
					t.Errorf("feature %d has an empty name", e.Number)
				}
				if first, dup := names[e.Name]; dup {
					t.Errorf("name %q used by features %d and %d", e.Name, first, e.Number)
				}
				names[e.Name] = e.Number
				prev = e.Number
			}
		})
	}
}

func TestImplement(t *testing.T) {
	base := NsmfPDUSessionEntries()
	impl, err := Implement(base, 7, 8, 34)
	if err != nil {
		t.Fatal(err)
	}
	if base[6].Implemented {
		t.Error("Implement must not mutate its input")
	}
	c := MustCatalog(impl...)
	// Features 7 and 8 -> 0x40|0x80 = c0; 34 is Rel19 and gated out under rel17.
	if got := c.Supported(profile(t, "rel17", nil)).String(); got != "c0" {
		t.Errorf("rel17 Supported=%q want c0", got)
	}
	if got := c.Supported(profile(t, "rel19", nil)); !got.Has(34) || got.Len() != 3 {
		t.Errorf("rel19 Supported=%q", got)
	}
	for _, n := range []int{0, 42, -1} {
		if _, err := Implement(base, 7, n); err == nil {
			t.Errorf("Implement(%d) expected error", n)
		}
	}
}
