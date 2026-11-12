package ngap

// Per-gNB release capability byte-identity guard (REL19-4.8). The golden hex
// under testdata/legacy_gnb/ was captured from the builders as they were at
// commit faf1623 (before the ranCap parameter existed), so this test proves the
// Rel-17 wire bytes did not move, independent of any in-tree delegate.
// Regenerate (only on a deliberate wire change) with UPDATE_GOLDEN=1.

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

type legacyCase struct {
	name  string
	build func(ranCap capability.PeerRAN) []byte
}

func legacyCases() []legacyCase {
	nas := []byte{0x7E, 0x00, 0x42, 0x01, 0x02}
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	s1 := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	s2 := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}, {SST: 2}}
	one := []PDUSessionSetupItemCxtReq{{PDUSessionID: 1, SST: 1, SD: []byte{0, 0, 1}, Transfer: []byte{0x00, 0x01, 0x02}}}
	two := append(append([]PDUSessionSetupItemCxtReq{}, one...),
		PDUSessionSetupItemCxtReq{PDUSessionID: 5, SST: 2, Transfer: []byte{0xAA, 0xBB}})
	ics := func(nasPDU []byte, nssai []amfctx.SNSSAISubscribed, ul, dl int64, rfsp int, ps []PDUSessionSetupItemCxtReq) func(capability.PeerRAN) []byte {
		return func(c capability.PeerRAN) []byte {
			return legacyICS(1, 2, nasPDU, key, 0xE000, 0xE000, "001", "01", 0x80, 1, 1, nssai, ul, dl, rfsp, ps, c)
		}
	}
	psr := func(nasPDU []byte, sd []byte, ambr *UEAMBR) func(capability.PeerRAN) []byte {
		return func(c capability.PeerRAN) []byte {
			return legacyPSR(3, 4, 9, nasPDU, []byte{0xDE, 0xAD, 0xBE, 0xEF}, 2, sd, ambr, c)
		}
	}
	return []legacyCase{
		{"ics-nonas-nopdu", ics(nil, s1, 0, 0, 0, nil)},
		{"ics-nas-nopdu", ics(nas, s1, 0, 0, 0, nil)},
		{"ics-nas-rfsp", ics(nas, s2, 0, 0, 7, nil)},
		{"ics-nas-1session-ambr", ics(nas, s1, 100_000_000, 200_000_000, 0, one)},
		{"ics-nas-2sessions-rfsp256", ics(nas, s2, 0, 0, 256, two)},
		{"ics-nonas-2sessions", ics(nil, s2, 1, 2, 3, two)},
		{"psr-nas-sd-noambr", psr(nas, []byte{0, 0, 1}, nil)},
		{"psr-nonas-nosd-ambr", psr(nil, nil, &UEAMBR{ULBps: 1_000_000, DLBps: 2_000_000})},
		{"psr-nas-sd-ambr", psr(nas, []byte{0, 0, 1}, &UEAMBR{ULBps: 5, DLBps: 6})},
	}
}

func TestLegacyGNBByteIdentical(t *testing.T) {
	dir := filepath.Join("testdata", "legacy_gnb")
	for _, tc := range legacyCases() {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".hex")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				got := tc.build(capability.PeerRAN{})
				if len(got) == 0 {
					t.Fatal("builder returned empty PDU")
				}
				if err := os.WriteFile(path, []byte(hex.EncodeToString(got)+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			want := strings.TrimSpace(string(raw))
			peers := map[string]capability.PeerRAN{
				"zero":  {},
				"rel17": {Release: capability.Rel17},
				// No Rel-18+ IE exists in these messages yet, so a Rel-19 gNB
				// must be byte-identical too.
				"rel18": {Release: capability.Rel18},
				"rel19": {Release: capability.Rel19},
			}
			for pn, peer := range peers {
				if got := hex.EncodeToString(tc.build(peer)); got != want {
					t.Errorf("%s peer: bytes differ from golden\n got %s\nwant %s", pn, got, want)
				}
			}
		})
	}
}

func legacyICS(amfUEID, ranUEID int64, nasPDU []byte, secKey [32]byte, enc, integ uint16, mcc, mnc string,
	regionID byte, setID uint16, amfID byte, nssai []amfctx.SNSSAISubscribed, ul, dl int64, rfsp int,
	ps []PDUSessionSetupItemCxtReq, c capability.PeerRAN) []byte {
	return BuildInitialContextSetupRequest(amfUEID, ranUEID, nasPDU, secKey, enc, integ, mcc, mnc,
		regionID, setID, amfID, nssai, ul, dl, rfsp, ps, c)
}

func legacyPSR(amfUEID, ranUEID int64, psi uint8, nasPDU, n2 []byte, sst uint8, sd []byte, ambr *UEAMBR, c capability.PeerRAN) []byte {
	return BuildPDUSessionResourceSetupRequest(amfUEID, ranUEID, psi, nasPDU, n2, sst, sd, ambr, c)
}
