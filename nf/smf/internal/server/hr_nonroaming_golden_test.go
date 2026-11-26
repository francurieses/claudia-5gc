package server

// hr_nonroaming_golden_test.go - ROAM-002 non-regression goldens: the plain non-roaming PFCP Session
// Establishment Request and the SMF NRF NFProfile (sbi.fqdn unset) must be byte-identical to the
// pre-ROAM-002 output. Regenerate with UPDATE_GOLDEN=1 only from a tree that predates the change.
// Ref: TS 29.244 §7.5.2.1, TS 29.510 §6.1.6.2.2.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/nrf"
)

// captureNonRoamingN4Establishment runs sendPFCPSessionEstablishment for a fixed non-roaming session
// against a local UDP PFCP stub and returns the raw request bytes it received.
func captureNonRoamingN4Establishment(t *testing.T) []byte {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen PFCP stub: %v", err)
	}
	defer conn.Close()
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 8192)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			got <- nil
			return
		}
		got <- append([]byte(nil), buf[:n]...)
		_, _ = conn.WriteToUDP(nil, raddr) // unblock the SMF's best-effort response read
	}()

	s := newGoldenServer(t)
	s.cfg.Peers.UPF = conn.LocalAddr().String()
	s.cfg.UPFN3Addr = "10.0.0.1"
	sess := &Session{
		SEID: 1, ULTEID: 1, UEIP: net.ParseIP("10.60.0.2"), DNN: "internet", PDUSessionID: 1,
		AMBRULMbps: 50, AMBRDLMbps: 200,
	}
	s.sendPFCPSessionEstablishment(context.Background(), sess)
	b := <-got
	if b == nil {
		t.Fatal("PFCP stub received no Session Establishment Request")
	}
	return b
}

// TestGolden_NonRoamingN4EstablishmentByteIdentical pins the non-roaming N4 establishment bytes.
func TestGolden_NonRoamingN4EstablishmentByteIdentical(t *testing.T) {
	b := captureNonRoamingN4Establishment(t)
	got := []byte(hex.EncodeToString(b) + "\n")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(filepath.Join("testdata", "golden_non_roaming_n4_establishment.hex"), got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want := readGolden(t, "golden_non_roaming_n4_establishment.hex"); !bytes.Equal(got, want) {
		t.Errorf("non-roaming N4 establishment bytes changed:\n got: %s\nwant: %s", got, want)
	}
}

// TestNonRoamingN4Establishment_NoHRArtifacts: with HR == nil the request carries only the plain
// two-PDR / two-FAR rule set, no N9 / second F-TEID / extra rules.
func TestNonRoamingN4Establishment_NoHRArtifacts(t *testing.T) {
	m, err := pfcpmsg.ParseSessionEstablishmentRequest(captureNonRoamingN4Establishment(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n := len(m.CreatePDR); n != 2 {
		t.Errorf("CreatePDR = %d, want 2", n)
	}
	if n := len(m.CreateFAR); n != 2 {
		t.Errorf("CreateFAR = %d, want 2", n)
	}
	if n := len(m.CreateQER); n != 2 {
		t.Errorf("CreateQER = %d, want 2", n)
	}
	if n := len(m.CreateURR); n != 1 {
		t.Errorf("CreateURR = %d, want 1", n)
	}
	if m.CreateBAR == nil {
		t.Error("CreateBAR missing")
	}
	if (&Session{}).HR != nil {
		t.Error("a plain session must have HR == nil")
	}
}

func goldenSMFProfileCfg() *config.Config {
	return &config.Config{
		NFInstanceID: "11111111-2222-3333-4444-555555555555",
		SNSSAIs: []struct {
			SST int    `yaml:"sst"`
			SD  string `yaml:"sd"`
		}{{SST: 1, SD: "000001"}, {SST: 2, SD: "000002"}},
		DNNs: []config.DNNConfig{{Name: "internet"}, {Name: "ims"}},
	}
}

// TestGolden_SMFNFProfileNoFQDNByteIdentical: ApplyFQDNIdentity with an empty fqdn is a no-op, so the
// NFProfile is the pre-ROAM-002 one.
func TestGolden_SMFNFProfileNoFQDNByteIdentical(t *testing.T) {
	p := BuildNFProfile(goldenSMFProfileCfg(), nil)
	if err := nrf.ApplyFQDNIdentity(p, "", ":8004", "001", "01"); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(filepath.Join("testdata", "golden_smf_nfprofile_no_fqdn.json"), got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want := readGolden(t, "golden_smf_nfprofile_no_fqdn.json"); !bytes.Equal(got, want) {
		t.Errorf("NFProfile (no fqdn) changed:\n got: %s\nwant: %s", got, want)
	}

	t.Run("non-empty fqdn changes the profile", func(t *testing.T) {
		p := BuildNFProfile(goldenSMFProfileCfg(), nil)
		const fqdn = "smf.5gc.mnc001.mcc001.3gppnetwork.org"
		if err := nrf.ApplyFQDNIdentity(p, fqdn, ":8004", "001", "01"); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(b, got) || !strings.Contains(string(b), fqdn) {
			t.Errorf("fqdn not applied: %s", b)
		}
	})
}
