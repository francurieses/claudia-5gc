package roaming

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const okPartner = `partners:
  - plmn: {mcc: "001", mnc: "02"}
    n32:
      ca_file: /x/ca.crt
      address: sepp.5gc.mnc002.mcc001.3gppnetwork.org:8443
    home_nfs:
      ausf_api_root: https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002
      udm_api_root: https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003
  - plmn: {mcc: "310", mnc: "260"}
    n32:
      ca_file: /y/ca.crt
`

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "partners.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadPartners(t *testing.T) {
	got, err := LoadPartners(writeFile(t, okPartner), nil)
	if err != nil || len(got) != 1 || got[0].PLMN != (PLMN{"001", "02"}) {
		t.Fatalf("got %+v err %v; want only 001-02 (entry without home_nfs ignored, n32 tolerated)", got, err)
	}
	if got, err := LoadPartners(filepath.Join(t.TempDir(), "none.yaml"), nil); err != nil || got != nil {
		t.Fatalf("missing file: got %v err %v, want none/nil", got, err)
	}
	if got, err := LoadPartners(writeFile(t, ""), nil); err != nil || got != nil {
		t.Fatalf("empty file: %v %v", got, err)
	}
}

func TestLoadPartnersInvalid(t *testing.T) {
	roots := "      ausf_api_root: https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002\n      udm_api_root: https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003\n"
	for name, body := range map[string]string{
		"bad yaml":      "partners: [",
		"bad mcc":       "partners:\n  - plmn: {mcc: \"0a1\", mnc: \"02\"}\n",
		"duplicate":     "partners:\n  - plmn: {mcc: \"001\", mnc: \"02\"}\n  - plmn: {mcc: \"001\", mnc: \"02\"}\n",
		"http root":     "partners:\n  - plmn: {mcc: \"001\", mnc: \"02\"}\n    home_nfs:\n      ausf_api_root: http://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002\n      udm_api_root: https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003\n",
		"plmn mismatch": "partners:\n  - plmn: {mcc: \"001\", mnc: \"03\"}\n    home_nfs:\n" + roots,
	} {
		if _, err := LoadPartners(writeFile(t, body), nil); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestMergeAndResolve(t *testing.T) {
	inline := HomePLMN{PLMN: PLMN{"001", "02"}, AUSFAPIRoot: "https://old", UDMAPIRoot: "https://old"}
	other := HomePLMN{PLMN: PLMN{"999", "70"}}
	file := []HomePLMN{{PLMN: PLMN{"001", "02"}, AUSFAPIRoot: "https://new"}, {PLMN: PLMN{"310", "260"}}}
	m := MergePartners(Config{HomePLMNs: []HomePLMN{inline, other}}, file)
	if len(m.HomePLMNs) != 3 || m.HomePLMNs[0].AUSFAPIRoot != "https://new" || m.HomePLMNs[1] != other || m.HomePLMNs[2].PLMN.MCC != "310" {
		t.Fatalf("merge: %+v", m.HomePLMNs)
	}

	p := writeFile(t, okPartner)
	t.Setenv(PartnersFileEnv, p)
	cfg, err := ResolveConfig(Config{Enabled: true, SEPPAddress: "sepp:8014", PartnersFile: "/nonexistent"}, nil)
	if err != nil || len(cfg.HomePLMNs) != 1 {
		t.Fatalf("env must override config key: %+v %v", cfg, err)
	}
	t.Setenv(PartnersFileEnv, "")
	cfg, err = ResolveConfig(Config{Enabled: true, SEPPAddress: "sepp:8014", PartnersFile: p}, nil)
	if err != nil || len(cfg.HomePLMNs) != 1 {
		t.Fatalf("config key: %+v %v", cfg, err)
	}
	if got := (Config{}).PartnersPath(); got != DefaultPartnersFile {
		t.Fatalf("default path %q", got)
	}
	if cfg, err := ResolveConfig(Config{Enabled: false, PartnersFile: "/bad"}, nil); err != nil || cfg.PartnersFile != "/bad" {
		t.Fatalf("disabled must not load: %v", err)
	}
}

// Default core: no partners -> non-serving PLMN is #11 (ErrHomePLMNNotConfigured, no
// route, no SBI); serving PLMN stays non-roaming (nil route -> byte-identical local path).
func TestClassifyWithPartnersFile(t *testing.T) {
	cfg := Config{Enabled: true, SEPPAddress: "sepp:8014"}
	r, err := NewFromFile(cfg, filepath.Join(t.TempDir(), "absent.yaml"), "001", "01", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rt, err := r.Classify("suci-0-001-02-0-0-0-0000000001"); rt != nil || !errors.Is(err, ErrHomePLMNNotConfigured) {
		t.Fatalf("non-partner: %v %v", rt, err)
	}
	if rt, err := r.Classify("suci-0-001-01-0-0-0-0000000001"); rt != nil || err != nil {
		t.Fatalf("serving PLMN: %v %v", rt, err)
	}
	// Partner with n32 only (no home_nfs): still #11.
	r, err = NewFromFile(cfg, writeFile(t, "partners:\n  - plmn: {mcc: \"001\", mnc: \"02\"}\n    n32: {ca_file: /x}\n"), "001", "01", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Classify("suci-0-001-02-0-0-0-1"); !errors.Is(err, ErrHomePLMNNotConfigured) {
		t.Fatalf("partner without home_nfs: %v", err)
	}
	// Partner with home_nfs routes via the SEPP.
	r, err = NewFromFile(cfg, writeFile(t, okPartner), "001", "01", nil)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := r.Classify("suci-0-001-02-0-0-0-1")
	if err != nil || rt == nil || rt.ViaSEPP != "sepp:8014" || !strings.HasPrefix(rt.AUSFAPIRoot, "https://ausf.") {
		t.Fatalf("partner route: %+v %v", rt, err)
	}
	if rt, err := r.Classify("suci-0-001-01-0-0-0-1"); rt != nil || err != nil {
		t.Fatalf("serving PLMN with file loaded: %v %v", rt, err)
	}
}
