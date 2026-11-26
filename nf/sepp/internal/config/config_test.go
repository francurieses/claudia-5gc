package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// noFile points the partners file at an absent path so tests never read /etc.
func noFile(t *testing.T) {
	t.Helper()
	t.Setenv(PartnersFileEnv, filepath.Join(t.TempDir(), "absent-partners.yaml"))
}

func TestLoadDefaultsWhenMissing(t *testing.T) {
	noFile(t)
	t.Setenv("CONFIG_PATH", filepath.Join(t.TempDir(), "absent.yaml"))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SBI.Address != "0.0.0.0:8014" || cfg.Metrics.Address != "0.0.0.0:9115" || cfg.N32.Address != "0.0.0.0:8443" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadOverridesAndBadYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("sbi:\n  address: \"1.2.3.4:1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", p)
	cfg, err := Load()
	if err != nil || cfg.SBI.Address != "1.2.3.4:1" {
		t.Fatalf("override failed: %v %+v", err, cfg)
	}
	if err := os.WriteFile(p, []byte("sbi: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected parse error")
	}
}

func writeYAML(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsNoPartnersNoFallback(t *testing.T) {
	noFile(t)
	t.Setenv("CONFIG_PATH", filepath.Join(t.TempDir(), "absent.yaml"))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HasRoamingConfig() || len(cfg.Initiators()) != 0 || cfg.PartnersFileLoaded {
		t.Fatalf("default must have no partners: %+v", cfg.N32.Partners)
	}
	if cfg.N32.TLS.CertFile != "/etc/5gc/pki/n32/local/sepp.crt" || cfg.N32.TLS.KeyFile != "/etc/5gc/pki/n32/local/sepp.key" {
		t.Fatalf("N32 cert defaults: %+v", cfg.N32.TLS)
	}
	if cfg.SBI.FQDN != "sepp.5gc.mnc001.mcc001.3gppnetwork.org" {
		t.Fatalf("sbi.fqdn=%q", cfg.SBI.FQDN)
	}
}

func TestFQDNDerivedFromPLMN(t *testing.T) {
	noFile(t)
	t.Setenv("CONFIG_PATH", writeYAML(t, "c.yaml", "plmn: {mcc: \"310\", mnc: \"26\"}\n"))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SBI.FQDN != "sepp.5gc.mnc026.mcc310.3gppnetwork.org" {
		t.Fatalf("sbi.fqdn=%q (MNC must be zero-padded to 3)", cfg.SBI.FQDN)
	}
	if got := (Partner{PLMN: PLMN{MCC: "001", MNC: "02"}}).FQDN(); got != "sepp.5gc.mnc002.mcc001.3gppnetwork.org" {
		t.Fatalf("partner fqdn=%q", got)
	}
}

func TestPartnersInlineFileOverrideAndEnv(t *testing.T) {
	file := writeYAML(t, "partners.yaml", `partners:
  - plmn: {mcc: "001", mnc: "02"}
    n32: {ca_file: /file/ca.crt, address: "p:8443"}
  - plmn: {mcc: "001", mnc: "03"}
    home_nfs: {ausf_api_root: "https://a:1", udm_api_root: "https://u:1"}
`)
	t.Setenv(PartnersFileEnv, file)
	t.Setenv("CONFIG_PATH", writeYAML(t, "c.yaml", `n32:
  partners_file: /ignored/by/env.yaml
  partners:
    - plmn: {mcc: "001", mnc: "02"}
      n32: {ca_file: /inline/ca.crt}
    - plmn: {mcc: "001", mnc: "04"}
      n32: {ca_file: /inline4/ca.crt}
`))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PartnersFileLoaded || cfg.PartnersFilePath != file {
		t.Fatalf("file not used: %q %v", cfg.PartnersFilePath, cfg.PartnersFileLoaded)
	}
	by := map[string]Partner{}
	for _, p := range cfg.N32.Partners {
		by[p.PLMN.Key()] = p
	}
	if len(by) != 3 {
		t.Fatalf("partners: %+v", cfg.N32.Partners)
	}
	if p := by["001-002"]; p.Source != SourceFile || p.N32.CAFile != "/file/ca.crt" || p.N32.Address != "p:8443" {
		t.Fatalf("file must override inline: %+v", p)
	}
	if p := by["001-004"]; p.Source != SourceConfig {
		t.Fatalf("inline source: %+v", p)
	}
	// 001/03 has home_nfs only: an AMF partner, not an N32 partner.
	if n := len(cfg.N32Partners()); n != 2 {
		t.Fatalf("N32Partners=%d", n)
	}
	if n := len(cfg.Initiators()); n != 1 {
		t.Fatalf("Initiators=%d", n)
	}
}

func TestPartnersFileFromConfigKeyAndMissingIsNotAnError(t *testing.T) {
	file := writeYAML(t, "p.yaml", "partners:\n  - plmn: {mcc: \"001\", mnc: \"02\"}\n    n32: {ca_file: /x}\n")
	t.Setenv(PartnersFileEnv, "")
	t.Setenv("CONFIG_PATH", writeYAML(t, "c.yaml", "n32:\n  partners_file: "+file+"\n"))
	cfg, err := Load()
	if err != nil || len(cfg.N32Partners()) != 1 || cfg.N32Partners()[0].Source != SourceFile {
		t.Fatalf("n32.partners_file not honoured: %v %+v", err, cfg)
	}
	t.Setenv("CONFIG_PATH", writeYAML(t, "c2.yaml", "n32:\n  partners_file: /nonexistent/partners.yaml\n"))
	cfg, err = Load()
	if err != nil || cfg.HasRoamingConfig() || cfg.PartnersFileLoaded {
		t.Fatalf("missing file must mean no partners: %v", err)
	}
}

func TestInvalidPartnersFileFailsClosed(t *testing.T) {
	t.Setenv("CONFIG_PATH", filepath.Join(t.TempDir(), "absent.yaml"))
	for name, body := range map[string]string{
		"bad yaml":       "partners: [unclosed",
		"unknown key":    "partners:\n  - plmn: {mcc: \"001\", mnc: \"02\"}\n    n32: {ca_filee: /x}\n",
		"bad plmn":       "partners:\n  - plmn: {mcc: \"1\", mnc: \"02\"}\n",
		"duplicate plmn": "partners:\n  - plmn: {mcc: \"001\", mnc: \"02\"}\n  - plmn: {mcc: \"001\", mnc: \"002\"}\n",
		"n32 no ca_file": "partners:\n  - plmn: {mcc: \"001\", mnc: \"02\"}\n    n32: {address: \"h:1\"}\n",
		"bad address":    "partners:\n  - plmn: {mcc: \"001\", mnc: \"02\"}\n    n32: {ca_file: /x, address: host}\n",
	} {
		t.Setenv(PartnersFileEnv, writeYAML(t, "p.yaml", body))
		if _, err := Load(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLegacyKeysRejectedNamingReplacement(t *testing.T) {
	noFile(t)
	for name, tc := range map[string]struct{ yaml, want string }{
		"roaming_partners": {"n32:\n  roaming_partners:\n    - {mcc: \"001\", mnc: \"02\"}\n", "n32.partners"},
		"peers":            {"n32:\n  peers: []\n", "n32.partners[].n32.address"},
		"tls.ca_file":      {"n32:\n  tls:\n    ca_file: /x\n", "n32.partners[].n32.ca_file"},
	} {
		t.Setenv("CONFIG_PATH", writeYAML(t, "c.yaml", tc.yaml))
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err=%v want mention of %q", name, err, tc.want)
		}
	}
}

func TestPartnerPLMNValidation(t *testing.T) {
	for _, tc := range []struct {
		mcc, mnc string
		ok       bool
	}{{"001", "01", true}, {"310", "260", true}, {"1", "01", false}, {"001", "1", false}, {"001", "0001", false}, {"00a", "01", false}, {"", "", false}} {
		c := defaults()
		c.N32.Partners = []Partner{{PLMN: PLMN{MCC: tc.mcc, MNC: tc.mnc}, N32: PartnerN32{CAFile: "/x"}}}
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%q/%q: err=%v", tc.mcc, tc.mnc, err)
		}
	}
}

func TestTopologyHidingDefaultAndExplicit(t *testing.T) {
	noFile(t)
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{"omitted defaults to true", "n32:\n  address: \"0.0.0.0:8443\"\n", true},
		{"explicit true", "n32:\n  topology_hiding: true\n", true},
		{"explicit false", "n32:\n  topology_hiding: false\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CONFIG_PATH", p)
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.TopologyHidingEnabled(); got != tc.want {
				t.Fatalf("TopologyHidingEnabled=%v want %v", got, tc.want)
			}
		})
	}
	p := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(p, []byte("n32:\n  topology_hiding: maybe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", p)
	if _, err := Load(); err == nil {
		t.Fatal("non-boolean topology_hiding must be rejected")
	}
}

func TestHasRoamingConfig(t *testing.T) {
	cfg := defaults()
	if cfg.HasRoamingConfig() {
		t.Fatal("default config has no roaming")
	}
	cfg.N32.Partners = []Partner{{PLMN: PLMN{MCC: "001", MNC: "02"}}}
	if cfg.HasRoamingConfig() {
		t.Fatal("a partner without n32.ca_file is not an N32 partner")
	}
	cfg.N32.Partners[0].N32.CAFile = "/x"
	if !cfg.HasRoamingConfig() {
		t.Fatal("partner with ca_file must count")
	}
}

// The shipped configs and the shipped partners files must load with the new schema.
func TestShippedConfigsLoad(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	testpeer := filepath.Join(root, "config", "roaming", "partners-testpeer.yaml")
	example := filepath.Join(root, "config", "roaming", "partners.example.yaml")
	for _, tc := range []struct {
		cfg, partners string
		wantPartners  int
		wantInit      int
	}{
		{"dev.yaml", "absent", 0, 0},
		{"dev.yaml", example, 0, 0},
		{"dev.yaml", testpeer, 1, 1},
		{"hsepp.yaml", "absent", 1, 1},
	} {
		p := tc.partners
		if p == "absent" {
			p = filepath.Join(t.TempDir(), "none.yaml")
		}
		t.Setenv(PartnersFileEnv, p)
		t.Setenv("CONFIG_PATH", filepath.Join("..", "..", "config", tc.cfg))
		cfg, err := Load()
		if err != nil {
			t.Fatalf("%s + %s: %v", tc.cfg, tc.partners, err)
		}
		if n := len(cfg.N32Partners()); n != tc.wantPartners || len(cfg.Initiators()) != tc.wantInit {
			t.Errorf("%s + %s: partners=%d initiators=%d", tc.cfg, tc.partners, n, len(cfg.Initiators()))
		}
	}
}
