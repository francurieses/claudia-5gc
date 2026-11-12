package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsWhenMissing(t *testing.T) {
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

func TestN32TLSFallbackAndPartnerValidation(t *testing.T) {
	cfg := defaults()
	if f := cfg.N32TLS(); f.CAFile != cfg.SBI.TLS.CAFile || f.CertFile != cfg.SBI.TLS.CertFile || f.KeyFile != cfg.SBI.TLS.KeyFile {
		t.Fatalf("no fallback: %+v", f)
	}
	cfg.N32.TLS.CAFile = "/n32/ca.crt"
	if f := cfg.N32TLS(); f.CAFile != "/n32/ca.crt" || f.CertFile != cfg.SBI.TLS.CertFile {
		t.Fatalf("partial override: %+v", f)
	}
	for _, tc := range []struct {
		mcc, mnc string
		ok       bool
	}{{"001", "01", true}, {"310", "260", true}, {"1", "01", false}, {"001", "1", false}, {"001", "0001", false}, {"00a", "01", false}, {"", "", false}} {
		c := defaults()
		c.N32.RoamingPartners = []PLMN{{MCC: tc.mcc, MNC: tc.mnc}}
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%q/%q: err=%v", tc.mcc, tc.mnc, err)
		}
	}
}

func TestLoadRejectsInvalidPartner(t *testing.T) {
	path := t.TempDir() + "/c.yaml"
	if err := os.WriteFile(path, []byte("n32:\n  roaming_partners:\n    - {mcc: \"12\", mnc: \"01\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", path)
	if _, err := Load(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateN32Peers(t *testing.T) {
	ok := N32Peer{PLMN: PLMN{MCC: "001", MNC: "02"}, FQDN: "sepp.5gc.mnc002.mcc001.3gppnetwork.org", Address: "sepp.5gc.mnc002.mcc001.3gppnetwork.org:8443"}
	for name, tc := range map[string]struct {
		mut func(*N32Peer)
		ok  bool
	}{
		"valid":      {func(*N32Peer) {}, true},
		"bad plmn":   {func(p *N32Peer) { p.PLMN.MCC = "1" }, false},
		"no fqdn":    {func(p *N32Peer) { p.FQDN = "" }, false},
		"no port":    {func(p *N32Peer) { p.Address = "host" }, false},
		"empty host": {func(p *N32Peer) { p.Address = ":8443" }, false},
		"empty addr": {func(p *N32Peer) { p.Address = "" }, false},
	} {
		c := defaults()
		p := ok
		tc.mut(&p)
		c.N32.Peers = []N32Peer{p}
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

func TestTopologyHidingDefaultAndExplicit(t *testing.T) {
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
	cfg.N32.RoamingPartners = []PLMN{{MCC: "001", MNC: "02"}}
	if !cfg.HasRoamingConfig() {
		t.Fatal("roaming_partners must count")
	}
	cfg = defaults()
	cfg.N32.Peers = []N32Peer{{}}
	if !cfg.HasRoamingConfig() {
		t.Fatal("peers must count")
	}
}
