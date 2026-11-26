package config

import (
	"os"
	"path/filepath"
	"testing"
)

// vupf_n9_allowed_cidrs: parsed from YAML, empty = no restriction, an invalid CIDR is a startup error.
func TestVUPFN9AllowedCIDRs(t *testing.T) {
	load := func(t *testing.T, yaml string) (*Config, error) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "smf.yaml")
		if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CONFIG_PATH", p)
		return Load()
	}
	t.Run("unset", func(t *testing.T) {
		cfg, err := load(t, "plmn: {mcc: '001', mnc: '01'}\n")
		if err != nil {
			t.Fatal(err)
		}
		if n, err := cfg.ParseVUPFN9AllowedCIDRs(); err != nil || len(n) != 0 {
			t.Errorf("got %v %v, want no restriction", n, err)
		}
	})
	t.Run("valid", func(t *testing.T) {
		cfg, err := load(t, "vupf_n9_allowed_cidrs: ['192.0.2.0/24', '2001:db8::/32']\n")
		if err != nil {
			t.Fatal(err)
		}
		n, err := cfg.ParseVUPFN9AllowedCIDRs()
		if err != nil || len(n) != 2 || n[0].String() != "192.0.2.0/24" || n[1].String() != "2001:db8::/32" {
			t.Errorf("got %v %v", n, err)
		}
	})
	t.Run("invalid is a startup error", func(t *testing.T) {
		if _, err := load(t, "vupf_n9_allowed_cidrs: ['192.0.2.0/33']\n"); err == nil {
			t.Fatal("invalid CIDR accepted")
		}
		if _, err := load(t, "vupf_n9_allowed_cidrs: ['not-a-cidr']\n"); err == nil {
			t.Fatal("invalid CIDR accepted")
		}
	})
}
