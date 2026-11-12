package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadReleaseBlock: the optional release: block selects the profile name
// and is absent (rel17 default) otherwise. Ref: TS 29.500 §6.6.2.
func TestLoadReleaseBlock(t *testing.T) {
	const base = `
nf_instance_id: "00000000-0000-4000-8000-000000000001"
plmn: {mcc: "001", mnc: "01"}
sbi:
  address: "127.0.0.1:0"
  tls: {cert_file: c, key_file: k, ca_file: a}
`
	for _, tc := range []struct{ name, extra, want string }{
		{"absent", "", ""},
		{"rel19", "release:\n  profile: rel19\n", "rel19"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nrf.yaml")
			if err := os.WriteFile(path, []byte(base+tc.extra), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Release.Profile != tc.want {
				t.Errorf("Release.Profile = %q, want %q", cfg.Release.Profile, tc.want)
			}
		})
	}
}
