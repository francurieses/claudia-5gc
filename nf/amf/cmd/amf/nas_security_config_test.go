package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfig_NASIntegrityEnforcement: strict by default, relaxed only on
// explicit config or env, invalid value is a startup error (AMF-033).
func TestLoadConfig_NASIntegrityEnforcement(t *testing.T) {
	load := func(t *testing.T, y string) (*Config, error) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
		return loadConfig(p)
	}
	for name, tc := range map[string]struct {
		yaml, env, want string
		wantErr         bool
	}{
		"default strict":     {yaml: "nf_instance_id: x\n", want: "strict"},
		"yaml relaxed":       {yaml: "nas_security:\n  integrity_enforcement: relaxed\n", want: "relaxed"},
		"env overrides yaml": {yaml: "nas_security:\n  integrity_enforcement: relaxed\n", env: "strict", want: "strict"},
		"env relaxed":        {yaml: "nf_instance_id: x\n", env: "relaxed", want: "relaxed"},
		"invalid yaml":       {yaml: "nas_security:\n  integrity_enforcement: off\n", wantErr: true},
		"invalid env":        {yaml: "nf_instance_id: x\n", env: "log-only", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AMF_NAS_INTEGRITY_ENFORCEMENT", tc.env)
			cfg, err := load(t, tc.yaml)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want startup error")
				}
				return
			}
			if err != nil || cfg.NASSecurity.IntegrityEnforcement != tc.want {
				t.Fatalf("cfg=%v err=%v want %s", cfg, err, tc.want)
			}
		})
	}
}
