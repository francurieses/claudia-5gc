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
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.NASSecurity.IntegrityEnforcement != tc.want {
				t.Fatalf("got %s, want %s", cfg.NASSecurity.IntegrityEnforcement, tc.want)
			}
		})
	}
}

// TestLoadConfig_NASCipheringOrder: default list, YAML/env override and startup
// errors for an invalid list (SEC-006, TS 33.501 §6.7.1.1).
func TestLoadConfig_NASCipheringOrder(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml, env string
		want      []byte
		wantErr   bool
	}{
		"default":      {yaml: "nf_instance_id: x\n", want: []byte{2, 1, 3, 0}},
		"yaml":         {yaml: "nas_security:\n  ciphering_order: \"NEA3, NEA2, NEA1, NEA0\"\n", want: []byte{3, 2, 1, 0}},
		"env override": {yaml: "nas_security:\n  ciphering_order: \"NEA3\"\n", env: "NEA1", want: []byte{1}},
		"unknown":      {yaml: "nas_security:\n  ciphering_order: \"NEA2, NEA7\"\n", wantErr: true},
		"duplicate":    {yaml: "nas_security:\n  ciphering_order: \"NEA2, NEA2\"\n", wantErr: true},
		"bad env":      {yaml: "nf_instance_id: x\n", env: ",", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AMF_NAS_CIPHERING_ORDER", tc.env)
			p := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfig(p)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want startup error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(cfg.NASSecurity.cipheringOrderIDs) != string(tc.want) {
				t.Fatalf("got %v; want %v", cfg.NASSecurity.cipheringOrderIDs, tc.want)
			}
		})
	}
}
