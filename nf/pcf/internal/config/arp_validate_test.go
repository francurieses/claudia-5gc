package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidate_ARPEnums covers the arp_preempt_* enum validation (TS 29.571 §5.4.4.7).
func TestValidate_ARPEnums(t *testing.T) {
	cases := []struct {
		name, capab, vuln, wantKey string
	}{
		{"defaults", "NOT_PREEMPT", "NOT_PREEMPTABLE", ""},
		{"empty allowed", "", "", ""},
		{"may/preemptable", "MAY_PREEMPT", "PREEMPTABLE", ""},
		{"bad cap", "SOMETIMES", "", "arp_preempt_cap"},
		{"bad vuln", "", "MAYBE", "arp_preempt_vuln"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{}
			c.DefaultSMPolicy.ARPPreemptCap = tc.capab
			c.DefaultSMPolicy.ARPPreemptVuln = tc.vuln
			err := c.Validate()
			if tc.wantKey == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantKey) {
				t.Fatalf("want error naming %s, got %v", tc.wantKey, err)
			}
		})
	}
}

// TestLoad_RejectsInvalidARP proves Load calls Validate.
func TestLoad_RejectsInvalidARP(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pcf.yaml")
	if err := os.WriteFile(p, []byte("default_sm_policy:\n  arp_preempt_cap: SOMETIMES\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", p)
	t.Setenv("OPERATOR_CONFIG_PATH", filepath.Join(t.TempDir(), "absent.yaml"))
	if _, err := Load(); err == nil {
		t.Fatal("Load accepted invalid arp_preempt_cap")
	}
}
