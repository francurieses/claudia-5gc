package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_NGAPRANProfiles(t *testing.T) {
	load := func(t *testing.T, y string) (*Config, error) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
		return loadConfig(p)
	}
	t.Run("valid", func(t *testing.T) {
		cfg, err := load(t, "ngap:\n  ran_profiles:\n    - gnb_name: \"lab-*\"\n      max_release: Rel-17\n    - global_ran_node_id: \"000001/24\"\n      max_release: rel18\n")
		if err != nil || len(cfg.NGAP.RANProfiles) != 2 {
			t.Fatalf("cfg=%v err=%v", cfg, err)
		}
	})
	for name, y := range map[string]string{
		"bad release":   "ngap:\n  ran_profiles:\n    - gnb_name: a\n      max_release: Rel-20\n",
		"both selector": "ngap:\n  ran_profiles:\n    - gnb_name: a\n      global_ran_node_id: \"01/24\"\n      max_release: Rel-17\n",
		"no selector":   "ngap:\n  ran_profiles:\n    - max_release: Rel-17\n",
		"bad pattern":   "ngap:\n  ran_profiles:\n    - gnb_name: \"[\"\n      max_release: Rel-17\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, y); err == nil || !strings.Contains(err.Error(), "ngap config") {
				t.Errorf("err = %v, want ngap config error", err)
			}
		})
	}
}
