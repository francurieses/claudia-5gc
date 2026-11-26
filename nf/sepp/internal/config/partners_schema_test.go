package config

import (
	"path/filepath"
	"runtime"
	"testing"
)

// repoFile resolves a path relative to the repository root.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(self), "..", "..", "..", "..", rel)
}

// TestShippedPartnersFilesLoad pins the shared partners-file schema: the
// AMF-only home_nfs.smf_api_root key (home-routed PDU sessions) must not make
// the strict (KnownFields) SEPP parser reject the shipped files.
func TestShippedPartnersFilesLoad(t *testing.T) {
	for _, rel := range []string{"config/roaming/partners-testpeer.yaml", "config/roaming/partners.example.yaml"} {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			t.Setenv(PartnersFileEnv, repoFile(t, rel))
			t.Setenv("CONFIG_PATH", filepath.Join(t.TempDir(), "absent.yaml"))
			if _, err := Load(); err != nil {
				t.Fatalf("Load %s: %v", rel, err)
			}
		})
	}
}

func TestPartnersFileHomeNFsSMFAPIRoot(t *testing.T) {
	file := writeYAML(t, "partners.yaml", `partners:
  - plmn: {mcc: "001", mnc: "02"}
    n32: {ca_file: /file/ca.crt, address: "p:8443"}
    home_nfs:
      ausf_api_root: https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002
      udm_api_root: https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003
      smf_api_root: https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004
`)
	t.Setenv(PartnersFileEnv, file)
	t.Setenv("CONFIG_PATH", filepath.Join(t.TempDir(), "absent.yaml"))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.N32.Partners) != 1 ||
		cfg.N32.Partners[0].HomeNFs.SMFAPIRoot != "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004" {
		t.Fatalf("smf_api_root not parsed: %+v", cfg.N32.Partners)
	}
	// An unknown home_nfs key is still rejected (strict schema kept).
	bad := writeYAML(t, "bad.yaml", `partners:
  - plmn: {mcc: "001", mnc: "02"}
    n32: {ca_file: /file/ca.crt}
    home_nfs: {pcf_api_root: "https://x:1"}
`)
	t.Setenv(PartnersFileEnv, bad)
	if _, err := Load(); err == nil {
		t.Fatal("unknown home_nfs key accepted")
	}
}
