package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// loadFrom runs Load against yamlPath with the operator config disabled
// (pointing at a non-existent file).
func loadFrom(t *testing.T, yamlPath string) *Config {
	t.Helper()
	t.Setenv("CONFIG_PATH", yamlPath)
	t.Setenv("OPERATOR_CONFIG_PATH", filepath.Join(t.TempDir(), "absent-operator.yaml"))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// TestLoad_SBITLSKeysAreHonoured proves the nested sbi.tls.* keys override the
// Go defaults, i.e. the YAML values are not silently ignored.
func TestLoad_SBITLSKeysAreHonoured(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pcf.yaml")
	yml := "sbi:\n  address: \"0.0.0.0:9999\"\n  fqdn: \"pcf.example\"\n  tls:\n" +
		"    cert_file: /x/cert.pem\n    key_file: /x/key.pem\n    ca_file: /x/ca.pem\n"
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadFrom(t, p)
	if cfg.SBI.TLS.CertFile != "/x/cert.pem" || cfg.SBI.TLS.KeyFile != "/x/key.pem" || cfg.SBI.TLS.CAFile != "/x/ca.pem" {
		t.Errorf("TLS paths not taken from YAML: %+v", cfg.SBI.TLS)
	}
	if cfg.SBI.Address != "0.0.0.0:9999" || cfg.SBI.FQDN != "pcf.example" {
		t.Errorf("sbi address/fqdn: %q %q", cfg.SBI.Address, cfg.SBI.FQDN)
	}
}

// TestDevYAML_StrictAndTLSNested loads config/dev.yaml with KnownFields(true)
// (an unknown or flat sbi.cert_file key fails) and checks the TLS paths.
func TestDevYAML_StrictAndTLSNested(t *testing.T) {
	const dev = "../../config/dev.yaml"
	data, err := os.ReadFile(dev)
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var strict Config
	if err := dec.Decode(&strict); err != nil {
		t.Fatalf("dev.yaml has keys the Config does not read: %v", err)
	}
	want := map[string]string{
		"cert": "/etc/5gc/pki/pcf.crt", "key": "/etc/5gc/pki/pcf.key", "ca": "/etc/5gc/pki/ca.crt",
	}
	got := map[string]string{
		"cert": strict.SBI.TLS.CertFile, "key": strict.SBI.TLS.KeyFile, "ca": strict.SBI.TLS.CAFile,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("sbi.tls %s = %q, want %q", k, got[k], v)
		}
	}
	if cfg := loadFrom(t, dev); cfg.SBI.TLS.CertFile != want["cert"] {
		t.Errorf("Load(dev.yaml) cert = %q", cfg.SBI.TLS.CertFile)
	}
}
