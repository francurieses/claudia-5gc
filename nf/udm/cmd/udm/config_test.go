package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestHomeConfigParses checks the roaming home-PLMN config (ROAM-001) loads sbi.fqdn and plmn.
func TestHomeConfigParses(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "config", "hudm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if c.SBI.FQDN != "udm.5gc.mnc002.mcc001.3gppnetwork.org" || c.PLMN.MCC != "001" || c.PLMN.MNC != "02" ||
		c.Peers.NRF != "hnrf:8000" || c.Peers.UDR != "hudr:8005" {
		t.Errorf("unexpected hudm config: %+v", c)
	}
}
