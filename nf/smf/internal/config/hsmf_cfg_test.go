package config

import "testing"

// config/hsmf.yaml must parse and override the Go defaults it targets.
func TestHSMFYAML(t *testing.T) {
	t.Setenv("CONFIG_PATH", "../../config/hsmf.yaml")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PLMN.MCC != "001" || cfg.PLMN.MNC != "02" || cfg.Peers.PCF != "" || cfg.Peers.NRF != "hnrf:8000" ||
		cfg.Peers.UPF != "hupf-n4.5gc.local:8805" || cfg.UPFN9Addr != "172.30.20.200" || len(cfg.DNNs) != 1 ||
		cfg.DNNs[0].UEIPPool != "10.70.0.0/24" || cfg.SBI.TLS.CertFile != "/etc/5gc/pki/smf.crt" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}
