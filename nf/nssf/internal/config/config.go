package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

// SliceEntry is a single S-NSSAI entry in the NSSF policy.
type SliceEntry struct {
	SST int    `yaml:"sst"`
	SD  string `yaml:"sd"`
}

type Config struct {
	NFInstanceID string `yaml:"nf_instance_id"`
	PLMN         struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`
	SBI struct {
		Address string `yaml:"address"`
		TLS     struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
			CAFile   string `yaml:"ca_file"`
		} `yaml:"tls"`
	} `yaml:"sbi"`
	Peers struct {
		NRF string `yaml:"nrf"`
	} `yaml:"peers"`
	Metrics struct {
		Address string `yaml:"address"`
	} `yaml:"metrics"`
	// AllowedSlices is the set of S-NSSAIs this NSSF is configured to allow.
	// A UE requesting a slice not in this list will receive an empty AllowedNSSAI.
	AllowedSlices []SliceEntry `yaml:"allowed_slices"`
}

func Load() (*Config, error) {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "/etc/5gc/config.yaml"
	}
	cfg := &Config{
		NFInstanceID: "00000000-0000-4009-8000-000000000001",
	}
	cfg.PLMN.MCC, cfg.PLMN.MNC = "001", "01"
	cfg.SBI.Address = "0.0.0.0:8007"
	cfg.Metrics.Address = "0.0.0.0:9109"
	cfg.Peers.NRF = "nrf:8000"
	cfg.SBI.TLS.CAFile = "/etc/5gc/pki/ca.crt"
	cfg.SBI.TLS.CertFile = "/etc/5gc/pki/nssf.crt"
	cfg.SBI.TLS.KeyFile = "/etc/5gc/pki/nssf.key"

	// Layer operator config (PLMN + slices) between Go defaults and per-NF YAML.
	if op, err := operatorcfg.LoadOperator(""); err != nil {
		return nil, fmt.Errorf("config: operator config: %w", err)
	} else if op != nil {
		op.ApplyToPLMN(&cfg.PLMN.MCC, &cfg.PLMN.MNC)
		if slices := op.Slices(); len(slices) > 0 {
			cfg.AllowedSlices = cfg.AllowedSlices[:0]
			for _, s := range slices {
				cfg.AllowedSlices = append(cfg.AllowedSlices, SliceEntry{SST: s.SST, SD: s.SD})
			}
		}
	}

	data, err := os.ReadFile(cfgPath)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parse YAML: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("config: read file: %w", err)
	}
	return cfg, nil
}
