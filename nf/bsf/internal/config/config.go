// Package config loads the BSF configuration from a YAML file.
//
// Config path: CONFIG_PATH env var → /etc/5gc/config.yaml (default).
// Keys are merged: Go defaults → per-NF YAML (config/dev.yaml in dev).
//
// Ref: TS 23.501 §6.2.16 (BSF), TS 29.521 §5 (Nbsf_Management)
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all BSF configuration.
type Config struct {
	// NFInstanceID is the unique BSF NF instance UUID.
	// Ref: TS 29.510 §6.1.6.2.2
	NFInstanceID string `yaml:"nf_instance_id"`

	PLMN struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`

	SBI struct {
		// Address is the listen address for the Nbsf_Management SBI server (host:port).
		// Default: 0.0.0.0:8010
		Address string `yaml:"address"`
		// FQDN is the BSF FQDN advertised in the NRF profile and used in Location headers.
		// Consumers use this to build the /nbsf-management/v1/pcfBindings/{bindingId} URI.
		FQDN string `yaml:"fqdn"`
		TLS  struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
			CAFile   string `yaml:"ca_file"`
		} `yaml:"tls"`
	} `yaml:"sbi"`

	Peers struct {
		// NRF is the NRF address (host:port). Used for registration and heartbeat.
		// Ref: TS 29.510 §5.2.2
		NRF string `yaml:"nrf"`
	} `yaml:"peers"`

	Metrics struct {
		// Address is the Prometheus metrics listen address (host:port).
		// Default: 0.0.0.0:9111
		Address string `yaml:"address"`
	} `yaml:"metrics"`
}

// Load reads the BSF configuration from CONFIG_PATH (or /etc/5gc/config.yaml).
// A missing file is tolerated and default values are used — the NF runs without
// TLS (h2c plain) which is suitable for unit and functional tests.
func Load() (*Config, error) {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "/etc/5gc/config.yaml"
	}

	cfg := defaults()

	data, err := os.ReadFile(cfgPath)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("bsf: config: parse YAML: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("bsf: config: read file: %w", err)
	}
	return cfg, nil
}

func defaults() *Config {
	cfg := &Config{}
	cfg.NFInstanceID = "00000000-0000-4010-8000-000000000002"
	cfg.PLMN.MCC = "001"
	cfg.PLMN.MNC = "01"
	cfg.SBI.Address = "0.0.0.0:8010"
	cfg.SBI.FQDN = "bsf.5gc.mnc001.mcc001.3gppnetwork.org"
	cfg.SBI.TLS.CAFile = "/etc/5gc/pki/ca.crt"
	cfg.SBI.TLS.CertFile = "/etc/5gc/pki/bsf.crt"
	cfg.SBI.TLS.KeyFile = "/etc/5gc/pki/bsf.key"
	cfg.Peers.NRF = "nrf:8000"
	cfg.Metrics.Address = "0.0.0.0:9111"
	return cfg
}
