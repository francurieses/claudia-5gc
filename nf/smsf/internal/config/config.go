// Package config loads the SMSF configuration from a YAML file.
//
// Config path: CONFIG_PATH env var → /etc/5gc/config.yaml (default).
// Keys are merged: Go defaults → operator.yaml → per-NF YAML.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all SMSF configuration.
type Config struct {
	// NFInstanceID is the unique SMSF NF instance UUID.
	// Ref: TS 29.510 §6.1.6.2.2
	NFInstanceID string `yaml:"nf_instance_id"`

	PLMN struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`

	SBI struct {
		// Address is the listen address for the Nsmsf SBI server (host:port).
		Address string `yaml:"address"`
		TLS     struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
			CAFile   string `yaml:"ca_file"`
		} `yaml:"tls"`
	} `yaml:"sbi"`

	Peers struct {
		// NRF is the NRF address (host:port). Used for registration and heartbeat.
		NRF string `yaml:"nrf"`
		// UDM is the UDM address (host:port). Used for UECM SMSF registration.
		// Ref: TS 29.503 §5.3.2 (Nudm_UECM)
		UDM string `yaml:"udm"`
		// AMF is the AMF namf-comm SBI address (host:port). Used for MT SMS delivery
		// via Namf_Communication_N1N2MessageTransfer when the SMSF does not have an
		// AMF callback URI from Activate (static fallback for tests).
		// Ref: TS 29.518 §5.2.2.3
		AMF string `yaml:"amf"`
	} `yaml:"peers"`

	Metrics struct {
		Address string `yaml:"address"`
	} `yaml:"metrics"`
}

// Load reads the SMSF configuration.
// Missing file is tolerated and returns defaults — the NF runs without TLS (h2c).
func Load() (*Config, error) {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "/etc/5gc/config.yaml"
	}

	cfg := defaults()

	data, err := os.ReadFile(cfgPath)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("smsf: config: parse YAML: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("smsf: config: read file: %w", err)
	}
	return cfg, nil
}

func defaults() *Config {
	cfg := &Config{}
	cfg.NFInstanceID = "00000000-0000-4010-8000-000000000001"
	cfg.PLMN.MCC = "001"
	cfg.PLMN.MNC = "01"
	cfg.SBI.Address = "0.0.0.0:8009"
	cfg.SBI.TLS.CAFile = "/etc/5gc/pki/ca.crt"
	cfg.SBI.TLS.CertFile = "/etc/5gc/pki/smsf.crt"
	cfg.SBI.TLS.KeyFile = "/etc/5gc/pki/smsf.key"
	cfg.Peers.NRF = "nrf:8000"
	cfg.Peers.UDM = "udm:8003"
	cfg.Peers.AMF = "amf:8001"
	cfg.Metrics.Address = "0.0.0.0:9110"
	return cfg
}
