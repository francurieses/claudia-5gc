// Package config loads the LMF configuration from a YAML file.
//
// Config path: CONFIG_PATH env var → /etc/5gc/config.yaml (default).
// Keys are merged: Go defaults → per-NF YAML (config/dev.yaml in dev).
//
// Ref: TS 23.501 §6.2.18 (LMF), TS 29.572 §5.2.2.2 (Nlmf_Location DetermineLocation)
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// CellCoord is a WGS84 coordinate pair mapped to a serving NR cell.
// Used to populate the locationEstimate in DetermineLocation responses.
// Ref: TS 29.572 §6.1.6.2.2 (locationEstimate, GeographicArea shape=POINT).
type CellCoord struct {
	// Lat is the WGS84 latitude in decimal degrees.
	Lat float64 `yaml:"lat"`
	// Lon is the WGS84 longitude in decimal degrees.
	Lon float64 `yaml:"lon"`
}

// Config holds all LMF configuration.
type Config struct {
	// NFInstanceID is the unique LMF NF instance UUID.
	// Ref: TS 29.510 §6.1.6.3.3
	NFInstanceID string `yaml:"nf_instance_id"`

	PLMN struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`

	SBI struct {
		// Address is the listen address for the Nlmf SBI server (host:port).
		// Default: 0.0.0.0:8012
		Address string `yaml:"address"`
		// FQDN is the LMF FQDN advertised in the NRF profile.
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
		// AMF is the AMF SBI address (host:port). Used for Namf_Location calls.
		// Ref: TS 29.518 §5.2.2.6
		AMF string `yaml:"amf"`
	} `yaml:"peers"`

	Metrics struct {
		// Address is the Prometheus metrics listen address (host:port).
		// Default: 0.0.0.0:9113
		Address string `yaml:"address"`
	} `yaml:"metrics"`

	// CellCoordinates is an optional map from NRCellId hex string → WGS84 coordinate.
	// When the AMF returns an nrCellId that matches a key, the lat/lon are used in the
	// locationEstimate. Absent entries default to lat=0, lon=0.
	// Ref: TS 29.572 §6.1.6.2.2
	CellCoordinates map[string]CellCoord `yaml:"cell_coordinates"`
}

// Load reads the LMF configuration from CONFIG_PATH (or /etc/5gc/config.yaml).
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
			return nil, fmt.Errorf("lmf: config: parse YAML: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("lmf: config: read file: %w", err)
	}
	return cfg, nil
}

func defaults() *Config {
	cfg := &Config{}
	cfg.NFInstanceID = "00000000-0000-4012-8000-000000000001"
	cfg.PLMN.MCC = "001"
	cfg.PLMN.MNC = "01"
	cfg.SBI.Address = "0.0.0.0:8012"
	cfg.SBI.FQDN = "lmf.5gc.mnc001.mcc001.3gppnetwork.org"
	cfg.SBI.TLS.CAFile = "/etc/5gc/pki/ca.crt"
	cfg.SBI.TLS.CertFile = "/etc/5gc/pki/lmf.crt"
	cfg.SBI.TLS.KeyFile = "/etc/5gc/pki/lmf.key"
	cfg.Peers.NRF = "nrf:8000"
	cfg.Peers.AMF = "amf:8001"
	cfg.Metrics.Address = "0.0.0.0:9113"
	cfg.CellCoordinates = make(map[string]CellCoord)
	return cfg
}
