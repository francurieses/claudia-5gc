// Package config loads the NEF configuration from a YAML file.
//
// Config path: CONFIG_PATH env var → /etc/5gc/config.yaml (default).
// Keys are merged: Go defaults → per-NF YAML (config/dev.yaml in dev).
//
// Ref: TS 23.501 §6.2.5 (NEF), TS 29.522 §4.4.13 (Nnef_AFsessionWithQoS)
package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// Config holds all NEF configuration.
type Config struct {
	// NFInstanceID is the unique NEF NF instance UUID.
	// Ref: TS 29.510 §6.1.6.2.2
	NFInstanceID string `yaml:"nf_instance_id"`

	PLMN struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`

	SBI struct {
		// Address is the listen address for the Nnef SBI server (host:port).
		// Default: 0.0.0.0:8011
		Address string `yaml:"address"`
		// FQDN is the NEF FQDN advertised in the NRF profile and used in Location headers.
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
		// BSF is the BSF address (host:port). Used for PCF binding discovery.
		// Ref: TS 29.521 §5.2.2.4
		BSF string `yaml:"bsf"`
	} `yaml:"peers"`

	// OAuth2 holds settings for verifying northbound bearer tokens.
	// The NEF uses the same HS256 JWT model as the NRF.
	// Ref: TS 29.522 §6, TS 29.510 §6.3 (NRF token model)
	OAuth2 struct {
		// Secret is the HMAC-SHA256 signing secret shared with the NRF issuer.
		// In dev this matches the NRF's jwt_secret. In production: rotate per TS 33.501.
		Secret string `yaml:"secret"`
	} `yaml:"oauth2"`

	Metrics struct {
		// Address is the Prometheus metrics listen address (host:port).
		// Default: 0.0.0.0:9112
		Address string `yaml:"address"`
	} `yaml:"metrics"`

	// Release selects the release profile (rel17 default, rel19) that gates
	// supportedFeatures wire behaviour; NF_RELEASE_PROFILE overrides.
	// Ref: TS 29.500 §6.6.2.
	Release capability.ReleaseConfig `yaml:"release"`
}

// Load reads the NEF configuration from CONFIG_PATH (or /etc/5gc/config.yaml).
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
			return nil, fmt.Errorf("nef: config: parse YAML: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("nef: config: read file: %w", err)
	}
	return cfg, nil
}

// APIRoot returns the NEF SBI apiRoot (scheme + FQDN + listen port) that peers
// use to reach this NEF: the same FQDN the NRF NFProfile advertises
// (nefsbi.BuildNFProfile) plus the port of SBI.Address, since the profile
// carries no ipEndPoints. Returns "" when FQDN or the port is not configured.
// Ref: TS 29.510 §6.1.6.2.2 (fqdn), TS 29.500 §6.1.1 (apiRoot)
func (c *Config) APIRoot() string {
	if c.SBI.FQDN == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(c.SBI.Address)
	if err != nil || port == "" || port == "0" {
		return ""
	}
	return "https://" + net.JoinHostPort(c.SBI.FQDN, port)
}

func defaults() *Config {
	cfg := &Config{}
	cfg.NFInstanceID = "00000000-0000-4011-8000-000000000001"
	cfg.PLMN.MCC = "001"
	cfg.PLMN.MNC = "01"
	cfg.SBI.Address = "0.0.0.0:8011"
	cfg.SBI.FQDN = "nef.5gc.mnc001.mcc001.3gppnetwork.org"
	cfg.SBI.TLS.CAFile = "/etc/5gc/pki/ca.crt"
	cfg.SBI.TLS.CertFile = "/etc/5gc/pki/nef.crt"
	cfg.SBI.TLS.KeyFile = "/etc/5gc/pki/nef.key"
	cfg.Peers.NRF = "nrf:8000"
	cfg.Peers.BSF = "bsf:8010"
	cfg.OAuth2.Secret = "5gc-dev-secret"
	cfg.Metrics.Address = "0.0.0.0:9112"
	return cfg
}
