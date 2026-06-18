// Package config loads and validates NRF runtime configuration.
package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

// Config is the NRF runtime configuration. Mirrors the YAML schema in
// nf/nrf/config/dev.yaml.
type Config struct {
	// NFInstanceID is the UUID of this NRF instance (3GPP TS 29.510 §6.1.6.2.2).
	NFInstanceID string `yaml:"nf_instance_id"`

	// PLMN identifies the operator (3GPP TS 23.003).
	PLMN PLMN `yaml:"plmn"`

	SBI SBI `yaml:"sbi"`

	// Heartbeat timeout for registered NFs. Default 90s per
	// TS 29.510 §6.1.6.2.2 NFProfile.heartBeatTimer guidance.
	HeartbeatTimeoutSec int `yaml:"heartbeat_timeout_sec"`

	// OAuth2Secret is the HMAC-HS256 signing secret for JWT access tokens.
	// Ref: TS 33.501 §13.4.1 — client_credentials grant for SBA.
	// Defaults to a dev-only secret; MUST be overridden in production.
	OAuth2Secret string `yaml:"oauth2_secret"`

	Metrics Metrics `yaml:"metrics"`
}

type PLMN struct {
	MCC string `yaml:"mcc"`
	MNC string `yaml:"mnc"`
}

type SBI struct {
	Address string `yaml:"address"` // host:port
	TLS     TLS    `yaml:"tls"`
}

type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

type Metrics struct {
	Address string `yaml:"address"` // host:port
}

// Load reads YAML from path (defaults to /etc/5gc/config.yaml) and validates it.
func Load(path string) (*Config, error) {
	if path == "" {
		path = "/etc/5gc/config.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// Seed PLMN from operator config before per-NF YAML overwrites it.
	var c Config
	if op, err := operatorcfg.LoadOperator(""); err != nil {
		return nil, fmt.Errorf("operator config: %w", err)
	} else if op != nil {
		c.PLMN.MCC = op.PLMN.MCC
		c.PLMN.MNC = op.PLMN.MNC
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.NFInstanceID == "" {
		// auto-generate per spec; warn upstream that persistence is needed across restarts
		c.NFInstanceID = uuid.NewString()
	} else if _, err := uuid.Parse(c.NFInstanceID); err != nil {
		return fmt.Errorf("nf_instance_id must be a UUID: %w", err)
	}
	if c.PLMN.MCC == "" || c.PLMN.MNC == "" {
		return errors.New("plmn.mcc and plmn.mnc are required")
	}
	if c.SBI.Address == "" {
		return errors.New("sbi.address is required")
	}
	if c.SBI.TLS.CertFile == "" || c.SBI.TLS.KeyFile == "" {
		return errors.New("sbi.tls cert_file and key_file are required (TS 33.501 §13)")
	}
	if c.HeartbeatTimeoutSec == 0 {
		c.HeartbeatTimeoutSec = 90
	}
	if c.OAuth2Secret == "" {
		c.OAuth2Secret = "5gc-dev-oauth2-secret-change-in-production"
	}
	if c.Metrics.Address == "" {
		c.Metrics.Address = ":9100"
	}
	return nil
}
