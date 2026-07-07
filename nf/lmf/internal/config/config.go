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
		// UDM is the UDM SBI address (host:port). Used for lcs-privacy-data queries.
		// Ref: TS 29.503 §5.2.2; TS 23.273 §9.1.
		UDM string `yaml:"udm"`
	} `yaml:"peers"`

	Metrics struct {
		// Address is the Prometheus metrics listen address (host:port).
		// Default: 0.0.0.0:9113
		Address string `yaml:"address"`
	} `yaml:"metrics"`

	// CellCoordinates is an optional map from NRCellId hex string → WGS84 coordinate.
	// When the AMF returns an nrCellId that matches a key, the lat/lon anchor the
	// synthesized UE position. Absent entries fall back to DefaultCoord.
	// Ref: TS 29.572 §6.1.6.2.2
	CellCoordinates map[string]CellCoord `yaml:"cell_coordinates"`

	// DefaultCoord is the WGS84 anchor used when a serving NRCellId has no entry in
	// CellCoordinates. Avoids reporting (0,0) for unmapped cells.
	DefaultCoord CellCoord `yaml:"default_coordinate"`

	// Mobility controls the synthetic UE-motion model (see internal/server/mobility.go).
	// Cell-ID positioning carries no lat/lon on the wire, so coordinates are synthesized:
	// each UE follows a smooth, bounded, deterministic walk anchored at its serving cell.
	// This is a simulation aid for demos/portal — NOT a real positioning method.
	Mobility MobilityConfig `yaml:"mobility"`

	// PrivacyCheck enables the UDM lcsData lookup before disclosing a UE's location
	// to an LCS client. When true, LMF queries Peers.UDM before calling AMF; a
	// BLOCK_ALL subscriber policy results in 403 PRIVACY_EXCEPTION_DENIED.
	// Set to false in environments without UDM (unit tests, isolated staging).
	// Ref: TS 23.273 §9.1; TS 29.503 §5.2.2 lcsData.
	PrivacyCheck bool `yaml:"privacy_check"`

	// LocationSubscription controls the EventSubscription service (TS 29.572 §5.2.3).
	LocationSubscription LocationSubscriptionConfig `yaml:"location_subscription"`
}

// LocationSubscriptionConfig holds parameters for the Nlmf_Location EventSubscription service.
// Ref: TS 29.572 §5.2.3.
type LocationSubscriptionConfig struct {
	// DefaultSamplingIntervalS is the AOI sampling cadence in seconds when the caller
	// omits samplingInterval. Default: 5 s. Ref: TS 29.572 §5.2.3.2.
	DefaultSamplingIntervalS int `yaml:"default_sampling_interval_s"`
	// DefaultReportingIntervalS is the periodic reporting cadence in seconds when the
	// caller omits reportingInterval. Default: 10 s. Ref: TS 29.572 §5.2.3.2.
	DefaultReportingIntervalS int `yaml:"default_reporting_interval_s"`
	// MaxDurationS caps the subscription lifetime in seconds. 0 → 3600 s.
	// Ref: TS 29.572 §5.2.3.2 (duration IE).
	MaxDurationS int `yaml:"max_duration_s"`
	// NotificationRetry is the number of extra attempts on 5xx / transport error
	// before the notification is dropped. Default: 1 (one retry).
	// Ref: TS 29.572 §6.1.6.2.4 (notification best-effort delivery).
	NotificationRetry int `yaml:"notification_retry"`
}

// MobilityConfig tunes the synthetic UE-motion model.
type MobilityConfig struct {
	// Enabled turns the motion model on. When false the static cell anchor is returned.
	Enabled bool `yaml:"enabled"`
	// RadiusM bounds how far (metres) a UE may stray from its serving cell anchor.
	RadiusM float64 `yaml:"radius_m"`
	// SpeedMps sets the nominal ground speed (metres/second) of the walk.
	SpeedMps float64 `yaml:"speed_mps"`
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
	// Default anchor (Madrid, Puerta del Sol) for cells without an explicit coordinate.
	cfg.DefaultCoord = CellCoord{Lat: 40.4168, Lon: -3.7038}
	cfg.Mobility = MobilityConfig{Enabled: true, RadiusM: 500, SpeedMps: 5}
	cfg.LocationSubscription = LocationSubscriptionConfig{
		DefaultSamplingIntervalS:  5,
		DefaultReportingIntervalS: 10,
		MaxDurationS:              3600,
		NotificationRetry:         1,
	}
	return cfg
}
